"""End-to-end tests against a local HTTP server.

These exercise the whole path a front-end sees: BatchWorker on its own
thread, events on the bus, rows in SQLite, findings derived from real
collected observations. No external network.
"""

from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from slap import core, db
from slap.collectors.base import CollectorConfig
from slap.config import Settings
from slap.events import BatchFinished, BatchStarted, EventBus, SiteFinished

SLOW_WORDPRESS_PAGE = (
    "<!doctype html><html><head>"
    '<meta name="generator" content="WordPress 6.5">'
    '<meta name="generator" content="WP Rocket 3.15.9" data-wpr-features="lazyload">'
    '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    '<div class="elementor-widget"></div>'
    "</head><body>" + ("padding " * 2000) + "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        body = SLOW_WORDPRESS_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "max-age=0, no-cache")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test output
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture
def settings(tmp_path):
    s = Settings(
        db_path=tmp_path / "slap.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        report_dir=tmp_path / "reports",
        collector=CollectorConfig(timeout=10.0, http_concurrency=4),
    )
    yield s
    db.close_thread_connections()


# --------------------------------------------------------------------------

def test_the_connection_cache_survives_being_emptied(tmp_path):
    """The bug that failed Windows CI while pointing everywhere but here.

    `close_thread_connections` leaves the cache as an EMPTY dict, and
    `connect`'s ``getattr(...) or {}`` treated empty as absent: it built a
    fresh dict the ``hasattr`` guard then refused to store. From the first
    close onward, every connection the thread opened was uncached and
    unclosable. One command per process never notices. A test suite is many
    commands in one process, and on Windows an open database cannot be
    deleted, so it surfaced as WinError 32 in `slap verify`'s scratch
    cleanup — deterministically, and only there.
    """
    path = tmp_path / "cache.sqlite3"

    first = db.connect(path)
    db.close_thread_connections()          # the state every command exits in

    second = db.connect(path)
    third = db.connect(path)
    assert second is third, "the cache must work after being emptied"
    assert second is not first

    db.close_thread_connections()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        second.cursor()


def test_prepare_urls_normalizes_dedupes_and_skips_comments():
    result = core.prepare_urls([
        "example.com", "  https://example.com  ", "# a comment", "",
        "https://example.com", "other.com",
    ])
    assert result == ["https://example.com", "https://other.com"]


def test_batch_worker_runs_on_its_own_thread_and_persists(server, settings):
    worker = core.BatchWorker([server], settings)
    sink = worker.bus.queue_sink()
    worker.start()
    assert worker.wait(60), "batch did not finish in time"

    result = worker.result()
    assert result.total == 1
    assert result.succeeded == 1
    assert not result.cancelled

    events = list(sink.drain())
    assert any(isinstance(e, BatchStarted) for e in events)
    assert any(isinstance(e, SiteFinished) and e.ok for e in events)
    assert any(isinstance(e, BatchFinished) for e in events)


def test_collected_observations_reach_the_database(server, settings):
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    run_id = worker.result().run_ids[0]

    detail = core.get_run_detail(settings, run_id)
    assert detail is not None
    values = {o["metric_key"]: o for o in detail["observations"]}

    assert values["http.status"]["numeric_value"] == 200
    assert values["tech.cms"]["text_value"] == "WordPress"
    assert values["tech.page_builder"]["text_value"] == "Elementor"
    assert values["wprocket.present"]["numeric_value"] == 1.0
    assert values["wprocket.version"]["text_value"] == "3.15.9"
    # Served by a plain test server, so WP Rocket's cache never touched it.
    assert values["wprocket.page_cached"]["numeric_value"] == 0.0


def test_findings_are_derived_and_stored(server, settings):
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    run_id = worker.result().run_ids[0]

    findings = core.get_run_detail(settings, run_id)["findings"]
    ids = {f["rule_id"] for f in findings}

    # The headline WP Rocket finding, with its remediation attached.
    assert "wprocket-cache-cold" in ids
    cold = next(f for f in findings if f["rule_id"] == "wprocket-cache-cold")
    assert cold["wp_rocket_setting"]
    assert "3.15.9" in cold["detail"]

    # Security headers are entirely absent from the test server.
    assert "no-hsts" in ids
    assert "no-csp" in ids
    assert "cookies-insecure" in ids
    assert "server-version-disclosure" in ids


def test_tls_collector_degrades_gracefully_on_plain_http(server, settings):
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    run_id = worker.result().run_ids[0]
    values = {
        o["metric_key"]: o
        for o in core.get_run_detail(settings, run_id)["observations"]
    }
    assert values["tls.valid"]["numeric_value"] == 0.0
    assert "HTTPS" in values["tls.error"]["text_value"]


def test_crux_reports_unavailable_without_an_api_key(server, settings):
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    run_id = worker.result().run_ids[0]
    values = {
        o["metric_key"]: o
        for o in core.get_run_detail(settings, run_id)["observations"]
    }
    assert values["crux.available"]["numeric_value"] == 0.0


def test_unreachable_host_fails_the_run_without_killing_the_batch(server, settings):
    urls = [server, "http://127.0.0.1:1/"]
    worker = core.BatchWorker(urls, settings).start()
    assert worker.wait(60)
    result = worker.result()

    assert result.total == 2
    assert result.succeeded == 1
    assert result.failed == 1

    runs = core.list_runs(settings)
    assert {r["status"] for r in runs} == {"completed", "failed"}
    failed = next(r for r in runs if r["status"] == "failed")
    assert failed["error"]


def test_redirects_are_recorded(server, settings):
    worker = core.BatchWorker([f"{server}/redirect"], settings).start()
    worker.wait(60)
    run_id = worker.result().run_ids[0]
    values = {
        o["metric_key"]: o
        for o in core.get_run_detail(settings, run_id)["observations"]
    }
    assert values["redirect.hops"]["numeric_value"] == 1.0
    assert "302" in values["redirect.chain"]["text_value"]


def test_batches_and_runs_are_listable(server, settings):
    worker = core.BatchWorker([server, f"{server}/redirect"], settings).start()
    worker.wait(60)
    batch_id = worker.result().batch_id

    batches = core.list_batches(settings)
    assert batches[0]["batch_id"] == batch_id
    assert batches[0]["run_count"] == 2

    runs = core.list_runs(settings, batch_id=batch_id)
    assert len(runs) == 2
    assert all(r["finding_count"] > 0 for r in runs)


def test_cancel_is_safe_from_another_thread(server, settings):
    urls = [f"{server}/?i={i}" for i in range(30)]
    worker = core.BatchWorker(urls, settings)
    worker.start()
    worker.cancel()
    assert worker.wait(60)
    result = worker.result()
    # Whatever was in flight finished; nothing is left in a running state.
    assert all(
        r["status"] in ("completed", "failed", "cancelled")
        for r in core.list_runs(settings)
    )
    assert result.cancelled or result.total <= len(urls)


def test_run_rows_carry_provenance(server, settings):
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    run = core.get_run(settings, worker.result().run_ids[0])
    assert run["slap_version"]
    assert run["schema_version"] == 1
    assert run["started_at"] and run["finished_at"]


def test_empty_batch_is_a_no_op_not_a_crash(settings):
    worker = core.BatchWorker([], settings).start()
    assert worker.wait(30)
    result = worker.result()
    assert result.total == 0
    assert not result.cancelled


def test_event_bus_survives_a_broken_subscriber():
    bus = EventBus()
    seen = []
    bus.subscribe(lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    bus.subscribe(seen.append)
    bus.emit(BatchStarted(batch_id="x", total=1))
    assert len(seen) == 1


def test_an_unreachable_site_produces_no_findings(settings):
    """A site we never reached must not be described.

    Many rules fire on `missing: true`, so deriving findings from an empty
    observation set reports "No HSTS header" for a host that never answered.
    """
    worker = core.BatchWorker(["http://127.0.0.1:1/"], settings).start()
    assert worker.wait(60)

    run_id = core.list_runs(settings)[0]["id"]
    detail = core.get_run_detail(settings, run_id)
    assert detail["run"]["status"] == "failed"
    assert detail["observations"] == []
    assert detail["findings"] == []


def test_a_reachable_site_still_produces_findings(server, settings):
    """Guards the fix above from over-reaching."""
    worker = core.BatchWorker([server], settings).start()
    assert worker.wait(60)
    detail = core.get_run_detail(settings, worker.result().run_ids[0])
    assert detail["findings"]


# --------------------------------------------------------------------------
# Surviving the SALP -> SLAP rename
#
# Both of these guard data the user already has. The rename is cosmetic;
# losing somebody's audit history to it would not be.
# --------------------------------------------------------------------------

def test_a_pre_rename_database_is_migrated_not_broken(tmp_path):
    """An existing database has run.salp_version and must keep working.

    CREATE TABLE IF NOT EXISTS does not touch an existing table, so without
    the migration this fails on the first INSERT partway through a batch,
    which is the worst possible moment to discover it.
    """
    import sqlite3

    path = tmp_path / "old.sqlite3"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE site (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL,
                           label TEXT, client TEXT, created_at TEXT);
        CREATE TABLE run (
            id INTEGER PRIMARY KEY, batch_id TEXT NOT NULL,
            site_id INTEGER NOT NULL, started_at TEXT NOT NULL,
            finished_at TEXT, status TEXT NOT NULL, error TEXT,
            salp_version TEXT NOT NULL, schema_version INTEGER NOT NULL,
            lh_version TEXT, chrome_version TEXT, throttling_profile TEXT,
            git_sha TEXT);
        INSERT INTO site (id, hostname) VALUES (1, 'example.com');
        INSERT INTO run (batch_id, site_id, started_at, status,
                         salp_version, schema_version)
        VALUES ('b1', 1, '2026-01-01T00:00:00+00:00', 'ok', '0.1.0', 1);
        """
    )
    legacy.commit()
    legacy.close()
    db.close_thread_connections()

    conn = db.init_db(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(run)")}
    assert "slap_version" in columns
    assert "salp_version" not in columns

    # The history survived the rename rather than being recreated empty.
    assert conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
    assert conn.execute("SELECT slap_version FROM run").fetchone()[0] == "0.1.0"

    # And a new write against the renamed column works.
    db.create_run(conn, batch_id="b2", site_id=1,
                  slap_version="0.2.0", schema_version=1)
    assert conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 2
    db.close_thread_connections()


def test_migrating_twice_is_a_no_op(tmp_path):
    path = tmp_path / "fresh.sqlite3"
    conn = db.init_db(path)
    assert db.migrate(conn) == []
    db.close_thread_connections()


def test_the_pre_rename_data_directory_is_used_when_it_holds_a_database(
        tmp_path, monkeypatch):
    from slap import config

    monkeypatch.setattr(config, "data_dir_base", lambda: tmp_path)
    (tmp_path / "salp").mkdir()
    (tmp_path / "salp" / "salp.sqlite3").write_bytes(b"")

    assert config.default_data_dir() == tmp_path / "salp"
    assert config.using_legacy_data_dir()
    # Crucially the FILE name follows too. Returning salp/slap.sqlite3 would
    # create an empty second database beside the real one and show no history.
    assert config.default_db_path() == tmp_path / "salp" / "salp.sqlite3"


def test_the_new_data_directory_wins_once_it_exists(tmp_path, monkeypatch):
    from slap import config

    monkeypatch.setattr(config, "data_dir_base", lambda: tmp_path)
    (tmp_path / "salp").mkdir()
    (tmp_path / "slap").mkdir()

    assert config.default_data_dir() == tmp_path / "slap"
    assert not config.using_legacy_data_dir()
    assert config.default_db_path() == tmp_path / "slap" / "slap.sqlite3"


def test_a_clean_machine_gets_the_new_directory(tmp_path, monkeypatch):
    from slap import config

    monkeypatch.setattr(config, "data_dir_base", lambda: tmp_path)
    assert config.default_data_dir() == tmp_path / "slap"
    assert not config.using_legacy_data_dir()


def test_an_empty_legacy_directory_does_not_pin_us_to_it(tmp_path, monkeypatch):
    """A stray salp/reports/ from an `-o` export is not history.

    Triggering on the directory rather than the database would leave every
    future run writing into a folder named after the old project because
    somebody once exported a report there.
    """
    from slap import config

    monkeypatch.setattr(config, "data_dir_base", lambda: tmp_path)
    (tmp_path / "salp" / "reports").mkdir(parents=True)

    assert config.default_data_dir() == tmp_path / "slap"
    assert not config.using_legacy_data_dir()


def test_the_old_env_var_still_points_the_database(tmp_path, monkeypatch):
    from slap.config import Settings as S

    monkeypatch.delenv("SLAP_DB", raising=False)
    monkeypatch.setenv("SALP_DB", str(tmp_path / "kept.sqlite3"))
    assert S.load(tmp_path / "missing.toml").db_path == tmp_path / "kept.sqlite3"

    # And the new one wins when both are set.
    monkeypatch.setenv("SLAP_DB", str(tmp_path / "new.sqlite3"))
    assert S.load(tmp_path / "missing.toml").db_path == tmp_path / "new.sqlite3"
