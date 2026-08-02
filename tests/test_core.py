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


# --------------------------------------------------------------------------
# Content encoding: only ask for what we can decode
# --------------------------------------------------------------------------

def test_the_fetch_only_advertises_decodable_encodings(monkeypatch):
    """The first real-site audit: the header was the literal
    "gzip, deflate, br", wordpress.org obliged with brotli, no decoder was
    installed, and httpx quietly fell back to identity. Every HTML-reading
    collector then analysed 28KB of raw compressed bytes: zero components
    detected on a WordPress site, generator tag and all, with no error
    recorded anywhere. The fixtures never catch it because they serve gzip,
    which the standard library always decodes."""
    import builtins

    from slap.collectors import http_probe

    http_probe.accept_encoding.cache_clear()
    header = http_probe.accept_encoding()
    assert "gzip" in header and "deflate" in header

    for token in ("br", "zstd"):
        if token in header.split(", "):
            continue        # not installed here; nothing to assert against
        assert False, f"{token} missing although its decoder is a dependency"

    # And with the decoders gone, the header must shrink rather than lie.
    real_import = builtins.__import__

    def no_compression_libs(name, *args, **kwargs):
        if name in ("brotli", "brotlicffi", "zstandard"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_compression_libs)
    http_probe.accept_encoding.cache_clear()
    stripped = http_probe.accept_encoding()
    assert "br" not in stripped.split(", ")
    assert "zstd" not in stripped.split(", ")
    assert "gzip" in stripped
    monkeypatch.undo()
    http_probe.accept_encoding.cache_clear()


def test_a_brotli_page_is_read_as_html_not_as_bytes(settings):
    """End to end through the real pipeline against a server that only
    speaks brotli, the encoding that broke on the first real site."""
    brotli = pytest.importorskip("brotli", reason="brotli decoder not installed")
    import asyncio
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    page = (b'<!doctype html><html><head>'
            b'<meta name="generator" content="WordPress 6.5">'
            b'<title>br</title></head><body>compressed</body></html>')
    compressed = brotli.compress(page)

    class BrotliOnly(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            accept = self.headers.get("Accept-Encoding", "")
            assert "br" in accept, f"fetch no longer advertises br: {accept}"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Encoding", "br")
            self.send_header("Content-Length", str(len(compressed)))
            self.end_headers()
            self.wfile.write(compressed)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), BrotliOnly)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/"
        settings.discovery.enabled = False
        settings.lighthouse.enabled = False
        result = asyncio.run(core.run_batch([url], settings))
        assert result.succeeded == 1

        conn = db.connect(settings.db_path)
        rows = {r["metric_key"]: r for r in conn.execute(
            """SELECT o.metric_key, o.numeric_value, o.text_value
               FROM observation o JOIN page p ON p.id = o.page_id
               JOIN run r ON r.id = p.run_id WHERE r.id = ?""",
            (result.run_ids[0],))}
        # The page was readable: the generator tag was seen through the
        # compression, which is exactly what failed on wordpress.org.
        assert rows["tech.cms"]["text_value"] == "WordPress"
        assert rows["component.observed_count"]["numeric_value"] >= 1
        assert rows["http.compression"]["text_value"] == "br"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_init_db_applies_the_schema_once_per_connection(tmp_path, monkeypatch):
    """Every core read funnels through init_db, and it used to run the
    migration probe plus the full DDL script on each call, per row rendered
    by the web UI. The schema cannot change mid-process; pay once."""
    calls = []
    real_migrate = db.migrate

    def counting_migrate(conn):
        calls.append(1)
        return real_migrate(conn)

    monkeypatch.setattr(db, "migrate", counting_migrate)
    path = tmp_path / "once.sqlite3"
    first = db.init_db(path)
    second = db.init_db(path)
    assert first is second
    assert len(calls) == 1

    # After a close, the same path must initialise again: the file may not
    # even be the same file by then.
    db.close_thread_connections()
    (tmp_path / "once.sqlite3").unlink()
    conn = db.init_db(path)
    assert len(calls) == 2
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "run" in tables
    db.close_thread_connections()


# --------------------------------------------------------------------------
# Clearing all history: the one deliberate exception to append-only
# --------------------------------------------------------------------------

def test_clear_history_removes_everything_and_only_ours(server, settings,
                                                        tmp_path):
    """Complete or not at all: rows without blobs leak orphaned megabytes,
    blobs without rows are unreachable forever. And "ours" has a boundary:
    artifact paths are absolute, so one corrupt row must never be able to
    delete a file outside the artifact directory."""
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    conn = db.connect(settings.db_path)

    # A recorded artifact blob, a stray in the same directory, and a file
    # OUTSIDE it that a corrupt row points at.
    settings.artifact_dir.mkdir(parents=True, exist_ok=True)
    blob = settings.artifact_dir / "run-1-lhr.json.gz"
    blob.write_bytes(b"x" * 2048)
    stray = settings.artifact_dir / "orphaned.json.gz"
    stray.write_bytes(b"y" * 1024)
    precious = tmp_path / "precious.txt"
    precious.write_text("an unrelated file", encoding="utf-8")
    run_id = core.list_runs(settings)[0]["id"]
    with db.transaction(conn):
        conn.execute("INSERT INTO artifact (run_id, kind, path) VALUES (?,?,?)",
                     (run_id, "lhr", str(blob)))
        conn.execute("INSERT INTO artifact (run_id, kind, path) VALUES (?,?,?)",
                     (run_id, "lhr", str(precious)))
        conn.execute("""INSERT INTO crux_history
                        (origin, form_factor, period_end, period_start,
                         metric_key, p75, fetched_at)
                        VALUES ('https://x.test','PHONE','2026-07-25',
                                '2026-06-28','crux.lcp.p75',1200,'now')""")

    before = core.history_totals(settings)
    assert before["runs"] >= 1 and before["crux_weeks"] == 1

    result = core.clear_history(settings)

    after = core.history_totals(settings)
    assert all(v == 0 for v in after.values()), after
    assert result.runs == before["runs"]
    assert result.artifact_files == 2            # the blob and the stray
    assert not blob.exists() and not stray.exists()
    assert precious.exists(), "a path outside the artifact dir was deleted"
    assert "Exported reports were not touched" in result.text


def test_clear_history_leaves_exported_reports_alone(server, settings):
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    run_id = core.list_runs(settings)[0]["id"]
    exported = core.export_report(settings, run_id, pdf=False)
    assert exported.html_path.is_file()

    core.clear_history(settings)
    assert exported.html_path.is_file(), \
        "a history wipe must never eat delivered documents"


def test_clear_history_vacuums_the_file_back_down(server, settings):
    """A "cleared" database still occupying its old size looks like a wipe
    that did not take."""
    worker = core.BatchWorker([server], settings).start()
    worker.wait(60)
    conn = db.connect(settings.db_path)
    with db.transaction(conn):
        conn.executemany(
            """INSERT INTO crux_history (origin, form_factor, period_end,
               period_start, metric_key, p75, fetched_at)
               VALUES (?,?,?,?,?,?,?)""",
            [(f"https://pad-{i}.test", "PHONE", f"2026-{(i % 12) + 1:02d}-01",
              "2026-01-01", f"crux.lcp.p75", float(i), "now" + "x" * 200)
             for i in range(4000)])
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    fat = settings.db_path.stat().st_size

    core.clear_history(settings)
    db.connect(settings.db_path).execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert settings.db_path.stat().st_size < fat
