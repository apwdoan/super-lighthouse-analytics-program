"""The web front-end: layering, the view model, and the two routes.

Route tests use FastAPI's TestClient against a real (temporary) database
built through the real core, so nothing here asserts against a mock of the
thing under test.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import timezone

import pytest

from slap import core, db
from slap.config import Settings
from slap.schema import Finding, FormFactor, Observation, Severity, Source, Unit

fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
from fastapi.testclient import TestClient  # noqa: E402

from slap_web import viewmodel as vm  # noqa: E402
from slap_web.app import create_app  # noqa: E402


# --------------------------------------------------------------------------
# Layering. The rule that has held through both front-ends.
# --------------------------------------------------------------------------

#: Any UI framework, not just Qt. The Qt-only version of this test would have
#: passed happily while `slap/core.py` grew a `from fastapi import ...`.
UI_FRAMEWORKS = {
    "PySide6", "PyQt5", "PyQt6",            # the previous front-end
    "fastapi", "starlette", "uvicorn",      # this one
    "flask", "django", "jinja2",
}
#: jinja2 is the one exception, and only in the report package, which renders
#: the client-facing HTML and predates every front-end.
TEMPLATE_EXEMPT = "report"


def test_nothing_under_slap_imports_a_ui_framework():
    """If `slap` imports the framework, the core stops being framework-free.

    That is what made replacing PySide6 with a web UI a rewrite of one
    package rather than of the whole project, so it is worth keeping true
    for whatever replaces this one.
    """
    import slap

    root = pathlib.Path(slap.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # Real imports only. Grepping for the string flags every
            # docstring that merely mentions the front-end.
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top not in UI_FRAMEWORKS:
                    continue
                if top == "jinja2" and TEMPLATE_EXEMPT in path.parts:
                    continue
                offenders.append(f"{path.relative_to(root)}:{node.lineno} ({top})")
    assert offenders == [], f"UI framework imported inside slap/: {offenders}"


def test_the_web_layer_never_touches_the_database():
    """slap_web is a client of slap.core, exactly as slap_gui was.

    A route that opens a connection or writes SQL is the core missing a
    function, which is the rule that produced `list_sites` and
    `get_site_detail` in the first place.
    """
    import slap_web

    root = pathlib.Path(slap_web.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(n.split(".")[-1] in {"sqlite3", "db"} for n in names):
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")
    assert offenders == [], f"slap_web reached past the core: {offenders}"


def test_the_web_layer_reuses_the_report_status_vocabulary():
    from slap.report.model import SEVERITY_STATUS, STATUS_WORDS

    assert vm.SEVERITY_STATUS is SEVERITY_STATUS
    assert vm.STATUS_WORDS is STATUS_WORDS
    # Every severity must map to a printed WORD. A bare swatch is not legal:
    # serious and warning are only DeltaE 13.6 apart in normal vision.
    for severity in SEVERITY_STATUS:
        assert vm.SEVERITY_WORDS[severity]


def test_trend_metrics_are_registered():
    """A typo here is invisible: the chart just renders empty forever."""
    from slap.schema import METRIC_REGISTRY

    unknown = [k for k in core.TREND_METRICS if k not in METRIC_REGISTRY]
    assert unknown == [], f"unregistered trend metrics: {unknown}"


# --------------------------------------------------------------------------
# View model
# --------------------------------------------------------------------------

def test_sparkline_needs_two_points():
    assert vm.sparkline([]) == ("", None)
    assert vm.sparkline([61]) == ("", None)
    path, last = vm.sparkline([28, 61])
    assert path.startswith("M") and last is not None


def test_sparkline_survives_a_flat_series():
    """Every run identical means a zero range; naive code divides by it."""
    path, last = vm.sparkline([63, 63, 63])
    assert path.count("L") == 2 and last is not None


def test_sparkline_skips_runs_with_no_score():
    path, _ = vm.sparkline([28, None, 61])
    assert path.count("L") == 1


def test_stamp_stays_distinct_however_old_the_runs_are():
    """The first fix only held for a day.

    It appended the time when a run was less than 24 hours old and fell back
    to "%-d %b" after that, so its own test passed on the day it was written
    and failed from the next morning onwards. This version pins a date far
    enough in the past that no clock can rescue it.
    """
    a = vm.stamp("2020-03-04T20:39:00+00:00")
    b = vm.stamp("2020-03-04T20:41:00+00:00")
    assert a != b
    assert a.startswith("4 Mar") or a.startswith("5 Mar")   # local tz may shift


def test_stamp_drops_the_date_only_for_today():
    """Today is the one case where the reader already has the date."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    assert ":" in vm.stamp(now)
    assert len(vm.stamp(now)) == 5          # HH:MM, no date


def test_stamp_distinguishes_runs_on_the_same_day():
    """`humanise` says 'today' for all of them, which made every axis tick
    on the first real render read 'today'."""
    a = vm.stamp("2026-07-31T20:39:00+00:00")
    b = vm.stamp("2026-07-31T20:41:00+00:00")
    assert a != b


def test_trend_needs_two_points_and_says_so():
    assert vm.build_trend([])["empty"] is True
    one = vm.build_trend([{"run_id": 1, "started_at": "2026-07-31T00:00:00+00:00",
                           "lh.score.performance": 61}])
    assert one["empty"] is True and one["count"] == 1


def test_trend_geometry_is_computed_not_left_to_the_template():
    history = [
        {"run_id": i, "started_at": f"2026-07-0{i}T00:00:00+00:00",
         "lh.score.performance": v}
        for i, v in enumerate([28, 52, 61], start=1)
    ]
    trend = vm.build_trend(history)
    assert trend["empty"] is False
    assert trend["line"].startswith("M") and trend["area"].endswith("Z")
    assert trend["delta"] == 33
    assert [m["value"] for m in trend["marks"]] == [28, 52, 61]
    assert trend["marks"][-1]["last"] is True
    assert sum(m["last"] for m in trend["marks"]) == 1


def test_tiles_fall_back_to_lab_and_say_which():
    """Three 'No data' boxes is honest and useless. A lab number is useful,
    but it is a different claim from field data and must be labelled."""
    tiles = {t.label: t for t in vm.build_tiles({"lh.lcp": 9300.0, "lh.cls": 0.0})}
    lcp = tiles["Largest Contentful Paint"]
    assert lcp.source == "lab" and lcp.value.startswith("9")
    # INP has no lab equivalent. Showing total blocking time under an INP
    # heading would be a lie, so it stays absent.
    assert tiles["Interaction to Next Paint"].source == "none"


def test_field_data_wins_over_lab_when_both_exist():
    tiles = {t.label: t for t in
             vm.build_tiles({"crux.lcp.p75": 2000.0, "lh.lcp": 9300.0})}
    assert tiles["Largest Contentful Paint"].source == "field"


def test_every_tile_carries_its_status_word():
    for tile in vm.build_tiles({}):
        assert tile.word


# --------------------------------------------------------------------------
# Routes, against a real database
# --------------------------------------------------------------------------

@pytest.fixture
def seeded(tmp_path):
    """Two runs for one site: the second fixes a rule and raises the score."""
    settings = Settings(
        db_path=tmp_path / "slap.sqlite3",
        report_dir=tmp_path / "reports",
        artifact_dir=tmp_path / "artifacts",
    )
    settings.ensure_dirs()
    conn = db.init_db(settings.db_path)

    def run(score: float, rules: list[str]) -> int:
        with db.transaction(conn):
            site_id = db.upsert_site(conn, "example.com", client="Acme")
            run_id = db.create_run(conn, batch_id="b1", site_id=site_id,
                                   slap_version="0.1.0", schema_version=1)
            page_id = db.create_page(conn, run_id, "https://example.com", None, FormFactor.MOBILE)
            db.insert_observations(conn, page_id, [
                Observation(metric_key="lh.score.performance", source=Source.LIGHTHOUSE,
                            numeric_value=score, unit=Unit.SCORE),
                Observation(metric_key="lh.lcp", source=Source.LIGHTHOUSE,
                            numeric_value=4200.0, unit=Unit.MS),
            ])
            db.insert_findings(conn, page_id, [
                Finding(rule_id=r, severity=Severity.MEDIUM, title=f"{r} fired",
                        detail="detail")
                for r in rules
            ])
            db.finish_run(conn, run_id, db.RunStatus.COMPLETED)
        return run_id

    run(30.0, ["no-hsts", "no-csp"])
    run(61.0, ["no-csp"])
    yield settings
    db.close_thread_connections()


@pytest.fixture
def client(seeded):
    return TestClient(create_app(seeded))


def test_sites_page_lists_the_site(client):
    body = client.get("/").text
    assert "example.com" in body and "Acme" in body
    assert "Needs work" in body          # 61 bands to needs-improvement


def test_site_detail_shows_the_trend_and_the_split(client, seeded):
    site = core.find_site(seeded, "example.com")
    body = client.get(f"/site/{site['id']}").text
    assert "Performance score over time" in body
    assert "Open (1)" in body and "Fixed (1)" in body
    assert "31 points across 2 runs" in body


def test_fixed_is_a_rule_id_diff_not_a_title_diff(seeded):
    """Titles carry formatted numbers that move between runs. Comparing them
    would report every improved finding as fixed AND newly discovered."""
    site = core.find_site(seeded, "example.com")
    detail = core.get_site_detail(seeded, site["id"])
    assert [f["rule_id"] for f in detail["fixed"]] == ["no-hsts"]
    assert [f["rule_id"] for f in detail["open"]] == ["no-csp"]
    assert detail["new"] == []


def test_an_empty_database_renders_an_empty_state(tmp_path):
    settings = Settings(db_path=tmp_path / "empty.sqlite3",
                        report_dir=tmp_path / "r", artifact_dir=tmp_path / "a")
    settings.ensure_dirs()
    body = TestClient(create_app(settings)).get("/").text
    assert "Nothing audited yet" in body
    db.close_thread_connections()


def test_an_unknown_site_is_a_404(client):
    assert client.get("/site/99999").status_code == 404


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


# --------------------------------------------------------------------------
# Cross-site findings
# --------------------------------------------------------------------------

def test_findings_group_by_rule_not_by_title(seeded):
    """Titles carry per-site numbers, so grouping on them splits one rule."""
    data = core.findings_across_sites(seeded)
    assert data["total_sites"] == 1
    assert [r["rule_id"] for r in data["rules"]] == ["no-csp"]
    # Fixed in the latest run, so not open anywhere.
    assert all(r["rule_id"] != "no-hsts" for r in data["rules"])


def test_findings_page_renders(client):
    body = client.get("/findings").text
    assert "Findings across every site" in body and "no-csp" in body


def test_findings_page_on_an_empty_database(tmp_path):
    settings = Settings(db_path=tmp_path / "e.sqlite3",
                        report_dir=tmp_path / "r", artifact_dir=tmp_path / "a")
    settings.ensure_dirs()
    assert "Nothing open" in TestClient(create_app(settings)).get("/findings").text
    db.close_thread_connections()


# --------------------------------------------------------------------------
# Report preview
# --------------------------------------------------------------------------

def test_report_preview_serves_the_real_report(client, seeded):
    runs = core.list_runs(seeded)
    run_id = runs[0]["id"]
    assert "Report preview" in client.get(f"/run/{run_id}").text
    report = client.get(f"/run/{run_id}/report.html")
    assert report.status_code == 200
    # The report's own document, not the app shell around it.
    assert "<!DOCTYPE html" in report.text or "<!doctype html" in report.text
    assert "/static/app.css" not in report.text


def test_report_preview_404s_on_an_unknown_run(client):
    assert client.get("/run/424242").status_code == 404


def test_export_arrives_as_a_browser_download(client, seeded):
    """The buttons used to POST, write into the app's data directory, and
    flash "Written to the report directory." In a browser that is a button
    that does nothing visible, aimed at a directory the user has never seen,
    named only by its role. The user's verdict was "does not work", and for
    a browser UI that verdict was correct: the deliverable of a click in a
    browser arrives through the browser."""
    run_id = core.list_runs(seeded)[0]["id"]
    response = client.get(f"/run/{run_id}/download/html")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "example.com" in response.headers["content-disposition"]
    assert "<!doctype html" in response.text.lower()

    # And the archive copy still lands in the reports directory, which the
    # CLI and the batch exports rely on.
    archived = list(seeded.report_dir.glob("example.com-*.html"))
    assert archived, "the on-disk archive copy must still be written"


def test_pdf_download_names_the_reason_when_there_is_no_backend(client, seeded,
                                                                monkeypatch):
    from slap import report as report_module

    async def no_pdf(*args, **kwargs):
        raise report_module.PdfError("no browser here")

    monkeypatch.setattr(report_module, "html_file_to_pdf_async", no_pdf)
    run_id = core.list_runs(seeded)[0]["id"]
    response = client.get(f"/run/{run_id}/download/pdf")
    assert response.status_code == 503
    assert "no browser" in response.json()["detail"]


def test_download_404s_on_unknown_run_and_unknown_kind(client):
    assert client.get("/run/424242/download/html").status_code == 404
    assert client.get("/run/1/download/docx").status_code == 404


def test_the_run_page_names_the_real_reports_directory(client, seeded):
    """"Where is that?" must be answerable from the page itself. "The report
    directory" is a role, not a place."""
    run_id = core.list_runs(seeded)[0]["id"]
    body = client.get(f"/run/{run_id}").text
    assert str(seeded.report_dir) in body


# --------------------------------------------------------------------------
# Activity
# --------------------------------------------------------------------------

def test_activity_starts_empty(client):
    snap = client.get("/activity").json()
    assert snap == {"running": False, "batch_id": "", "done": 0, "total": 0,
                    "sites": [], "log": []}


def test_activity_refuses_a_second_batch(seeded):
    """Two live batches means two sets of Lighthouse workers, and the
    concurrency cap that keeps scores reproducible stops meaning anything."""
    from slap_web.activity import ActivityManager

    manager = ActivityManager(seeded)
    manager._activity.running = True
    started, message = manager.start(["example.com"])
    assert started is False and "already running" in message


def test_activity_rejects_unusable_urls(seeded):
    from slap_web.activity import ActivityManager

    started, message = ActivityManager(seeded).start(["   ", "# a comment"])
    assert started is False and "No usable URLs" in message


def test_activity_tracks_in_flight_collectors_not_the_last_finished(seeded):
    """A site inside a 90-second Lighthouse run must not display 'crux'.

    This is the same bug the Qt progress table had, and it belonged in the
    core: the fix was adding CollectorStarted to the event vocabulary.
    """
    from slap.events import CollectorFinished, CollectorStarted, SiteStarted
    from slap_web.activity import ActivityManager

    manager = ActivityManager(seeded)
    url = "https://example.com"
    manager._activity.sites[url] = __import__(
        "slap_web.activity", fromlist=["SiteProgress"]).SiteProgress(url)

    manager._on_event(SiteStarted(batch_id="b", url=url))
    manager._on_event(CollectorStarted(batch_id="b", url=url, collector="crux"))
    manager._on_event(CollectorStarted(batch_id="b", url=url, collector="lighthouse"))
    manager._on_event(CollectorFinished(batch_id="b", url=url, collector="crux", ok=True))

    assert manager.snapshot()["sites"][0]["stage"] == "lighthouse"


def test_activity_log_is_bounded(seeded):
    """An unbounded list in a long-lived server process is a leak."""
    from slap.events import BatchStarted
    from slap_web.activity import LOG_LIMIT, ActivityManager

    manager = ActivityManager(seeded)
    for _ in range(LOG_LIMIT + 50):
        manager._on_event(BatchStarted(batch_id="b", total=1))
    assert len(manager._activity.log) == LOG_LIMIT


# --------------------------------------------------------------------------
# Platform portability
# --------------------------------------------------------------------------

def test_no_source_file_uses_a_platform_specific_strftime_code():
    """`%-d` is a glibc extension. Windows' C runtime rejects the `-` flag
    with `ValueError: Invalid format string`.

    A static scan rather than a behavioural test, because the whole problem
    is that Linux cannot reproduce it: the suite runs on Linux for every push
    and only the release build job runs on Windows, so a Windows-only format
    bug reaches a tag before anything notices. It reached one twice —
    `humanise` has carried `%-d %b` since it was written and raises on the
    site list for any site last audited more than a fortnight ago, which is
    the machine this project is developed on.

    Walks the AST rather than grepping, because the docstring you are reading
    contains the very string it is looking for. `%#d` is the Windows spelling
    of the same idea, non-portable in the other direction.
    """
    import ast
    import pathlib as _pathlib
    import re as _re

    import slap
    import slap_web

    pattern = _re.compile(r"%[-#][a-zA-Z]")
    offenders: list[str] = []

    for package in (slap, slap_web):
        root = _pathlib.Path(package.__file__).parent
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = {
                id(node.body[0].value)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef, ast.Module))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            }
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant)
                        and isinstance(node.value, str)
                        and id(node) not in docstrings
                        and pattern.search(node.value)):
                    offenders.append(f"{path.name}:{node.lineno}: {node.value!r}")

    assert offenders == [], (
        "platform-specific strftime codes found; format the day with an "
        f"f-string on `when.day` instead: {offenders}")


def test_the_date_helpers_work_with_a_stubbed_windows_strftime(monkeypatch):
    """Simulates the failure directly, so the fix is proven and not assumed.

    Windows raises on the whole format string, so any call that reaches
    strftime with a `-` flag fails regardless of which field it was for.
    """
    import datetime as datetime_module

    real_strftime = datetime_module.datetime.strftime

    class WindowsLike(datetime_module.datetime):
        def strftime(self, fmt):                       # noqa: D102
            if "%-" in fmt or "%#" in fmt:
                raise ValueError("Invalid format string")
            return real_strftime(self, fmt)

    monkeypatch.setattr(vm, "datetime", WindowsLike)
    when = WindowsLike(2020, 3, 4, 20, 39, tzinfo=timezone.utc)
    assert vm.day_month(when) == "4 Mar"
    assert vm.stamp("2020-03-04T20:39:00+00:00").startswith(("4 Mar", "5 Mar"))
    assert vm.humanise("2020-03-04T20:39:00+00:00") in ("4 Mar", "5 Mar")


# --------------------------------------------------------------------------
# The settings page
# --------------------------------------------------------------------------

def test_settings_page_shows_the_key_shape_never_the_key(client, seeded):
    from dataclasses import replace

    seeded.collector = replace(seeded.collector,
                               crux_api_key="AIzaSyFAKEFAKEFAKE_1234567890rdE")
    body = client.get("/settings").text
    assert "AIzaSyFAKEFAKEFAKE_1234567890rdE" not in body
    assert "AIzaSy...rdE" in body
    assert str(seeded.report_dir) in body        # the storage answers live here


def test_saving_a_key_persists_applies_and_tests_it(client, seeded, tmp_path,
                                                    monkeypatch):
    from slap import core as core_module

    seeded.config_path = tmp_path / "config.toml"
    checked = {}

    def fake_check(settings):
        checked["key"] = settings.collector.crux_api_key
        return True, "Real-user Core Web Vitals available."

    monkeypatch.setattr(core_module, "check_crux_key", fake_check)

    response = client.post("/settings/crux",
                           data={"key": "AIzaSyFAKEFAKEFAKE_1234567890rdE"},
                           follow_redirects=True)
    assert response.status_code == 200
    # Persisted for the next start...
    assert "AIzaSyFAKEFAKEFAKE_1234567890rdE" in \
        seeded.config_path.read_text(encoding="utf-8")
    # ...applied to the running app...
    assert seeded.collector.crux_api_key == "AIzaSyFAKEFAKEFAKE_1234567890rdE"
    # ...and tested, because "saved" and "working" are different claims.
    assert checked["key"] == "AIzaSyFAKEFAKEFAKE_1234567890rdE"
    assert "Working" in response.text


def test_clearing_the_key_removes_it_everywhere(client, seeded, tmp_path):
    from dataclasses import replace

    seeded.config_path = tmp_path / "config.toml"
    seeded.config_path.write_text(
        '[collector]\ncrux_api_key = "AIzaSyFAKEFAKEFAKE_1234567890rdE"\n',
        encoding="utf-8")
    seeded.collector = replace(seeded.collector,
                               crux_api_key="AIzaSyFAKEFAKEFAKE_1234567890rdE")

    response = client.post("/settings/crux", data={"key": ""},
                           follow_redirects=True)
    assert response.status_code == 200
    assert "crux_api_key" not in seeded.config_path.read_text(encoding="utf-8")
    assert seeded.collector.crux_api_key is None
    assert "No key is stored" in response.text


def test_a_malformed_key_is_refused_with_the_reason(client, seeded, tmp_path):
    seeded.config_path = tmp_path / "config.toml"
    response = client.post("/settings/crux", data={"key": "not a key!!"},
                           follow_redirects=True)
    assert response.status_code == 200
    assert "Not saved" in response.text
    assert not seeded.config_path.exists()


def test_the_env_override_is_disclosed(client, monkeypatch):
    monkeypatch.setenv("CRUX_API_KEY", "AIzaSyENVENVENVENV_1234567890env")
    body = client.get("/settings").text
    assert "CRUX_API_KEY" in body
    assert "precedence" in body
    assert "AIzaSyENVENVENVENV_1234567890env" not in body
