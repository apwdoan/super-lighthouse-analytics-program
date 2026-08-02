"""`slap verify`: the checks that used to live in two shells.

The point of moving them here is that they are now covered by this file. In
CI they were two 145-line steps, one bash and one PowerShell, and nothing
prevented a check landing on only one platform — which is exactly what nearly
happened when the vulnerability-database assertions went in.

A verifier that only ever passes is worthless, so most of what follows breaks
something and asserts the failure.
"""

from __future__ import annotations

import pytest

from slap import bundle, verify as verify_module
from slap.config import Settings
from slap.verify import (
    VerifyReport,
    check_audit_and_report,
    check_paths_are_inside_the_bundle,
    check_pdf,
    check_vulndb,
    render,
    verify,
)
from slap.vulndb import VulnDatabase, default_db_path


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.db_path = tmp_path / "verify.sqlite3"
    s.artifact_dir = tmp_path / "artifacts"
    s.report_dir = tmp_path / "reports"
    s.collector.crux_api_key = None
    s.discovery.enabled = False
    s.lighthouse.enabled = False
    return s


# --------------------------------------------------------------------------
# The report shape
# --------------------------------------------------------------------------

def test_a_failing_check_makes_the_whole_report_fail():
    report = VerifyReport()
    report.add("a", True)
    report.add("b", False, "broken")
    assert report.ok is False
    assert [c.name for c in report.failures] == ["b"]


def test_an_advisory_check_does_not_gate():
    """CI must not fail on something that does not make the build unusable,
    but a person reading the output still wants to see it."""
    report = VerifyReport()
    report.add("a", False, "not applicable here", advisory=True)
    assert report.ok is True
    assert report.failures == []


def test_the_json_shape_is_stable_enough_to_assert_on():
    report = VerifyReport(platform="linux", machine="x86_64", frozen=True)
    report.add("pdf export", False, "no browser")
    payload = report.to_dict()
    assert payload["ok"] is False
    assert payload["frozen"] is True
    assert payload["checks"][0] == {
        "name": "pdf export", "ok": False, "detail": "no browser",
        "advisory": False}


def test_the_rendered_output_names_what_failed():
    report = VerifyReport()
    report.add("pdf export", False, "no browser")
    text = render(report)
    assert "NOT usable" in text
    assert "pdf export" in text


# --------------------------------------------------------------------------
# Paths inside the bundle
# --------------------------------------------------------------------------

def test_a_source_checkout_has_nothing_to_contain():
    report = VerifyReport()
    check_paths_are_inside_the_bundle(report)
    check = report.checks[0]
    assert check.ok and check.advisory


def test_a_path_outside_the_bundle_fails(monkeypatch, tmp_path):
    """The check a stripped environment is supposed to make unnecessary.

    Windows has no `env -i`, so its CI step clears variables by name; the
    first version missed PLAYWRIGHT_BROWSERS_PATH and the bundle used the
    STAGING browser while reporting success. A leak like that is invisible
    unless something compares the resolved paths to the bundle root.
    """
    root = tmp_path / "bundle"
    (root / "runtime").mkdir(parents=True)
    inside = root / "runtime" / "chrome"
    inside.touch()
    outside = tmp_path / "staging" / "chrome"
    outside.parent.mkdir()
    outside.touch()

    monkeypatch.setattr(bundle, "is_frozen", lambda: True)
    monkeypatch.setattr(bundle, "bundle_root", lambda: root)
    monkeypatch.setattr(verify_module.bundle, "is_frozen", lambda: True)
    monkeypatch.setattr(verify_module.bundle, "bundle_root", lambda: root)
    monkeypatch.setattr(verify_module.bundle, "describe", lambda: {
        "frozen": "True", "bundle_root": str(root),
        "chromium": str(outside), "worker": str(inside), "node_source": "x",
    })

    report = VerifyReport()
    check_paths_are_inside_the_bundle(report)
    check = report.checks[0]
    assert check.ok is False
    assert "chromium" in check.detail
    assert "worker" not in check.detail        # that one was inside


def test_all_paths_inside_passes(monkeypatch, tmp_path):
    root = tmp_path / "bundle"
    (root / "runtime").mkdir(parents=True)
    inside = root / "runtime" / "chrome"
    inside.touch()
    monkeypatch.setattr(verify_module.bundle, "is_frozen", lambda: True)
    monkeypatch.setattr(verify_module.bundle, "bundle_root", lambda: root)
    monkeypatch.setattr(verify_module.bundle, "describe", lambda: {
        "frozen": "True", "bundle_root": str(root), "chromium": str(inside)})
    report = VerifyReport()
    check_paths_are_inside_the_bundle(report)
    assert report.checks[0].ok is True


# --------------------------------------------------------------------------
# The vulnerability database
# --------------------------------------------------------------------------

def test_a_missing_database_fails(settings, tmp_path):
    settings.vulndb_path = tmp_path / "nope.json"
    report = VerifyReport()
    check_vulndb(report, settings)
    assert report.checks[0].ok is False
    assert "no advisories" in report.checks[0].detail


def test_a_present_database_passes(settings):
    if not VulnDatabase.load(default_db_path()).available:
        pytest.skip("no vulnerability database; run `slap vulndb update`")
    settings.vulndb_path = default_db_path()
    report = VerifyReport()
    check_vulndb(report, settings)
    assert report.checks[0].ok is True
    assert "npm" in report.checks[0].detail


def test_a_stale_database_fails_when_a_limit_is_given(settings, tmp_path):
    """A bundle built once and run for a year carries year-old data. The
    report would print its own date, which is the design working, but nobody
    reads an appendix before trusting a headline."""
    path = tmp_path / "old.json"
    database = VulnDatabase(generated_at="2020-01-01T00:00:00+00:00",
                            sources={"npm": "OSV.dev"})
    from slap.vulndb import AffectedRange, Vulnerability

    database.index[("npm", "x")] = [
        Vulnerability(id="X-1", package="x", ecosystem="npm", summary="",
                      severity="low", ranges=(AffectedRange(introduced=(0,)),))]
    path.write_text(database.to_json(), encoding="utf-8")
    settings.vulndb_path = path

    report = VerifyReport()
    check_vulndb(report, settings, max_age_days=30)
    assert report.checks[0].ok is False
    assert "older than" in report.checks[0].detail

    fresh = VerifyReport()
    check_vulndb(fresh, settings)          # no limit: age is reported, not gated
    assert fresh.checks[0].ok is True


def test_a_database_with_no_npm_source_fails(settings, tmp_path):
    path = tmp_path / "empty-source.json"
    database = VulnDatabase(generated_at="2026-08-01T00:00:00+00:00",
                            sources={"wordpress": "somewhere"})
    from slap.vulndb import AffectedRange, Vulnerability

    database.index[("wordpress", "x")] = [
        Vulnerability(id="X-1", package="x", ecosystem="wordpress", summary="",
                      severity="low", ranges=(AffectedRange(introduced=(0,)),))]
    path.write_text(database.to_json(), encoding="utf-8")
    settings.vulndb_path = path
    report = VerifyReport()
    check_vulndb(report, settings)
    assert report.checks[0].ok is False


# --------------------------------------------------------------------------
# The end-to-end checks
# --------------------------------------------------------------------------

def test_the_audit_check_serves_its_own_page(settings):
    """It audits itself rather than the internet, so the check works offline
    and cannot fail because somebody else's site was down."""
    report = VerifyReport()
    check_audit_and_report(report, settings, lighthouse=False)
    names = {c.name: c for c in report.checks}
    assert names["audit"].ok, names["audit"].detail
    assert "observations" in names["audit"].detail
    assert names["html report"].ok


def test_the_pdf_check_asserts_a_file_on_disk(settings):
    report = VerifyReport()
    check_audit_and_report(report, settings, lighthouse=False)
    pdf = next(c for c in report.checks if c.name == "pdf export")
    if not pdf.ok:
        pytest.skip(f"no PDF backend here: {pdf.detail}")
    from pathlib import Path

    assert Path(pdf.detail).is_file()
    assert Path(pdf.detail).stat().st_size > 1000


def test_the_web_check_makes_real_requests(settings):
    """The check that catches uvicorn's dynamic imports: it resolves its
    event loop, HTTP protocol and lifespan implementations BY STRING at
    runtime, so a bundle missing them starts perfectly and dies on the first
    request. Nothing short of an actual request notices."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.verify import check_web_server

    report = VerifyReport()
    check_web_server(report, settings)
    check = report.checks[0]
    assert check.ok, check.detail
    assert "/healthz" in check.detail


def test_the_web_check_lives_outside_slap():
    """It drives uvicorn, and nothing under `slap/` may import a web
    framework. That rule is what made replacing PySide6 with a browser UI a
    rewrite of one package rather than of the project, and the AST test
    caught this function on its first day in the wrong package."""
    import slap.verify
    import slap_web.verify

    assert hasattr(slap_web.verify, "check_web_server")
    assert not hasattr(slap.verify, "check_web_server")


def test_an_extra_check_that_raises_is_reported_not_fatal(settings):
    """CI reads the exit code; a traceback is a worse signal than a false."""
    def exploding(report, settings):
        raise RuntimeError("boom")
    exploding.check_name = "exploding check"

    report = verify(settings, lighthouse=False, extra_checks=[exploding])
    failed = {c.name: c.detail for c in report.failures}
    assert "exploding check" in failed
    assert "boom" in failed["exploding check"]


def test_a_broken_pdf_backend_is_reported(settings, monkeypatch):
    from slap import core
    from slap.report.pdf import BackendStatus

    monkeypatch.setattr(core, "pdf_backend_status",
                        lambda: BackendStatus(False, "no browser here"))
    report = VerifyReport()
    check_pdf(report)
    assert report.checks[0].ok is False
    assert "no browser" in report.checks[0].detail


# --------------------------------------------------------------------------
# The whole command
# --------------------------------------------------------------------------

def test_verify_never_raises_even_when_everything_is_wrong(tmp_path, monkeypatch):
    """CI reads the exit code. A traceback is a worse signal than a false."""
    from slap import core
    from slap.report.pdf import BackendStatus

    broken = Settings()
    broken.db_path = tmp_path / "x.sqlite3"
    broken.artifact_dir = tmp_path / "a"
    broken.report_dir = tmp_path / "r"
    broken.vulndb_path = tmp_path / "missing.json"
    broken.collector.crux_api_key = None
    broken.discovery.enabled = False
    monkeypatch.setattr(core, "pdf_backend_status",
                        lambda: BackendStatus(False, "no browser"))

    report = verify(broken, lighthouse=False)
    assert report.ok is False
    assert {"vulnerability database", "pdf backend"} <= {
        c.name for c in report.failures}


def test_the_command_exits_non_zero_on_failure(tmp_path, capsys):
    import argparse

    from slap import cli

    broken = Settings()
    broken.vulndb_path = tmp_path / "missing.json"
    broken.collector.crux_api_key = None
    args = argparse.Namespace(json=True, no_lighthouse=True, no_web=True,
                              max_vulndb_age=None)
    code = cli.cmd_verify(args, broken)
    assert code == 1
    assert '"ok": false' in capsys.readouterr().out


def test_verifying_does_not_write_into_a_real_database(tmp_path):
    """`slap verify` must be safe to run on a machine with audits worth
    keeping: it writes to a scratch directory, not to the user's history."""
    import argparse

    from slap import cli

    real = Settings()
    real.db_path = tmp_path / "precious.sqlite3"
    real.collector.crux_api_key = None
    args = argparse.Namespace(json=True, no_lighthouse=True, no_web=True,
                              max_vulndb_age=None)
    cli.cmd_verify(args, real)
    assert not (tmp_path / "precious.sqlite3").exists()
