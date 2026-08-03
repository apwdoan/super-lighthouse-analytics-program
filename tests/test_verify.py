"""`slap verify`: the checks that used to live in two shells.

The point of moving them here is that they are now covered by this file. In
CI they were two 145-line steps, one bash and one PowerShell, and nothing
prevented a check landing on only one platform — which is exactly what nearly
happened when the vulnerability-database assertions went in.

A verifier that only ever passes is worthless, so most of what follows breaks
something and asserts the failure.
"""

from __future__ import annotations

import os
import sys

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


def test_a_mac_app_bundle_is_contained_by_the_app_not_the_exe_dir(monkeypatch,
                                                                  tmp_path):
    """The layout PyInstaller actually produces for an .app: the executable
    in Contents/MacOS, data in Contents/Resources, binaries in
    Contents/Frameworks, symlinks between them that resolve() follows. The
    executable's own directory contains almost nothing, so anchoring the
    containment check there flags Playwright's driver Node as a leak on
    every Mac. The .app is the thing that ships; contain to it."""
    app = tmp_path / "SLAP.app"
    macos = app / "Contents" / "MacOS"
    resources = app / "Contents" / "Resources" / "playwright" / "driver"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)
    node = resources / "node"
    node.touch()
    frameworks = app / "Contents" / "Frameworks"
    frameworks.mkdir()
    (frameworks / "playwright").symlink_to(
        app / "Contents" / "Resources" / "playwright", target_is_directory=True)
    outside = tmp_path / "staging-node"
    outside.touch()

    monkeypatch.setattr(verify_module.bundle, "is_frozen", lambda: True)
    monkeypatch.setattr(verify_module.bundle, "bundle_root", lambda: macos)
    monkeypatch.setattr(verify_module.bundle, "describe", lambda: {
        "frozen": "True", "bundle_root": str(macos),
        "node": str(frameworks / "playwright" / "driver" / "node"),
        "node_source": "playwright driver",
    })
    report = VerifyReport()
    check_paths_are_inside_the_bundle(report)
    assert report.checks[0].ok, report.checks[0].detail

    # And a genuine leak is still a leak: .app containment must not turn
    # the check into a formality.
    monkeypatch.setattr(verify_module.bundle, "describe", lambda: {
        "frozen": "True", "bundle_root": str(macos), "node": str(outside),
        "node_source": "staged runtime",
    })
    leaked = VerifyReport()
    check_paths_are_inside_the_bundle(leaked)
    assert leaked.checks[0].ok is False
    assert "node" in leaked.checks[0].detail


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


def test_the_headless_check_starts_with_no_console(settings):
    """The check that was missing. `SLAP.exe` double-clicked from Explorer is
    a process with no streams at all, and uvicorn's first act is to ask
    `sys.stdout` whether it is a terminal. CI and `slap verify` both launched
    the executable from a shell, where a Windows GUI-subsystem process
    inherits the parent console's handles, so both proved the one case that
    was never in doubt while the common one crashed."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.verify import check_headless_launch

    report = VerifyReport()
    check_headless_launch(report, settings)
    check = report.checks[0]
    assert check.ok, check.detail
    assert "no console" in check.detail


def test_the_headless_check_puts_the_streams_back(settings, capsys):
    """It takes the process's stdout away to do its job. Leaving it that way
    would take the rest of `slap verify`'s output with it."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.verify import check_headless_launch

    before = sys.stdout
    check_headless_launch(VerifyReport(), settings)
    assert sys.stdout is before
    print("still audible")
    assert "still audible" in capsys.readouterr().out


def test_the_headless_check_does_not_touch_the_users_log(settings, monkeypatch,
                                                         tmp_path):
    """Verifying a build must not append to a log the user may be reading,
    and must leave SLAP_LOG as it found it."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.verify import check_headless_launch

    theirs = tmp_path / "theirs.log"
    monkeypatch.setenv("SLAP_LOG", str(theirs))
    check_headless_launch(VerifyReport(), settings)
    assert not theirs.exists()
    assert os.environ["SLAP_LOG"] == str(theirs)


def test_the_headless_check_fails_when_the_repair_is_gone(settings, monkeypatch):
    """A check that cannot fail is decoration. Neutralise the stream repair
    and this must report the crash rather than passing anyway, which is what
    it would do if it repaired the streams itself before starting."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap import streams
    from slap_web.verify import check_headless_launch

    monkeypatch.setattr(streams, "attach_output", lambda path=None: None)
    report = verify(settings, lighthouse=False,
                    extra_checks=[check_headless_launch])
    failed = {c.name: c.detail for c in report.failures}
    assert "headless launch" in failed
    assert "formatter" in failed["headless launch"] or \
           "isatty" in failed["headless launch"]


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


def test_the_command_exits_non_zero_on_failure(tmp_path, capsys, monkeypatch):
    """CI reads the exit code, and this is now the ONLY command line this
    project has: SLAP is a GUI application and `verify` survived the CLI's
    removal because it is the build's self-test, not a user feature."""
    from slap import verify as verify_module

    broken = Settings()
    broken.vulndb_path = tmp_path / "missing.json"
    broken.collector.crux_api_key = None
    monkeypatch.setattr(Settings, "load", classmethod(lambda cls, p=None: broken))
    code = verify_module.main(["--json", "--no-lighthouse", "--no-web"])
    assert code == 1
    assert '"ok": false' in capsys.readouterr().out


def test_no_sqlite_connection_survives_cmd_verify(tmp_path, monkeypatch, capsys):
    """Every connection the command opens must be closed by the time it
    returns.

    This is what earns `scratch_directory` the right to give up quietly.
    Windows CI failed cleanup with WinError 32 on the scratch database; the
    holder there is external (a scanner opening the freshly checkpointed
    file), and the cleanup now retries and then leaves the directory rather
    than crash. If the busy file were ever OURS, that leniency would hide a
    real connection leak forever. So this tracks every sqlite connection
    created during the command and asserts each was closed, which fails
    loudly and cross-platform on the day someone leaks one.
    """
    import sqlite3
    import threading

    from slap import verify as verify_module

    made: list[tuple[str, str, sqlite3.Connection]] = []
    real_connect = sqlite3.connect

    def tracking(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        made.append((str(args[0]) if args else str(kwargs.get("database")),
                     threading.current_thread().name, conn))
        return conn

    monkeypatch.setattr(sqlite3, "connect", tracking)

    # The state every prior command leaves behind: an emptied — not absent —
    # connection cache. The leak this test exists for only fired from that
    # state, which is why it passed alone and failed in the suite, and why
    # it failed on CI only after other test files had run a command first.
    from slap import core
    core.close_connections()

    settings = Settings()
    settings.collector.crux_api_key = None
    monkeypatch.setattr(Settings, "load",
                        classmethod(lambda cls, p=None: settings))
    verify_module.main(["--json", "--no-lighthouse", "--no-web"])

    # Only the command's own connections. The monkeypatch window is process
    # wide, and an anyio worker thread idling on from an earlier test's web
    # check can open a connection to that test's database mid-window; that
    # thread's connections are its own to close on its own schedule.
    ours = [(path, thread, conn) for path, thread, conn in made
            if "slap-verify-" in path]
    assert ours, "the command should have opened at least the scratch database"
    for path, thread, conn in ours:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            conn.cursor()
            pytest.fail(f"open connection to {path} from thread {thread}")


def test_scratch_cleanup_retries_past_a_transient_holder(monkeypatch):
    """The Windows CI failure: the delete lands inside a virus scanner's
    window on the just-written file. A short backoff outlasts the scan."""
    import shutil

    attempts: list[int] = []
    real_rmtree = shutil.rmtree

    def flaky(path, **kwargs):
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError(
                32, "The process cannot access the file because it is "
                    "being used by another process")
        return real_rmtree(path, **kwargs)

    monkeypatch.setattr(verify_module.shutil, "rmtree", flaky)
    monkeypatch.setattr(verify_module.time, "sleep", lambda seconds: None)

    with verify_module.scratch_directory("slap-test-") as root:
        (root / "held.sqlite3").write_text("x", encoding="utf-8")

    assert len(attempts) == 3
    assert not root.exists()


def test_scratch_cleanup_gives_up_quietly_not_with_a_traceback(monkeypatch,
                                                               capsys):
    """`slap verify` printing "This build works." and then dying in cleanup
    is a lie about the build. A stuck file costs a note on stderr and a
    stranded directory in temp, never the exit code."""
    import shutil

    real_rmtree = shutil.rmtree

    def stubborn(path, **kwargs):
        if kwargs.get("ignore_errors"):
            return None                       # deletes nothing, raises nothing
        raise PermissionError(32, "held forever")

    monkeypatch.setattr(verify_module.shutil, "rmtree", stubborn)
    monkeypatch.setattr(verify_module.time, "sleep", lambda seconds: None)

    with verify_module.scratch_directory("slap-test-") as root:
        (root / "held.sqlite3").write_text("x", encoding="utf-8")

    assert root.exists()                      # left behind, deliberately
    assert "scratch" in capsys.readouterr().err
    real_rmtree(root)


def test_verifying_does_not_write_into_a_real_database(tmp_path, monkeypatch):
    """The self-check must be safe to run on a machine with audits worth
    keeping: it writes to a scratch directory, not to the user's history."""
    from slap import verify as verify_module

    real = Settings()
    real.db_path = tmp_path / "precious.sqlite3"
    real.collector.crux_api_key = None
    monkeypatch.setattr(Settings, "load", classmethod(lambda cls, p=None: real))
    verify_module.main(["--json", "--no-lighthouse", "--no-web"])
    assert not (tmp_path / "precious.sqlite3").exists()


# --------------------------------------------------------------------------
# The macOS signature: the executable is the launch gate, the seal is not
# --------------------------------------------------------------------------

def test_the_signature_check_is_advisory_off_a_mac_bundle():
    from slap.verify import check_macos_signature

    report = VerifyReport()
    check_macos_signature(report)
    check = report.checks[0]
    assert check.ok and check.advisory


def _mac_frozen(monkeypatch, tmp_path):
    """Pose as a frozen .app: bundle_root is Contents/MacOS."""
    macos = tmp_path / "SLAP.app" / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    monkeypatch.setattr(verify_module.sys, "platform", "darwin")
    monkeypatch.setattr(verify_module.bundle, "is_frozen", lambda: True)
    monkeypatch.setattr(verify_module.bundle, "bundle_root", lambda: macos)
    return tmp_path / "SLAP.app"


def test_an_unsigned_executable_fails_the_check(monkeypatch, tmp_path):
    """The launch gate. On Apple Silicon the kernel refuses an unsigned
    Mach-O, so if ``Contents/MacOS/SLAP`` will not verify, the app cannot
    start -- and THAT, not the bundle seal, is what this check gates. The
    seal cannot be valid for an ad-hoc bundle carrying a runtime tree and
    the app does not need it, so gating on it failed every macOS build for
    a signature nobody would ever use."""
    import subprocess

    from slap.verify import check_macos_signature

    app = _mac_frozen(monkeypatch, tmp_path)
    exe = str(app / "Contents" / "MacOS" / "SLAP")

    def run(command, **kwargs):
        # The executable verify fails; the bundle-seal verify (--strict) is
        # allowed to pass so the failure is unambiguously the executable.
        if command[:2] == ["codesign", "--verify"] and command[-1] == exe:
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="code object is not signed at all")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(verify_module.subprocess, "run", run)
    report = VerifyReport()
    check_macos_signature(report)

    gate = next(c for c in report.checks if c.name == "code signature")
    assert gate.ok is False
    assert gate.advisory is False, "an app that will not launch is not advisory"
    assert "refuse to launch" in gate.detail


def test_a_missing_bundle_seal_is_a_note_not_a_failure(monkeypatch, tmp_path):
    """The seal codesign cannot produce here. The executable is signed, so
    the app launches; the seal is reported for information and never gates."""
    import subprocess

    from slap.verify import check_macos_signature

    app = _mac_frozen(monkeypatch, tmp_path)
    exe = str(app / "Contents" / "MacOS" / "SLAP")

    def run(command, **kwargs):
        # Executable verifies; the strict bundle-seal verify does not.
        if command[-1] == exe:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="a sealed resource is missing")

    monkeypatch.setattr(verify_module.subprocess, "run", run)
    report = VerifyReport()
    check_macos_signature(report)

    by_name = {c.name: c for c in report.checks}
    assert by_name["code signature"].ok is True             # launch gate: fine
    assert "will launch" in by_name["code signature"].detail
    seal = by_name["bundle seal"]
    assert seal.ok is False and seal.advisory is True       # a note, not a gate
    # And the report as a whole still passes: advisory failures do not gate.
    assert report.ok is True


def test_a_fully_signed_bundle_passes_both(monkeypatch, tmp_path):
    import subprocess

    from slap.verify import check_macos_signature

    _mac_frozen(monkeypatch, tmp_path)
    monkeypatch.setattr(
        verify_module.subprocess, "run",
        lambda command, **kw: subprocess.CompletedProcess(command, 0, "", ""))

    report = VerifyReport()
    check_macos_signature(report)
    by_name = {c.name: c for c in report.checks}
    assert by_name["code signature"].ok is True
    assert "will launch" in by_name["code signature"].detail
    assert by_name["bundle seal"].ok is True
