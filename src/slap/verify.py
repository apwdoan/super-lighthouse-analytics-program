"""Does this build actually work? One command, every platform.

Written because the answer used to live in two 145-line CI steps, one in bash
and one in PowerShell, asserting the same eleven things in different
languages. They had not drifted, but nothing prevented it: a check added to
one and forgotten in the other would have passed CI and shipped. That is
exactly what happened by hand when the vulnerability-database assertions went
in, and only care stopped it.

So the *checks* live here, in Python, covered by the test suite and shipped
inside the bundle they verify. What stays platform-specific in CI is only what
genuinely is: launching the process, finding the executable, and stripping the
environment.

**The only command line this project still has, and not a user feature.**
SLAP is a GUI application: the executable opens a browser and there is
nothing for a person to type. This survives the CLI's removal because CI
runs it against the bundle it just built, on every platform, and it is what
caught the macOS signature break, the missing Node inside the .app, the
windowed-launch crash and the vulnerability database resolving outside the
bundle. A check somebody has to remember to run is a check that does not
run. See :func:`main` for how it is reached.

The governing rule, inherited from `doctor` and from the packaging work:
**check the thing the real code path does, not a proxy for it.** `check_backend`
once reported PDF export healthy on a bundle whose export failed, because it
stat-ed a file rather than launching the browser. So this runs a real audit
against a page it serves itself, exports a real PDF, and drives the real web
server over a real socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

from . import __version__, bundle
from .config import Settings

#: A page with enough wrong with it that findings fire: no compression, no
#: caching, no security headers, and a cookie with no flags. Served from
#: memory so the bundle needs no fixture files on disk.
_PAGE = (
    b"<!doctype html><html><head><title>SLAP self-check</title>"
    b'<meta name="generator" content="WordPress 6.5">'
    b"</head><body><h1>SLAP self-check</h1>"
    b"<p>Served by the bundle to verify itself.</p>"
    b"</body></html>"
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", "selfcheck=1; Path=/")
        self.end_headers()
        self.wfile.write(_PAGE)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


def _serve() -> tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextlib.contextmanager
def scratch_directory(prefix: str) -> Iterator[Path]:
    """A temporary directory whose cleanup does not outrank the verdict.

    Verifying writes a database, reports and a log into scratch space and
    deletes it on the way out. On Windows an open file cannot be deleted
    (SQLite opens without FILE_SHARE_DELETE), so anything still holding a
    handle turns cleanup into ``WinError 32`` — and because cleanup runs
    *after* the report is printed, `slap verify` would announce the build
    works and then crash with a traceback. The exit code and the sentence
    both lie about the build.

    The first time that happened, the holder was SLAP itself: a cache bug
    in ``db.connect`` leaked every connection after the first
    ``close_thread_connections``. That bug is fixed, and the tracking test
    beside this one asserts the command closes every connection it opens —
    which is what earns this function the right to be lenient about the
    holders that remain. Those are real and not ours to close: a server
    thread pool's workers release their connections on their own schedule
    shortly after the web checks finish, and Windows virus scanners open
    freshly modified files behind everyone's back.

    So: retry with a short backoff, which outlasts both; then delete what
    can be deleted, leave what cannot, and say so on stderr. A scratch
    directory stranded in the temp dir is a nuisance, not a failed build.

    Not ``TemporaryDirectory(ignore_cleanup_errors=True)``, because that
    swallows the failure silently everywhere — including the day another
    leak like the one above lands, which is exactly the day the noise is
    the point. The tracking test guards the our-handle case; the stderr
    note reports the rest.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        for pause in (0.0, 0.1, 0.25, 0.5, 1.0):
            time.sleep(pause)
            try:
                shutil.rmtree(path)
                break
            except OSError:
                continue
        else:
            shutil.rmtree(path, ignore_errors=True)
            if path.exists():
                print(f"note: could not remove scratch directory {path}; "
                      "something (an antivirus?) is holding a file in it",
                      file=sys.stderr)


@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    detail: str = ""
    #: A check that fails without making the bundle unusable. CI does not
    #: gate on these; a person reading the output still wants to see them.
    advisory: bool = False


@dataclass(slots=True)
class VerifyReport:
    checks: list[Check] = field(default_factory=list)
    platform: str = ""
    machine: str = ""
    frozen: bool = False
    slap_version: str = __version__

    def add(self, name: str, ok: bool, detail: str = "", *,
            advisory: bool = False) -> None:
        self.checks.append(Check(name, ok, detail, advisory))

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks if not c.advisory)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and not c.advisory]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "platform": self.platform,
            "machine": self.machine,
            "frozen": self.frozen,
            "slap_version": self.slap_version,
            "checks": [
                {"name": c.name, "ok": c.ok, "detail": c.detail,
                 "advisory": c.advisory}
                for c in self.checks
            ],
        }


# --------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------

def check_paths_are_inside_the_bundle(report: VerifyReport) -> None:
    """Every resolved runtime path must live under the bundle root.

    The check that a stripped environment is supposed to make unnecessary,
    asserted anyway. On Windows there is no ``env -i``, so the CI step clears
    variables by name; the first version missed ``PLAYWRIGHT_BROWSERS_PATH``
    and the bundle cheerfully used the *staging* browser, reporting success
    while proving nothing about what it ships. A leak like that is invisible
    unless something compares the paths to the bundle.
    """
    root = bundle.bundle_root()
    if not bundle.is_frozen() or root is None:
        report.add("paths inside the bundle", True,
                   "not a frozen build; nothing to contain", advisory=True)
        return

    root = Path(root).resolve()
    # On macOS the executable sits in Contents/MacOS, but PyInstaller puts
    # an .app's data files in Contents/Resources and its binaries in
    # Contents/Frameworks, reached through symlinks that resolve() follows.
    # Contain to the .app, which is the thing that actually ships; anything
    # inside it is bundled by definition. Anchoring to the executable's own
    # directory would flag Playwright's driver Node as a leak on every Mac.
    for parent in root.parents:
        if parent.suffix == ".app":
            root = parent
            break
    outside: list[str] = []
    for name, value in bundle.describe().items():
        if name in ("frozen", "bundle_root", "node_source") or not value:
            continue
        try:
            Path(value).resolve().relative_to(root)
        except ValueError:
            outside.append(f"{name}={value}")

    report.add(
        "paths inside the bundle", not outside,
        f"all runtime paths under {root}" if not outside
        else "resolved outside the bundle: " + "; ".join(outside),
    )


def check_macos_signature(report: VerifyReport) -> None:
    """Is the executable signed so macOS will launch it?

    Only one signature decides that, and it is not the whole-bundle seal the
    first version of this check verified. The **main executable** must carry a
    valid signature or the Apple Silicon kernel refuses to exec it;
    PyInstaller signs ``Contents/MacOS/SLAP`` when it assembles the .app, and
    copying ``runtime/`` beside it afterwards does not touch that Mach-O, so
    the signature the kernel checks survives.

    The check reads that signature with ``codesign -d`` (display), never
    ``codesign --verify``. Verify validates the bundle's resource seal, which
    means walking ``Contents/`` -- and the bundled ``node_modules`` tree
    (directories like ``@types/node/ts5.7``) defeats codesign's bundle
    scanner, so a full verify fails on a perfectly launchable app. That is the
    exact wall the build hit; running it here would just move the same failure
    from the build step to this one. Display reads the executable's own
    signature and stops, so the runtime tree never enters into it.

    On Apple Silicon this code is already running inside that executable via
    ``SLAP --self-check``, so the kernel has effectively pre-confirmed the
    answer. The probe earns its keep on an Intel runner, where an unsigned
    Mach-O still execs: there it is what would catch an executable that runs
    on the build machine yet strands every arm64 user. The whole-bundle seal
    is deliberately not checked -- it is ad-hoc (never satisfies Gatekeeper;
    the first-run helper's quarantine strip is what does) and structurally
    absent here, so verifying it would spend a 700MB bundle walk to report a
    failure that means nothing.
    """
    if sys.platform != "darwin" or not bundle.is_frozen():
        report.add("code signature", True,
                   "not a macOS app bundle; nothing to sign", advisory=True)
        return

    root = bundle.bundle_root()
    app = next((p for p in (root or Path(".")).parents if p.suffix == ".app"),
               None)
    if app is None:
        report.add("code signature", True,
                   "frozen, but not inside an .app", advisory=True)
        return

    # Read the executable's own signature without validating the bundle's
    # resource seal: `codesign -d` (display) does not walk Contents/, so the
    # bundled runtime that defeats a full --verify never enters into it. A
    # non-zero exit here means the Mach-O carries no signature at all, which
    # is the one state the arm64 kernel will not launch.
    executable = app / "Contents" / "MacOS" / "SLAP"
    result = subprocess.run(["codesign", "-d", str(executable)],
                            capture_output=True, text=True)
    detail = " ".join((result.stderr or result.stdout or "").split())
    report.add(
        "code signature", result.returncode == 0,
        f"{executable.name} is signed and will launch"
        if result.returncode == 0
        else f"{detail[:200]} -- macOS will refuse to launch it")


def check_lighthouse(report: VerifyReport, settings: Settings) -> None:
    from .collectors.lighthouse import LighthouseRunner

    runner = LighthouseRunner(settings.lighthouse)
    ok, detail = runner.check()
    if ok:
        try:
            versions = asyncio.run(runner.probe())
            detail = (f"Lighthouse {versions.get('lighthouseVersion')}, "
                      f"Chrome {versions.get('chromeVersion')}, "
                      f"Node {versions.get('node')}")
        except Exception as exc:                       # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
    report.add("lighthouse", ok, detail)


def check_pdf(report: VerifyReport) -> None:
    from . import core

    status = core.pdf_backend_status()
    report.add("pdf backend", bool(status), status.detail)


def check_vulndb(report: VerifyReport, settings: Settings, *,
                 max_age_days: int | None = None) -> None:
    from .vulndb import VulnDatabase

    database = VulnDatabase.load(settings.vulndb_path)
    if not database.available:
        report.add("vulnerability database", False,
                   f"no advisories at {settings.vulndb_path}")
        return
    detail = (f"{database.count} advisories from "
              f"{', '.join(sorted(database.sources))}, "
              f"{database.age_days} day(s) old, at {settings.vulndb_path}")
    ok = "npm" in database.sources
    if ok and max_age_days is not None and (database.age_days or 0) > max_age_days:
        ok = False
        detail += f" -- older than the {max_age_days}-day limit"
    report.add("vulnerability database", ok, detail)


def check_audit_and_report(report: VerifyReport, settings: Settings, *,
                           lighthouse: bool) -> None:
    """Audit a page this process serves, then export HTML and PDF from it.

    The end-to-end check, and the reason the others cannot be trusted alone:
    a bundle can resolve every path and still fail on the first real run. It
    audits itself rather than the internet so the check works offline and
    cannot fail because somebody else's site was down.
    """
    from . import core, db

    httpd, base = _serve()
    try:
        settings.lighthouse.enabled = lighthouse
        result = asyncio.run(core.run_batch([base], settings))
        if result.succeeded != 1:
            error = result.outcomes[0].error if result.outcomes else "no outcome"
            report.add("audit", False, f"the audit did not complete: {error}")
            return

        run_id = result.run_ids[0]
        connection = db.connect(settings.db_path)
        findings = db.get_findings(connection, run_id)
        observations = db.get_observations(connection, run_id)
        report.add("audit", bool(observations),
                   f"run {run_id}: {len(observations)} observations, "
                   f"{len(findings)} findings")

        exported = core.export_report(settings, run_id, pdf=True)
        html_ok = exported.html_path.is_file() and exported.html_path.stat().st_size > 0
        report.add("html report", html_ok, str(exported.html_path))

        pdf_ok = bool(exported.pdf_path) and exported.pdf_path.is_file()
        report.add(
            "pdf export", pdf_ok,
            str(exported.pdf_path) if pdf_ok
            else (exported.pdf_error or "no PDF produced"),
        )
    except Exception as exc:                           # noqa: BLE001
        report.add("audit", False, f"{type(exc).__name__}: {exc}")
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------

#: A check is any callable taking (report, settings). Front-ends contribute
#: their own: `slap_web.verify.check_web_server` drives uvicorn, which nothing
#: under `slap/` may import.
Check_fn = Any


def verify(settings: Settings, *, lighthouse: bool = True,
           max_vulndb_age_days: int | None = None,
           extra_checks: "list[Check_fn] | None" = None) -> VerifyReport:
    """Run every check and return the report. Never raises.

    ``extra_checks`` is how the web front-end contributes its own. Nothing
    under ``slap/`` imports a UI framework — rule 5, and the reason replacing
    PySide6 with a web UI was a rewrite of one package rather than of the
    project. A verifier that reached for uvicorn here would be the first
    breach, and the AST test that walks every module under `slap/` caught it
    the moment this file did exactly that.
    """
    report = VerifyReport(
        platform=sys.platform,
        machine=platform.machine(),
        frozen=bundle.is_frozen(),
    )
    settings.ensure_dirs()

    check_paths_are_inside_the_bundle(report)
    check_macos_signature(report)
    check_vulndb(report, settings, max_age_days=max_vulndb_age_days)
    check_pdf(report)
    if lighthouse:
        check_lighthouse(report, settings)
    check_audit_and_report(report, settings, lighthouse=lighthouse)
    for check in (extra_checks or []):
        try:
            check(report, settings)
        except Exception as exc:                       # noqa: BLE001
            report.add(getattr(check, "check_name", "extra check"), False,
                       f"{type(exc).__name__}: {exc}")
    return report


def render(report: VerifyReport, *, as_json: bool = False) -> str:
    if as_json:
        return json.dumps(report.to_dict(), indent=2)

    lines = [
        "",
        f"SLAP {report.slap_version} on {report.platform}/{report.machine}"
        f"{' (bundled)' if report.frozen else ' (source checkout)'}",
        "",
    ]
    for check in report.checks:
        mark = "ok " if check.ok else ("note" if check.advisory else "FAIL")
        lines.append(f"  [{mark}] {check.name}")
        if check.detail:
            lines.append(f"         {check.detail}")
    lines.append("")
    lines.append("This build works." if report.ok else
                 "This build is NOT usable: "
                 + ", ".join(c.name for c in report.failures))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# The command line, and the only one this project still has.
#
# SLAP is a GUI application: the executable opens a browser and there is no
# user-facing command line at all. This one survives because it is not a
# user feature. It is the build's self-test, run by CI against the bundle
# it just produced on every platform, and it is what caught the macOS
# signature break, the missing Node in the .app, the windowed-launch crash
# and the vulnerability database that resolved outside the bundle. A check
# a person has to remember to run is a check that does not run.
#
# Reached as `python -m slap.verify` from a source checkout and
# `SLAP --self-check` from the bundle. Neither is advertised anywhere a
# user looks.
# --------------------------------------------------------------------------

def main(argv: "list[str] | None" = None) -> int:
    """Run every check, print the report, and return the exit code CI reads."""
    import argparse

    from . import core
    from .config import Settings

    parser = argparse.ArgumentParser(
        prog="slap --self-check",
        description="Prove this build works. Internal; not a user command.")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--no-lighthouse", action="store_true",
                        help="skip the browser checks")
    parser.add_argument("--no-web", action="store_true",
                        help="skip the web server checks")
    parser.add_argument("--max-vulndb-age", type=int, metavar="DAYS",
                        help="fail if the bundled database is older than this")
    parser.add_argument("--config", default=None)
    args = parser.parse_args(argv)

    settings = Settings.load(args.config)

    # A scratch database and report directory, so verifying never writes into
    # a teammate's real history. Safe to run twice on a machine that has
    # audits worth keeping. Not a plain TemporaryDirectory: on Windows,
    # deleting the just-checkpointed database races the virus scanner.
    with scratch_directory("slap-verify-") as root:
        settings.db_path = root / "verify.sqlite3"
        settings.artifact_dir = root / "artifacts"
        settings.report_dir = root / "reports"
        settings.discovery.enabled = False        # one page is the point
        settings.collector.crux_api_key = None    # no network dependency

        # The web checks live in `slap_web`, because they drive uvicorn and
        # nothing under `slap/` may import a web framework. This function is
        # the seam that puts the two together, as the CLI used to be.
        extra = []
        if not args.no_web:
            try:
                from slap_web.verify import (
                    check_headless_launch, check_web_server,
                )

                extra.extend([check_web_server, check_headless_launch])
            except ImportError:
                pass

        report = verify(settings, lighthouse=not args.no_lighthouse,
                        max_vulndb_age_days=args.max_vulndb_age,
                        extra_checks=extra)
        print(render(report, as_json=args.json))
        core.close_connections()
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
