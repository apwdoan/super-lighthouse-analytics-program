"""The web front-end's contribution to `slap verify`.

Lives here rather than in :mod:`slap.verify` because it drives uvicorn, and
nothing under ``slap/`` may import a web framework. That is rule 5, the reason
replacing PySide6 with a browser UI was a rewrite of one package rather than
of the project, and it is enforced by a test that walks the AST of every
module under ``slap/``. That test caught this function on its first day in the
wrong package.

:func:`slap.verify.verify` takes a list of extra checks; the CLI passes these
in when the web extra is installed.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import threading
from pathlib import Path
from typing import Iterator

from slap.config import Settings
from slap.streams import detached
from slap.verify import VerifyReport, _free_port

from .server import make_config


def _serve_and_request(report: VerifyReport, settings: Settings, *,
                       name: str, prefix: str = "") -> None:
    """Start the real server on a loopback port and request real routes.

    This is what catches uvicorn's dynamic imports. It resolves its event
    loop, HTTP protocol and lifespan implementations *by string* at runtime,
    so a bundle missing them starts perfectly and dies on the first request.
    Nothing short of an actual request notices.

    Driven from a thread rather than a subprocess: re-executing a frozen
    bundle to test itself invites the multiprocessing recursion that
    `freeze_support` exists to prevent.
    """
    try:
        import httpx
        import uvicorn

        from .app import create_app
    except ImportError as exc:
        report.add(name, False, f"web extra not installed: {exc}")
        return

    port = _free_port()
    # The launch path's own configuration, not a copy of it. See
    # `server.make_config`: a verifier that assembles its own uvicorn
    # arguments proves that those arguments work, which is not the question.
    config = make_config(create_app(settings), port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = 20.0
        step = 0.25
        waited = 0.0
        while waited < deadline and not server.started:
            threading.Event().wait(step)
            waited += step
        if not server.started:
            report.add(name, False, "did not start within 20s")
            return

        failures: list[str] = []
        with httpx.Client(timeout=20.0) as client:
            for route in ("/healthz", "/", "/findings"):
                try:
                    response = client.get(base + route)
                    if response.status_code != 200:
                        failures.append(f"{route} -> HTTP {response.status_code}")
                except Exception as exc:               # noqa: BLE001
                    failures.append(f"{route} -> {type(exc).__name__}: {exc}")
        report.add(name, not failures,
                   f"{prefix}served /healthz, / and /findings on {base}"
                   if not failures else f"{prefix}" + "; ".join(failures))
    finally:
        server.should_exit = True
        thread.join(timeout=15)


def check_web_server(report: VerifyReport, settings: Settings) -> None:
    """The server, started the ordinary way: by something with a console."""
    _serve_and_request(report, settings, name="web server")


check_web_server.check_name = "web server"


@contextlib.contextmanager
def _log_to(path: Path) -> Iterator[None]:
    """Point the launch path's log at a scratch file for the duration."""
    previous = os.environ.get("SLAP_LOG")
    os.environ["SLAP_LOG"] = str(path)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("SLAP_LOG", None)
        else:
            os.environ["SLAP_LOG"] = previous


def check_headless_launch(report: VerifyReport, settings: Settings) -> None:
    """The server, started the way Explorer starts it: with no streams at all.

    The check that was missing, and the reason a crash on the most common
    path of all -- double-clicking SLAP.exe -- shipped past a green CI and a
    passing `slap verify`. Both launch the executable from a shell, and on
    Windows a GUI-subsystem process inherits its parent console's handles, so
    both proved the one case that was never in doubt. From Explorer there is
    no parent console to inherit, ``sys.stdout`` is ``None``, and uvicorn's
    first act is to ask that ``None`` whether it is a terminal.

    Nothing here repairs the streams: that is deliberate. The repair has to
    come from the launch path itself (`server.make_config`), or this check
    would pass a build whose users cannot start it. Delete the
    :func:`~slap.streams.attach_output` call there and this raises the real
    thing, ``ValueError: Unable to configure formatter 'default'``.

    ``SLAP_LOG`` sends the log somewhere disposable, so verifying a build
    does not append to a log the user may be reading, and so the check can
    then assert the file exists. A launch that dies with no console leaves
    the user nothing to send us except that file.
    """
    with tempfile.TemporaryDirectory(prefix="slap-headless-") as scratch:
        log = Path(scratch) / "slap.log"
        with _log_to(log), detached():
            _serve_and_request(report, settings, name="headless launch",
                               prefix="no console: ")

        check = report.checks[-1] if report.checks else None
        if check is not None and check.name == "headless launch" and check.ok:
            if not log.is_file() or log.stat().st_size == 0:
                check.ok = False
                check.detail = ("started, but wrote nothing to its log; "
                                "a crash on this path would be silent")


check_headless_launch.check_name = "headless launch"
