"""The web front-end's contribution to `slap verify`.

Lives here rather than in :mod:`slap.verify` because it drives uvicorn, and
nothing under ``slap/`` may import a web framework. That is rule 5, the reason
replacing PySide6 with a browser UI was a rewrite of one package rather than
of the project, and it is enforced by a test that walks the AST of every
module under ``slap/``. That test caught this function on its first day in the
wrong package.

:func:`slap.verify.verify` takes a list of extra checks; the CLI passes this
one in when the web extra is installed.
"""

from __future__ import annotations

import threading

from slap.config import Settings
from slap.verify import VerifyReport, _free_port


def check_web_server(report: VerifyReport, settings: Settings) -> None:
    """Start the real server on a loopback port and request real routes.

    This is the check that catches uvicorn's dynamic imports. It resolves its
    event loop, HTTP protocol and lifespan implementations *by string* at
    runtime, so a bundle missing them starts perfectly and dies on the first
    request. Nothing short of an actual request notices.

    Driven from a thread rather than a subprocess: re-executing a frozen
    bundle to test itself invites the multiprocessing recursion that
    `freeze_support` exists to prevent.
    """
    try:
        import httpx
        import uvicorn

        from .app import create_app
    except ImportError as exc:
        report.add("web server", False, f"web extra not installed: {exc}")
        return

    port = _free_port()
    config = uvicorn.Config(create_app(settings), host="127.0.0.1", port=port,
                            log_level="error")
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
            report.add("web server", False, "did not start within 20s")
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
        report.add("web server", not failures,
                   f"served /healthz, / and /findings on {base}"
                   if not failures else "; ".join(failures))
    finally:
        server.should_exit = True
        thread.join(timeout=15)


check_web_server.check_name = "web server"
