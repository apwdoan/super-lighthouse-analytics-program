"""Launching the app: a loopback server plus the user's browser.

The distributable still works the way it did: a teammate runs one thing and
installs nothing. The difference is that the window is their own browser
rather than Qt, which is what removes ~117MB of PySide6 from the bundle.

Bound to 127.0.0.1 and nothing else. This app reads a local database and
runs a browser engine; it has no authentication and must never be reachable
from the network.
"""

from __future__ import annotations

import argparse
import socket
import threading
import webbrowser
from pathlib import Path


def free_port(preferred: int = 8765) -> int:
    """The preferred port if it is free, otherwise one the OS picks.

    Hardcoding a port means the second copy fails to start with a confusing
    "address already in use" rather than simply working.
    """
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def make_config(app: object, port: int, *, log_level: str = "warning"):
    """The uvicorn configuration, built in one place.

    One place because `slap verify` builds it here too, and a verifier that
    assembles its own copy proves only that *its* copy works. This one did:
    it drove uvicorn from a process that always had a console, and so never
    met the crash that made every double-click of SLAP.exe fail before SLAP
    ran a line of its own code.

    Constructing a ``Config`` is not the inert step it looks like. It calls
    ``configure_logging()``, which builds uvicorn's formatters, one of which
    asks ``sys.stdout.isatty()`` -- and a windowed build has no stdout to
    ask. Hence :func:`~slap.streams.attach_output` here rather than only at
    the entry point: this is the last moment before something looks at a
    stream, and it is a moment both callers pass through.
    """
    import uvicorn

    from slap.streams import attach_output

    attach_output()
    return uvicorn.Config(app, host="127.0.0.1", port=port, log_level=log_level)


def main() -> int:
    import uvicorn

    from slap.config import Settings

    from .app import create_app

    parser = argparse.ArgumentParser(description="SLAP web interface")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--config", default=None)
    # Mirrors the CLI's --db. Without it the only way to point the server at
    # a database is SLAP_DB, which is awkward under `env -i` and is exactly
    # what a verification script needs to do.
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    settings = Settings.load(args.config)
    if args.db:
        settings.db_path = Path(args.db).expanduser()

    port = free_port(args.port)
    url = f"http://127.0.0.1:{port}/"
    config = make_config(create_app(settings), port)

    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()

    # flush=True is load-bearing. Python block-buffers stdout when it is
    # not a terminal, so a script that redirects this server's output to a
    # file and waits for the URL waits forever. The CI verification does
    # exactly that, and hung on it.
    print(f"SLAP is at {url}   (ctrl-c to stop)", flush=True)
    uvicorn.Server(config).run()
    return 0
