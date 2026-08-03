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
import sys
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
    # timeout_graceful_shutdown is what makes the Quit button able to work.
    # Graceful shutdown waits for open connections, and the activity dock
    # holds a server-sent-events stream open on EVERY page, so an untimed
    # shutdown waits on an infinite stream forever: a Quit button that
    # visibly does nothing while the process lives on. Five seconds lets
    # in-flight requests finish and then cuts the streams loose.
    return uvicorn.Config(app, host="127.0.0.1", port=port,
                          log_level=log_level, timeout_graceful_shutdown=5)


def launch_options(argv: "list[str] | None" = None):
    """Parse what the launcher understands and IGNORE everything else.

    Nothing here may refuse to start the application. SLAP is a GUI
    program: it has no console, so argparse's usual behaviour on an
    unrecognised flag -- print usage, exit 2 -- means a window that never
    opens and an error message written to a log file the user does not know
    exists. That is exactly what a shortcut still carrying the deleted
    `--cli audit example.com` produced: the entry point correctly fell
    through to the GUI, and then the GUI's own parser killed it.

    So: ``add_help=False`` (``-h`` is a request for output there is nowhere
    to print) and ``parse_known_args``. Unknown arguments are noted in the
    log and dropped. The flags below stay because the self-check and the
    development workflow use them, not because a user is expected to type
    one.
    """
    parser = argparse.ArgumentParser(description="SLAP", add_help=False)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--config", default=None)
    # Without this the only way to point the server at a database is
    # SLAP_DB, which is awkward under `env -i` and is exactly what a
    # verification script needs to do.
    parser.add_argument("--db", default=None)
    args, ignored = parser.parse_known_args(argv)
    if ignored:
        print(f"ignoring {' '.join(ignored)}; SLAP has no command line",
              flush=True)
    return args


def main() -> int:
    import uvicorn

    from slap.config import Settings

    from .app import create_app

    args = launch_options()

    settings = Settings.load(args.config)
    if args.db:
        settings.db_path = Path(args.db).expanduser()

    port = free_port(args.port)
    url = f"http://127.0.0.1:{port}/"
    application = create_app(settings)
    config = make_config(application, port)
    server = uvicorn.Server(config)
    # The Quit button's other half. The route calls this; the activity
    # streams are woken so their generator threads end, then uvicorn winds
    # down and `run()` below returns. Only the launcher wires this, so the
    # button exists exactly where quitting means something: the packaged
    # app with no console and no window, where the alternative was Task
    # Manager.
    def shutdown() -> None:
        application.state.activity.close()
        server.should_exit = True

    application.state.shutdown = shutdown

    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()

    # flush=True is load-bearing. Python block-buffers stdout when it is
    # not a terminal, so a script that redirects this server's output to a
    # file and waits for the URL waits forever. The CI verification does
    # exactly that, and hung on it.
    print(f"SLAP is at {url}   (ctrl-c to stop)", flush=True)
    server.run()

    # Past this line the app is over: uvicorn has drained its connections
    # and SQLite is WAL-journalled with no writer left. Exiting through the
    # interpreter instead would wait for any straggler non-daemon thread --
    # today none, after `activity.close()`, but one future blocking
    # generator would silently turn Quit back into a 25-second zombie. An
    # app whose window is a browser tab owes the user a process that is
    # GONE when the page says goodbye.
    import contextlib
    import os

    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.flush()
    os._exit(0)
