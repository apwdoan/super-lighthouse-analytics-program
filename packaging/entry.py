"""Entry point for the bundled application.

One executable serves both front-ends, because shipping two .exe files that
differ only in argv confuses more than it helps:

    SLAP.exe                 starts the local server and opens a browser
    SLAP.exe --cli audit ... the command line

The bundle is built with ``console=False``, so on Windows the CLI has no
console attached when launched from Explorer. Run it from an existing
terminal (``.\\SLAP.exe --cli doctor``) and output goes to that terminal,
because a GUI-subsystem process inherits its parent's console handles.
Launched from Explorer there is no parent console to inherit, the process
gets no streams at all, and :func:`slap.streams.attach_output` gives it a log
file instead. That is the first thing this does, before any import that
might ask a stream a question. uvicorn asks on its first line.
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    # Required before anything else in a frozen app: without it, any code
    # that spawns a process re-executes the bundle and forks the GUI
    # endlessly. PyInstaller's docs call this out and it is easy to forget.
    multiprocessing.freeze_support()

    # Before anything else that could write or probe a stream. Launched from
    # Explorer this process has none, and the traceback from finding that
    # out the hard way is the only thing the user can send us -- so it has
    # to have somewhere to land.
    from slap.streams import attach_output

    attach_output()

    argv = sys.argv[1:]
    if argv and argv[0] in ("--cli", "-c"):
        from slap.cli import main as cli_main

        return cli_main(argv[1:])

    from slap_web import main as web_main

    return web_main()


if __name__ == "__main__":
    raise SystemExit(main())
