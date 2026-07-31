"""Entry point for the bundled application.

One executable serves both front-ends, because shipping two .exe files that
differ only in argv confuses more than it helps:

    SLAP.exe                 the desktop app
    SLAP.exe --cli audit ... the command line

The bundle is built with ``console=False``, so on Windows the CLI has no
console attached when launched from Explorer. Run it from an existing
terminal (``.\\SLAP.exe --cli doctor``) and output goes to that terminal.
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    # Required before anything else in a frozen app: without it, any code
    # that spawns a process re-executes the bundle and forks the GUI
    # endlessly. PyInstaller's docs call this out and it is easy to forget.
    multiprocessing.freeze_support()

    argv = sys.argv[1:]
    if argv and argv[0] in ("--cli", "-c"):
        from slap.cli import main as cli_main

        return cli_main(argv[1:])

    from slap_gui import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
