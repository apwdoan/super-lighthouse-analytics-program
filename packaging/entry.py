"""Entry point for the bundled application.

SLAP is a GUI application. Double-clicking the executable starts a local
server and opens the user's browser at it, and that is the whole interface:
audits, reports, settings, the vulnerability database and quitting all live
on the page. There is no user-facing command line, and this file is where
that is true rather than merely intended.

One argument exists, and it is not for users:

    SLAP --self-check [--json] [--no-lighthouse] [--max-vulndb-age N]

That is the build's own test, run by CI against the bundle it just produced
on every platform. It is what caught the macOS signature break, the missing
Node inside the .app, the crash on every windowed launch, and the
vulnerability database that resolved to a path outside the bundle. Keeping
it costs one branch here; removing it would mean the only way to discover a
broken Mac build is for somebody to double-click it.

Anything else on the command line is ignored and the GUI starts anyway.
A person who drags a file onto the icon, or a shortcut carrying a stale
flag, should get the application rather than an error they cannot read: the
bundle is built with ``console=False``, so there is nowhere to print one.
That same flag is why :func:`slap.streams.attach_output` runs first, before
any import that might ask a stream a question. uvicorn asks on its first
line, and answering it with a ``None`` stdout crashed every launch from
Explorer until it was fixed.
"""

from __future__ import annotations

import multiprocessing
import sys

#: Not "--verify": the word for what this does, in the one place somebody
#: might read it, should not sound like a thing they are supposed to run.
SELF_CHECK = "--self-check"


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
    if argv and argv[0] == SELF_CHECK:
        from slap.verify import main as self_check

        return self_check(argv[1:])

    from slap_web import main as web_main

    return web_main()


if __name__ == "__main__":
    raise SystemExit(main())
