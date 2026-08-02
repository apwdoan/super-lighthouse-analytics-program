"""Standard output that actually exists.

The bundle is built with ``console=False``, because a client-facing tool that
flashes a black terminal window on every launch looks broken. The cost of
that flag is that on Windows, launched from Explorer, the process has no
console: ``sys.stdout``, ``sys.stderr`` and ``sys.stdin`` are all ``None``.

Most code survives that. ``print()`` is a documented no-op when
``sys.stdout`` is ``None``, which is why nothing complained for months. But
any library that *asks a stream a question* rather than writing to it dies,
and uvicorn asks the first question of the run::

    self.use_colors = sys.stdout.isatty()
        AttributeError: 'NoneType' object has no attribute 'isatty'
    ValueError: Unable to configure formatter 'default'

That is every double-click of SLAP.exe: the one path the bundle exists to
provide, failing before the first line of SLAP's own code runs. It survived
CI because CI launches the executable from a shell, which on Windows hands a
GUI-subsystem process the parent console's handles. There is no console only
when there is no parent console, and nothing in the build ever ran that way.

So: give the process real streams before anything looks at them. The
replacement is a log file rather than ``os.devnull``, because the failure
mode this fixes is precisely a crash with nothing on screen. A user who
double-clicks and gets an "Unhandled exception" box has nothing to send us;
with a log file they have the traceback. Falling back to devnull only when
the file cannot be opened keeps the rule that this must never be the reason
the app fails to start.

Nothing here is Windows-specific. ``pythonw``, a macOS ``.app`` bundle and a
service manager that closes its children's descriptors all produce the same
process, and the fix does not care which one it is looking at.
"""

from __future__ import annotations

import contextlib
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO, Iterator

#: Truncate the log once it passes this. A log nobody rotates grows until a
#: disk does, and the only part anyone reads is the launch that just failed.
MAX_LOG_BYTES = 512 * 1024

#: The names replaced, in pairs. ``sys.__stdout__`` matters as much as
#: ``sys.stdout``: it is what a library reaches for when it wants the *real*
#: stream rather than whatever redirected it, and in a windowed build both
#: are equally ``None``.
_PAIRS = (("stdout", "__stdout__"), ("stderr", "__stderr__"))


def usable(stream: object) -> bool:
    """Can this be written to and interrogated without raising?

    Deliberately not ``stream is not None``. A stream can be present and
    still be useless: a closed file raises ``ValueError`` on write, an
    inherited-but-invalid Windows handle raises ``OSError``, and some
    frozen-app shims install a writer with no ``isatty`` at all, which fails
    in exactly the same place uvicorn did. The probe asks for what callers
    actually use.

    ``fileno()`` is not probed. pytest's capture and Jupyter both replace
    stdout with something that has no file descriptor and works fine.
    """
    if stream is None:
        return False
    try:
        stream.write("")                                   # type: ignore[attr-defined]
        stream.flush()                                     # type: ignore[attr-defined]
        stream.isatty()                                    # type: ignore[attr-defined]
    except Exception:                                      # noqa: BLE001
        return False
    return True


def default_log_path() -> Path:
    """Beside the database, not beside the executable.

    The application directory is Program Files on a normal install: not
    writable, and wiped by the next upgrade. The per-user data directory is
    where everything else this app owns already lives.

    ``SLAP_LOG`` overrides it, matching ``SLAP_DB``. `slap verify` sets it so
    that checking a build does not append to a log the user may be reading,
    and it is the only lever anyone has over a process that by definition
    cannot be given command-line arguments: it was double-clicked.
    """
    from .config import default_data_dir

    if override := os.environ.get("SLAP_LOG"):
        return Path(override).expanduser()
    return default_data_dir() / "slap.log"


@dataclass(slots=True)
class Attachment:
    """What :func:`attach_output` did, so `doctor` and `verify` can say so."""

    attached: bool
    path: Path | None = None
    detail: str = ""
    stream: IO[str] | None = None

    def close(self) -> None:
        if self.stream is not None and not self.stream.closed:
            with contextlib.suppress(Exception):
                self.stream.flush()
                self.stream.close()


_ATTACHED: Attachment | None = None


def _open_log(path: Path) -> tuple[IO[str], Path | None, str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a"
        if path.is_file() and path.stat().st_size > MAX_LOG_BYTES:
            mode = "w"
        # Line buffering, because the interesting case is a process that is
        # about to die. A block-buffered log loses the traceback that
        # explains why.
        stream = open(path, mode, buffering=1, encoding="utf-8", errors="replace")
        return stream, path, f"no console; output goes to {path}"
    except OSError as exc:
        return (open(os.devnull, "w", encoding="utf-8"), None,
                f"no console and no log file ({exc}); output discarded")


def attach_output(path: Path | None = None) -> Attachment:
    """Make sure this process has somewhere to write. Idempotent.

    Call it before anything that might look at a stream, which in practice
    means the first statement of the entry point. Returns immediately when a
    console is attached, so it costs a source checkout nothing.
    """
    global _ATTACHED

    if _ATTACHED is not None and sys.stdout is _ATTACHED.stream:
        return _ATTACHED

    broken = [pair for pair in _PAIRS
              if not usable(getattr(sys, pair[0], None))]
    if not broken:
        _ATTACHED = Attachment(False, None, "a console is attached")
        return _ATTACHED

    stream, resolved, detail = _open_log(path or default_log_path())
    for name, dunder in broken:
        setattr(sys, name, stream)
        if not usable(getattr(sys, dunder, None)):
            setattr(sys, dunder, stream)

    # stdin too. Nothing here prompts, but `subprocess` with no explicit
    # stdin, and anything that calls `input()` on a bad day, both reach for
    # it, and a None there raises just as readily as a None stdout.
    if not hasattr(sys.stdin, "read"):
        with contextlib.suppress(OSError):
            sys.stdin = sys.__stdin__ = open(os.devnull, encoding="utf-8")

    if resolved is not None:
        from . import __version__

        stamp = datetime.now().isoformat(timespec="seconds")
        stream.write(f"\n---- SLAP {__version__} started {stamp} ----\n")

    _ATTACHED = Attachment(True, resolved, detail, stream)
    return _ATTACHED


def attachment() -> Attachment | None:
    """What the last :func:`attach_output` did, if it has been called."""
    return _ATTACHED


@contextlib.contextmanager
def detached() -> Iterator[None]:
    """Run a block with no streams at all, the way Explorer starts a build.

    This is not test scaffolding, or not only: `slap verify` uses it to
    launch the web server the way a double-click does, which is the check
    that would have caught the crash this module exists to prevent. The
    verifier had been driving uvicorn from a process that always had a
    console, and so proved the one thing that was never in doubt.
    """
    global _ATTACHED

    names = ("stdout", "stderr", "stdin", "__stdout__", "__stderr__", "__stdin__")
    saved = {name: getattr(sys, name, None) for name in names}
    was_attached, _ATTACHED = _ATTACHED, None
    try:
        for name in names:
            setattr(sys, name, None)
        yield
    finally:
        for name, value in saved.items():
            setattr(sys, name, value)
        if _ATTACHED is not None:
            _ATTACHED.close()
        _ATTACHED = was_attached
