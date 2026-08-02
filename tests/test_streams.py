"""A process with no stdout, which is every double-click of the bundle.

The bug these cover shipped: `SLAP.exe`, launched from Explorer, died before
running a line of SLAP's own code, with

    AttributeError: 'NoneType' object has no attribute 'isatty'
    ValueError: Unable to configure formatter 'default'

uvicorn builds its log formatters while constructing a ``Config``, and one of
them asks ``sys.stdout.isatty()``. A build made with ``console=False`` and
started from Explorer has no ``sys.stdout`` to ask.

Nothing caught it because everything that had ever started the executable --
CI, `slap verify`, every manual run -- started it from a shell, and on Windows
a GUI-subsystem process inherits its parent console's handles. The one launch
nobody automated was the one every user performs.
"""

from __future__ import annotations

import io
import sys

import pytest

from slap import streams
from slap.streams import (
    MAX_LOG_BYTES,
    attach_output,
    default_log_path,
    detached,
    usable,
)


@pytest.fixture(autouse=True)
def _forget_attachment():
    """Each test starts with the module having attached nothing."""
    streams._ATTACHED = None
    yield
    if streams._ATTACHED is not None:
        streams._ATTACHED.close()
    streams._ATTACHED = None


# --------------------------------------------------------------------------
# What counts as a stream
# --------------------------------------------------------------------------

def test_a_real_stream_is_usable():
    assert usable(io.StringIO()) is True


def test_no_stream_is_not_usable():
    """The windowed build's actual state, and the whole cause."""
    assert usable(None) is False


def test_a_closed_stream_is_not_usable():
    stream = io.StringIO()
    stream.close()
    assert usable(stream) is False


def test_a_writer_with_no_isatty_is_not_usable():
    """Present but useless, which some frozen-app shims install and which
    fails in the exact place uvicorn did. `is not None` would have passed
    this and crashed anyway."""

    class Shim:
        def write(self, text):
            return len(text)

        def flush(self):
            pass

    assert usable(Shim()) is False


def test_a_stream_that_raises_on_write_is_not_usable():
    """An inherited-but-invalid Windows handle: writes raise OSError."""

    class BadHandle:
        def write(self, text):
            raise OSError(9, "Bad file descriptor")

        def flush(self):
            pass

        def isatty(self):
            return False

    assert usable(BadHandle()) is False


# --------------------------------------------------------------------------
# Attaching
# --------------------------------------------------------------------------

def test_a_console_is_left_alone(tmp_path):
    """A source checkout and a terminal run must pay nothing for this."""
    before = sys.stdout
    result = attach_output(tmp_path / "slap.log")
    assert result.attached is False
    assert sys.stdout is before
    assert not (tmp_path / "slap.log").exists()


def test_output_survives_having_no_streams(tmp_path):
    log = tmp_path / "slap.log"
    with detached():
        assert sys.stdout is None
        result = attach_output(log)
        assert result.attached is True
        assert result.path == log
        print("something the user would otherwise never see")
        print("and the traceback that explains it", file=sys.stderr)

    text = log.read_text(encoding="utf-8")
    assert "something the user would otherwise never see" in text
    assert "and the traceback that explains it" in text


def test_the_log_says_which_build_wrote_it(tmp_path):
    """A log file is only useful if it dates and versions what it holds."""
    from slap import __version__

    log = tmp_path / "slap.log"
    with detached():
        attach_output(log)
    header = log.read_text(encoding="utf-8")
    assert __version__ in header
    assert "started" in header


def test_a_second_launch_appends_rather_than_erasing(tmp_path):
    log = tmp_path / "slap.log"
    for message in ("first launch", "second launch"):
        with detached():
            attach_output(log)
            print(message)
    text = log.read_text(encoding="utf-8")
    assert "first launch" in text and "second launch" in text


def test_a_log_nobody_rotates_does_not_grow_forever(tmp_path):
    log = tmp_path / "slap.log"
    log.write_text("x" * (MAX_LOG_BYTES + 1), encoding="utf-8")
    with detached():
        attach_output(log)
        print("the launch that matters")
    text = log.read_text(encoding="utf-8")
    assert len(text) < MAX_LOG_BYTES
    assert "the launch that matters" in text


def test_a_log_that_cannot_be_opened_is_not_fatal(tmp_path):
    """This must never be the reason the app fails to start. Discarding the
    output is a bad day; refusing to launch because the log directory is
    read-only is a broken product."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")

    with detached():
        result = attach_output(blocker / "slap.log")
        assert result.attached is True
        assert result.path is None
        assert "discarded" in result.detail
        print("goes nowhere, raises nothing")     # must not raise
        assert usable(sys.stdout)


def test_stdin_is_replaced_too(tmp_path):
    """`subprocess` with no explicit stdin reaches for it, and a None there
    raises as readily as a None stdout."""
    with detached():
        attach_output(tmp_path / "slap.log")
        assert sys.stdin is not None
        assert sys.stdin.read() == ""


def test_the_dunder_streams_are_replaced_too(tmp_path):
    """`sys.__stderr__` is what a library reaches for when it wants the real
    stream rather than whatever redirected it. In a windowed build it is
    equally None."""
    with detached():
        attach_output(tmp_path / "slap.log")
        assert usable(sys.__stdout__)
        assert usable(sys.__stderr__)


def test_attaching_twice_reuses_one_log(tmp_path):
    """The entry point calls it, then the server calls it again. Two open
    handles on one file, on Windows, is how you get a locked file."""
    log = tmp_path / "slap.log"
    with detached():
        first = attach_output(log)
        second = attach_output(log)
        assert first is second
        assert first.stream is second.stream


def test_slap_log_overrides_where_it_lands(tmp_path, monkeypatch):
    """The only lever anyone has over a process that was double-clicked."""
    monkeypatch.setenv("SLAP_LOG", str(tmp_path / "elsewhere.log"))
    assert default_log_path() == tmp_path / "elsewhere.log"

    with detached():
        result = attach_output()
        assert result.path == tmp_path / "elsewhere.log"


def test_detached_restores_what_it_took(tmp_path):
    before = (sys.stdout, sys.stderr, sys.stdin, sys.__stdout__)
    with detached():
        attach_output(tmp_path / "slap.log")
    assert (sys.stdout, sys.stderr, sys.stdin, sys.__stdout__) == before


def test_detached_restores_even_when_the_block_raises(tmp_path):
    before = sys.stdout
    with pytest.raises(RuntimeError):
        with detached():
            raise RuntimeError("boom")
    assert sys.stdout is before


# --------------------------------------------------------------------------
# The crash itself
# --------------------------------------------------------------------------

def test_the_server_configures_with_no_console(tmp_path):
    """The regression. `make_config` is the launch path's own configuration,
    and constructing a uvicorn Config is where the formatters get built."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.server import make_config

    with detached():
        attach_output(tmp_path / "slap.log")
        config = make_config(lambda *args: None, 8123)
    assert config.port == 8123


def test_the_server_repairs_the_streams_itself(tmp_path, monkeypatch):
    """`make_config` must do the repair, not merely tolerate one somebody
    else did. `slap verify`'s headless check relies on exactly that: it takes
    the streams away and never gives them back, so a launch path that
    depended on being handed working streams would fail there."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.server import make_config

    monkeypatch.setenv("SLAP_LOG", str(tmp_path / "slap.log"))
    with detached():
        make_config(lambda *args: None, 8124)       # no attach_output here
        assert usable(sys.stdout)
    assert (tmp_path / "slap.log").is_file()


def test_without_the_repair_the_server_still_fails(tmp_path, monkeypatch):
    """Proof the guard has teeth. Neutralise the repair and the original
    crash comes straight back, which is what every user got."""
    pytest.importorskip("uvicorn", reason="web extra not installed")
    from slap_web.server import make_config

    monkeypatch.setattr(streams, "attach_output", lambda path=None: None)
    with detached():
        with pytest.raises(Exception) as caught:
            make_config(lambda *args: None, 8125)
    assert "formatter" in str(caught.value) or "isatty" in str(caught.value)
