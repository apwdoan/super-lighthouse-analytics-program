"""Progress events: the seam between the core and any front-end.

This module deliberately imports nothing from Qt, asyncio, or the CLI.
The core emits plain dataclasses; front-ends decide what to do with them.

Two consumption styles are supported, because the CLI and the GUI want
opposite things:

* **Callback** (``bus.subscribe(fn)``): the CLI wants to print the moment
  something happens, on whatever thread produced it.
* **Queue** (``bus.queue_sink()``): Qt must not touch widgets from a
  worker thread. The GUI attaches a :class:`QueueSink`, then drains it
  from the main thread on a ``QTimer`` tick and converts each event into
  a Qt signal. That is the whole asyncio-to-Qt bridge; no qasync needed.

Sketch of the Qt side, for when Phase 2 starts::

    class Bridge(QObject):
        progress = Signal(object)

        def __init__(self, sink):
            super().__init__()
            self._sink = sink
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._drain)
            self._timer.start(100)

        def _drain(self):
            for event in self._sink.drain():
                self.progress.emit(event)
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class Event:
    """Base class. Every event carries a batch id and a timestamp."""

    batch_id: str
    at: datetime = field(default_factory=_now, compare=False)

    @property
    def message(self) -> str:
        return type(self).__name__


@dataclass(frozen=True, slots=True)
class BatchStarted(Event):
    total: int = 0

    @property
    def message(self) -> str:
        return f"Batch started: {self.total} site(s)"


@dataclass(frozen=True, slots=True)
class SiteStarted(Event):
    url: str = ""
    index: int = 0
    total: int = 0

    @property
    def message(self) -> str:
        return f"[{self.index}/{self.total}] {self.url}"


@dataclass(frozen=True, slots=True)
class CollectorStarted(Event):
    """A collector began work on a page.

    Exists so a progress UI can show what a site is *doing* rather than what
    it last finished. Without it, a site sitting in a 90-second Lighthouse
    run displays the name of whichever collector completed before it.
    """

    url: str = ""
    collector: str = ""

    @property
    def message(self) -> str:
        return f"    {self.collector}: started"


@dataclass(frozen=True, slots=True)
class CollectorFinished(Event):
    url: str = ""
    collector: str = ""
    observations: int = 0
    ok: bool = True
    error: str | None = None

    @property
    def message(self) -> str:
        if not self.ok:
            return f"    {self.collector}: failed ({self.error})"
        return f"    {self.collector}: {self.observations} observation(s)"


@dataclass(frozen=True, slots=True)
class SiteFinished(Event):
    url: str = ""
    run_id: int = 0
    index: int = 0
    total: int = 0
    observations: int = 0
    findings: int = 0
    ok: bool = True
    error: str | None = None

    @property
    def message(self) -> str:
        if not self.ok:
            return f"[{self.index}/{self.total}] {self.url} FAILED: {self.error}"
        return (f"[{self.index}/{self.total}] {self.url} done "
                f"({self.observations} obs, {self.findings} findings)")


@dataclass(frozen=True, slots=True)
class BatchFinished(Event):
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    cancelled: bool = False

    @property
    def message(self) -> str:
        verb = "cancelled" if self.cancelled else "finished"
        return f"Batch {verb}: {self.succeeded} ok, {self.failed} failed"


@dataclass(frozen=True, slots=True)
class LogMessage(Event):
    text: str = ""
    level: str = "info"

    @property
    def message(self) -> str:
        return self.text


class QueueSink:
    """Thread-safe buffer a front-end polls from its own thread."""

    def __init__(self, maxsize: int = 0) -> None:
        self._q: queue.Queue[Event] = queue.Queue(maxsize=maxsize)

    def __call__(self, event: Event) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:  # pragma: no cover - only with a bounded sink
            pass

    def drain(self, limit: int = 500) -> Iterator[Event]:
        """Yield up to ``limit`` buffered events. Never blocks."""
        for _ in range(limit):
            try:
                yield self._q.get_nowait()
            except queue.Empty:
                return

    def __len__(self) -> int:
        return self._q.qsize()


class EventBus:
    """Fan-out for progress events. Safe to emit from any thread."""

    def __init__(self) -> None:
        self._sinks: list[Callable[[Event], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, sink: Callable[[Event], None]) -> Callable[[], None]:
        with self._lock:
            self._sinks.append(sink)

        def unsubscribe() -> None:
            with self._lock:
                if sink in self._sinks:
                    self._sinks.remove(sink)

        return unsubscribe

    def queue_sink(self, maxsize: int = 0) -> QueueSink:
        sink = QueueSink(maxsize)
        self.subscribe(sink)
        return sink

    def emit(self, event: Event) -> None:
        with self._lock:
            sinks = list(self._sinks)
        for sink in sinks:
            try:
                sink(event)
            except Exception:  # a broken front-end must not kill a batch
                pass

    def log(self, batch_id: str, text: str, level: str = "info") -> None:
        self.emit(LogMessage(batch_id=batch_id, text=text, level=level))


class CancelToken:
    """Cooperative cancellation the GUI's Stop button sets.

    Checked between sites and between collectors, so a cancelled batch
    leaves every run row in a coherent terminal state instead of a
    half-written one.
    """

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise BatchCancelled()


class BatchCancelled(Exception):
    """Raised internally when a cancel token trips."""


__all__ = [
    "Event", "BatchStarted", "SiteStarted", "CollectorStarted",
    "CollectorFinished", "SiteFinished",
    "BatchFinished", "LogMessage", "EventBus", "QueueSink", "CancelToken",
    "BatchCancelled",
]


def describe(event: Any) -> str:
    """Human-readable one-liner. Used by the CLI and the GUI log pane."""
    return getattr(event, "message", str(event))
