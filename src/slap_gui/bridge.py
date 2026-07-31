"""The asyncio-to-Qt seam. Every threading bug in this app lives here.

The contract, per ``docs/gui-architecture.md``:

* :class:`slap.core.BatchWorker` owns a background thread with its own
  asyncio event loop. Qt's loop is never involved in collection, so a
  40-second Lighthouse run cannot stall painting.
* The worker emits plain dataclasses onto a thread-safe queue. This module
  drains that queue **on the main thread** from a ``QTimer`` and re-emits
  them as Qt signals. That is the whole bridge; no ``qasync``.
* Nothing under ``slap/`` imports Qt. The dependency points one way:
  ``slap_gui`` -> ``slap.core`` -> everything else.

Why not ``QThread`` with signals emitted from the worker: to emit a Qt
signal the worker must be a ``QObject``, which drags Qt into ``slap.core``
and destroys the property that makes the core testable without a display.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal

from slap import core
from slap.config import Settings
from slap.events import (
    BatchFinished,
    BatchStarted,
    CollectorFinished,
    CollectorStarted,
    Event,
    LogMessage,
    SiteFinished,
    SiteStarted,
)


class BatchBridge(QObject):
    """Turns core progress events into Qt signals, on the main thread."""

    batch_started = Signal(int)            # total sites
    site_started = Signal(str, int, int)   # url, index, total
    collector_started = Signal(str, str)      # url, collector
    collector_done = Signal(str, str, bool)   # url, collector, ok
    site_finished = Signal(object)         # SiteFinished
    batch_finished = Signal(object)        # BatchFinished
    log = Signal(str, str)                 # text, level
    stopped = Signal()                     # worker thread has exited

    #: Fast enough that the log feels live, slow enough not to burn cycles
    #: on an empty queue.
    POLL_MS = 100
    #: Bounded on purpose. A 100-site batch emits thousands of events;
    #: draining without a cap lets one timer tick block painting.
    DRAIN_LIMIT = 200

    def __init__(self, worker: core.BatchWorker, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._worker = worker
        self._sink = worker.bus.queue_sink()
        self._timer = QTimer(self)
        self._timer.setInterval(self.POLL_MS)
        self._timer.timeout.connect(self._drain)

    @property
    def batch_id(self) -> str:
        return self._worker.batch_id

    @property
    def finished(self) -> bool:
        return self._worker.finished

    def start(self) -> None:
        self._worker.start()
        self._timer.start()

    def cancel(self) -> None:
        """Request cancellation. Safe to call from the Qt main thread.

        Cooperative: in-flight sites finish first, and with Lighthouse
        enabled that can take 40 seconds. Callers must say so in the UI.
        """
        self._worker.cancel()

    def result(self) -> core.BatchResult | None:
        if not self._worker.finished:
            return None
        try:
            return self._worker.result()
        except BaseException as exc:  # noqa: BLE001 - surfaced as a log line
            self.log.emit(f"Batch failed: {exc}", "error")
            return None

    def _drain(self) -> None:
        for event in self._sink.drain(limit=self.DRAIN_LIMIT):
            self._dispatch(event)
        # Stop on the WORKER's state, not on seeing BatchFinished: that
        # event may still be sitting in the queue behind others.
        if self._worker.finished:
            self._timer.stop()
            # One last pass, or the tail of the queue is silently dropped.
            for event in self._sink.drain(limit=self.DRAIN_LIMIT):
                self._dispatch(event)
            self.stopped.emit()

    def _dispatch(self, event: Event) -> None:
        if isinstance(event, BatchStarted):
            self.batch_started.emit(event.total)
            self.log.emit(event.message, "info")
        elif isinstance(event, SiteStarted):
            self.site_started.emit(event.url, event.index, event.total)
        elif isinstance(event, CollectorStarted):
            self.collector_started.emit(event.url, event.collector)
        elif isinstance(event, CollectorFinished):
            self.collector_done.emit(event.url, event.collector, event.ok)
            if not event.ok:
                self.log.emit(event.message, "warning")
        elif isinstance(event, SiteFinished):
            self.site_finished.emit(event)
            self.log.emit(event.message, "info" if event.ok else "error")
        elif isinstance(event, BatchFinished):
            self.batch_finished.emit(event)
            self.log.emit(event.message, "info")
        elif isinstance(event, LogMessage):
            self.log.emit(event.text, event.level)


# --------------------------------------------------------------------------
# Background one-shots
#
# QRunnable is not a QObject and cannot carry signals, so each task pairs
# with a small signals object. These exist because both jobs below take
# seconds and would otherwise freeze the window.
# --------------------------------------------------------------------------

class _TaskSignals(QObject):
    done = Signal(object)
    failed = Signal(str)


class ExportTask(QRunnable):
    """Render a report off the main thread.

    ``core.export_report`` is synchronous and raises if called from a thread
    that already has a running event loop, so a plain ``QThreadPool`` thread
    is exactly right. ``ExportResult.pdf_error`` is set rather than raised
    when the PDF backend is missing, and the HTML is written regardless:
    that is a partial success, not a failure.
    """

    def __init__(self, settings: Settings, run_id: int, *,
                 pdf: bool = True, out_dir: Path | None = None) -> None:
        super().__init__()
        self.signals = _TaskSignals()
        self._settings = settings
        self._run_id = run_id
        self._pdf = pdf
        self._out_dir = out_dir

    def run(self) -> None:  # noqa: D102 - QRunnable entry point
        try:
            result = core.export_report(
                self._settings, self._run_id, pdf=self._pdf, out_dir=self._out_dir
            )
        except Exception as exc:  # noqa: BLE001
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.signals.done.emit(result)


class BatchExportTask(QRunnable):
    """Render every report in a batch, plus the index."""

    def __init__(self, settings: Settings, batch_id: str, *,
                 pdf: bool = True, merge: bool = False,
                 out_dir: Path | None = None) -> None:
        super().__init__()
        self.signals = _TaskSignals()
        self._settings = settings
        self._batch_id = batch_id
        self._pdf = pdf
        self._merge = merge
        self._out_dir = out_dir

    def run(self) -> None:  # noqa: D102
        try:
            result = core.export_batch_report(
                self._settings, self._batch_id, pdf=self._pdf,
                merge=self._merge, out_dir=self._out_dir,
            )
        except Exception as exc:  # noqa: BLE001
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.signals.done.emit(result)


class DoctorTask(QRunnable):
    """Probe every optional backend for the settings screen.

    Launches Chrome to read its version, so it takes a couple of seconds.
    Running it inline is what makes a settings dialog feel broken.
    """

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.signals = _TaskSignals()
        self._settings = settings

    def run(self) -> None:  # noqa: D102
        import asyncio

        from slap.collectors.lighthouse import LighthouseRunner, default_chrome_path

        report: dict[str, Any] = {}

        key = self._settings.collector.crux_api_key
        report["crux"] = (
            bool(key),
            "Real-user field data available."
            if key else
            "No CRUX_API_KEY set, so reports rely on lab data only. The key is "
            "free (150 queries/min): developer.chrome.com/docs/crux/api",
        )

        runner = LighthouseRunner(self._settings.lighthouse)
        ok, detail = runner.check()
        if ok:
            try:
                versions = asyncio.run(runner.probe())
                detail = (f"Lighthouse {versions.get('lighthouseVersion')} on "
                          f"Chrome {versions.get('chromeVersion')}, "
                          f"Node {versions.get('node')}")
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, str(exc)
        report["lighthouse"] = (ok, detail)

        chrome = default_chrome_path()
        report["chrome"] = (
            bool(chrome),
            chrome or "No Chromium found. Run: playwright install chromium",
        )

        status = core.pdf_backend_status()
        report["pdf"] = (bool(status), status.detail)

        self.signals.done.emit(report)


#: Strong references to in-flight tasks. See run_task().
_ACTIVE_TASKS: set[QRunnable] = set()


def run_task(task: QRunnable) -> None:
    """Hand a task to the global pool, keeping it alive until it finishes.

    Both halves of this matter and both are easy to get wrong:

    * **The caller's local reference is not enough.** A page does
      ``task = ExportTask(...); run_task(task)`` and returns; the local goes
      out of scope, Python collects the task, and with it the ``_TaskSignals``
      QObject the worker thread is about to emit from. The thread then dies
      with "Signal source has been deleted" and the UI simply never updates.
    * **``setAutoDelete(False)``** stops Qt deleting the C++ QRunnable the
      moment ``run()`` returns, which can invalidate the Python wrapper while
      a queued signal is still in flight to the main thread.

    So the task is held here until one of its signals reports it is done.
    """
    task.setAutoDelete(False)
    _ACTIVE_TASKS.add(task)

    def _release(*_args: object) -> None:
        _ACTIVE_TASKS.discard(task)

    signals = getattr(task, "signals", None)
    if signals is not None:
        signals.done.connect(_release)
        signals.failed.connect(_release)

    QThreadPool.globalInstance().start(task)
