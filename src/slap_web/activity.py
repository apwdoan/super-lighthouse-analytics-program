"""Running audits from the UI, and streaming progress to the browser.

This module is what replaces ``slap_gui/bridge.py``, and it is worth saying
what that file had to do that this one does not. In Qt, an event produced on
the worker thread had to cross into the GUI thread through a thread-safe
queue drained on a QTimer, and every bug in the project's history lived in
that crossing: QRunnable signals garbage-collected mid-emit, tasks outliving
the window, a thread pool that had to be waited on at close.

Here, ``BatchWorker`` already runs on its own thread with its own event
loop. The browser holds an ``EventSource``. The only thing needed between
them is a buffer that the HTTP handler can read from. There is no second
UI thread to marshal into, because the UI is in another process.

One live batch at a time, deliberately. Lighthouse concurrency is capped at
3 or 4 because contended CPU inflates blocking time and yields plausible,
irreproducible scores; letting an operator start a second batch from another
tab would quietly defeat that cap.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterator

from slap import core
from slap.config import Settings
from slap.events import (
    BatchFinished, BatchStarted, CollectorFinished, CollectorStarted, Event,
    SiteFinished, SiteStarted,
)

#: How much scrollback the dock keeps. A 100-site batch with Lighthouse
#: produces thousands of events; nobody reads past the last screenful, and
#: an unbounded list in a long-lived process is a leak.
LOG_LIMIT = 400


@dataclass(slots=True)
class SiteProgress:
    url: str
    state: str = "queued"        # queued | running | done | failed
    stage: str = ""
    findings: int = 0
    observations: int = 0
    error: str = ""


@dataclass
class Activity:
    """The state of the current batch, in a form the templates can render."""

    batch_id: str = ""
    running: bool = False
    sites: dict[str, SiteProgress] = field(default_factory=dict)
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LIMIT))
    _stages: dict[str, set[str]] = field(default_factory=dict)

    @property
    def done(self) -> int:
        return sum(1 for s in self.sites.values() if s.state in ("done", "failed"))

    @property
    def total(self) -> int:
        return len(self.sites)

    def snapshot(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "batch_id": self.batch_id,
            "done": self.done,
            "total": self.total,
            "sites": [
                {"url": s.url, "state": s.state, "stage": s.stage,
                 "findings": s.findings, "observations": s.observations,
                 "error": s.error}
                for s in self.sites.values()
            ],
            "log": list(self.log)[-12:],
        }


class ActivityManager:
    """Owns the one live batch and fans its events out to browser clients."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._worker: core.BatchWorker | None = None
        self._activity = Activity()
        # One Condition, not one queue per client: a client that closes its
        # tab mid-batch must not leave a queue filling forever behind it.
        self._version = 0
        self._changed = threading.Condition(self._lock)

    # -- reading -----------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._activity.snapshot()

    def stream(self, timeout: float = 25.0) -> Iterator[str]:
        """Server-sent events. Yields on change, and heartbeats otherwise.

        The heartbeat is not decoration: proxies and browsers drop an idle
        connection, and a Lighthouse run is 30 to 40 seconds of silence.
        """
        seen = -1
        while True:
            with self._changed:
                if self._version == seen:
                    self._changed.wait(timeout)
                changed = self._version != seen
                seen = self._version
                payload = self._activity.snapshot() if changed else None
            if payload is None:
                yield ": heartbeat\n\n"
            else:
                yield f"data: {json.dumps(payload)}\n\n"
                if not payload["running"] and payload["total"]:
                    return

    # -- writing -----------------------------------------------------------

    def _touch(self) -> None:
        with self._changed:
            self._version += 1
            self._changed.notify_all()

    def _on_event(self, event: Event) -> None:
        """Called on the worker's thread. Mutates under the lock, then wakes."""
        with self._lock:
            activity = self._activity
            if isinstance(event, BatchStarted):
                activity.batch_id = event.batch_id
            elif isinstance(event, SiteStarted):
                site = activity.sites.setdefault(event.url, SiteProgress(event.url))
                site.state, site.stage = "running", "starting"
                activity._stages[event.url] = set()
            elif isinstance(event, CollectorStarted):
                stages = activity._stages.setdefault(event.url, set())
                stages.add(event.collector)
                site = activity.sites.get(event.url)
                if site:
                    # In-flight collectors, not the last finished one. Showing
                    # the last FINISHED collector made a site sitting in a
                    # 90-second Lighthouse run display "crux" the whole time.
                    site.stage = ", ".join(sorted(stages))
            elif isinstance(event, CollectorFinished):
                stages = activity._stages.setdefault(event.url, set())
                stages.discard(event.collector)
                site = activity.sites.get(event.url)
                if site:
                    site.stage = ", ".join(sorted(stages)) or "finishing"
            elif isinstance(event, SiteFinished):
                site = activity.sites.setdefault(event.url, SiteProgress(event.url))
                site.state = "done" if event.ok else "failed"
                site.stage = ""
                site.findings = getattr(event, "findings", 0) or 0
                site.observations = getattr(event, "observations", 0) or 0
                site.error = "" if event.ok else (getattr(event, "error", "") or "failed")
            elif isinstance(event, BatchFinished):
                activity.running = False
            activity.log.append(event.message)
        self._touch()

    def start(self, urls: list[str]) -> tuple[bool, str]:
        """Begin a batch. Returns (started, message).

        Refuses while one is live rather than queueing behind it: two
        batches means two sets of Lighthouse workers and the concurrency
        cap stops meaning anything.
        """
        with self._lock:
            if self._activity.running:
                return False, "A batch is already running."
        targets = core.prepare_urls(urls)
        if not targets:
            return False, "No usable URLs after normalization."

        activity = Activity(running=True)
        for url in targets:
            activity.sites[url] = SiteProgress(url)
        with self._lock:
            self._activity = activity

        worker = core.BatchWorker(targets, self._settings)
        worker.bus.subscribe(self._on_event)
        self._worker = worker
        worker.start()
        self._touch()
        return True, f"Auditing {len(targets)} site(s)."

    def cancel(self) -> None:
        """Cooperative: in-flight sites finish, every run row lands terminal."""
        if self._worker is not None:
            self._worker.cancel()
        self._touch()
