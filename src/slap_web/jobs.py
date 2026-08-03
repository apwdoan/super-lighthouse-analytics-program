"""Long jobs the browser cannot wait on.

Exactly one so far: refreshing the vulnerability database. It belongs here
rather than in :mod:`activity` because that module owns the one live audit
and says so; two unrelated things sharing a progress channel is how a dock
ends up reporting an audit that is not running.

The shape is the same as `ActivityManager` for the same reason: a worker on
its own thread, a lock around the state, and a snapshot the HTTP handler
can read. There is no second UI thread to marshal into, because the UI is
in another process.
"""

from __future__ import annotations

import threading
from typing import Any

from slap import core
from slap.config import Settings


class DatabaseUpdate:
    """Rebuilding the vulnerability database, in the background.

    Not a synchronous form post, because of arithmetic: the NIST NVD allows
    5 requests per 30 seconds without an API key, and the database covers 28
    products, so a keyless refresh takes about five minutes. Every browser
    and proxy between here and the button would give up long before that,
    and the user would be left looking at a timeout while the refresh
    actually succeeded. With ``NVD_API_KEY`` set it is nearer forty seconds,
    which is still too long to hold a request open.

    One at a time, and the guards from the command-line version come with
    it: a product that fails after retries, or that suddenly returns nothing
    where the previous database had entries, aborts the write. A quietly
    smaller database is the same failure as a stale one, and every audit
    afterwards reports less while looking exactly as confident.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False
        self._line = ""
        self._done = 0
        self._total = 0
        self._result = ""
        self._error = ""
        self._source = "nvd"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "line": self._line,
                "done": self._done,
                "total": self._total,
                "result": self._result,
                "error": self._error,
            }

    def start(self, source: str = "nvd") -> tuple[bool, str]:
        """Returns (started, message)."""
        with self._lock:
            if self._running:
                return False, "An update is already running."
            self._source = "osv" if source == "osv" else "nvd"
            self._running = True
            self._result = self._error = ""
            self._done = 0
            self._line = "Starting..."
            from slap.vulndb import DEFAULT_NPM_PACKAGES, NVD_PRODUCTS

            self._total = len(NVD_PRODUCTS if self._source == "nvd"
                              else DEFAULT_NPM_PACKAGES)
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="slap-vulndb-update")
        self._thread.start()
        if self._source == "osv":
            return True, ("Updating from OSV.dev (npm only). You can keep "
                          "working; the page updates as it goes.")
        return True, ("Updating from the NIST NVD. This takes about five "
                      "minutes without an NVD_API_KEY, or under a minute "
                      "with one. You can keep working; the page updates "
                      "as it goes.")

    def _progress(self, index: int, package: str, message: str) -> None:
        with self._lock:
            self._done = index
            self._line = f"{package}: {message}"

    def _run(self) -> None:
        """Whatever happens, this thread must clear the running flag.

        The first version cleared it inside the success path and caught
        exceptions only around the update call itself, so anything that
        went wrong afterwards left the job "running" forever: the button
        stayed disabled, the page polled a job that had died, and the only
        cure was restarting the app. A background job that can get stuck
        pretending to work is worse than one that fails.
        """
        result: dict | None = None
        error = ""
        try:
            result = core.update_vulndb(self._settings, source=self._source,
                                        progress=self._progress)
        except Exception as exc:                       # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._running = False
                self._line = ""
                if error:
                    self._error = error
                elif isinstance(result, dict) and result.get("ok"):
                    self._result = str(result.get("message", "Updated."))
                elif isinstance(result, dict):
                    self._error = str(result.get("message")
                                      or "The update did not complete.")
                else:
                    # Total by construction. The version above this one
                    # reached for .get on whatever came back, which raised
                    # inside the finally block and skipped the error
                    # message: a job that had failed, said nothing, and
                    # left the page waiting.
                    self._error = "The update did not complete."
