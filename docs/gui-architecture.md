# SALP GUI architecture (PySide6)

*Decided 2026-07-31, built the same day. Sections 1 to 9 are the design as
decided; section 10 records what building it actually surfaced.*

The core is Qt-free and stays that way. Every decision that is expensive to
reverse is here, and `src/salp_gui/` implements it.

---

## 1. The decision, and what it cost

**Chosen: PySide6 (Qt for Python).** Audience is Austin plus a few
teammates running it on their own machines, so a packaged desktop app that
does not require a Python install is worth real money.

Recorded honestly, the alternative considered was a local web UI
(FastAPI + HTMX, or NiceGUI). It was rejected in favour of native
packaging, and these are the two costs that buys:

1. **The presentation layer exists twice.** The client-facing report is
   Jinja2 → HTML. Every results screen in Qt is a second rendering of the
   same observations, in a different technology. Keep them honest by having
   both read the same `core.get_run_detail()` payload, and resist letting
   the Qt view compute anything the report does not.
2. **Showing the report needs a browser.** See §7 for how to avoid paying
   the 150MB QtWebEngine tax on day one.

Nothing about the core forecloses the other path. Everything the GUI needs
is in `salp.core`, so a web front-end could be added later without touching
a collector.

---

## 2. Threading model

**One background thread, owning its own asyncio event loop. Qt's loop is
never involved in collection.**

```
Qt main thread                      salp-batch thread
--------------                      -----------------
QApplication event loop             asyncio event loop
  widgets, painting                   httpx, TLS, subprocesses
  QTimer (100ms) ──drains──►  QueueSink  ◄──emits── EventBus
  core.list_runs() reads              core.run_batch() writes
      │                                   │
      └──── SQLite (WAL) ─────────────────┘
         separate connection per thread
```

`core.BatchWorker` already implements this. The GUI never creates a thread
itself:

```python
worker = BatchWorker(urls, settings)
sink = worker.bus.queue_sink()
worker.start()
```

**Why not `qasync`** (running asyncio *on* the Qt loop): it is elegant and
it is the wrong trade here. Phase 2 adds a Node Lighthouse worker that
blocks for 25 to 40 seconds per run. Sharing one loop means any stall in
collection is a stall in painting. Two loops means a wedged Chrome process
degrades throughput and nothing else.

**Why not `QThread` with signals emitted from the worker**: to emit a Qt
signal the worker has to be a `QObject`, which drags Qt into `salp.core`
and destroys the property that makes the core testable without a display
server. The queue keeps that boundary intact.

> **Phase 2 note, correcting an earlier instinct.** `QProcess` is a genuinely
> nice API for driving the Node Lighthouse worker, and it is still the wrong
> choice here: the subprocess belongs to the core, and the core does not
> import Qt. Use `asyncio.create_subprocess_exec` instead.

---

## 3. The asyncio-to-Qt bridge

The entire bridge is about twenty lines. Write it once, in
`salp_gui/bridge.py`, and never think about threading again.

```python
from PySide6.QtCore import QObject, QTimer, Signal

from salp.events import (
    BatchFinished, BatchStarted, Event, SiteFinished, SiteStarted,
)


class BatchBridge(QObject):
    """Turns core events into Qt signals, on the main thread."""

    batch_started = Signal(int)             # total
    site_started = Signal(str, int, int)    # url, index, total
    site_finished = Signal(object)          # SiteFinished
    batch_finished = Signal(object)         # BatchFinished
    log = Signal(str)

    POLL_MS = 100

    def __init__(self, worker, parent=None):
        super().__init__(parent)
        self._worker = worker
        self._sink = worker.bus.queue_sink()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._drain)

    def start(self):
        self._worker.start()
        self._timer.start(self.POLL_MS)

    def cancel(self):
        self._worker.cancel()          # safe from this thread

    def _drain(self):
        for event in self._sink.drain(limit=200):
            self._dispatch(event)
        if self._worker.finished:
            self._timer.stop()

    def _dispatch(self, event: Event):
        self.log.emit(event.message)
        if isinstance(event, BatchStarted):
            self.batch_started.emit(event.total)
        elif isinstance(event, SiteStarted):
            self.site_started.emit(event.url, event.index, event.total)
        elif isinstance(event, SiteFinished):
            self.site_finished.emit(event)
        elif isinstance(event, BatchFinished):
            self.batch_finished.emit(event)
```

Three details that matter:

- **`drain(limit=200)`** is bounded on purpose. A 100-site batch emits
  hundreds of events; draining without a cap lets one timer tick block
  painting.
- **Stop the timer when the worker finishes**, not when `BatchFinished`
  arrives. The event may still be sitting in the queue.
- **100ms is right.** Faster wastes cycles on an empty queue; slower makes
  the log pane feel laggy.

---

## 4. SQLite concurrency

Already handled in `salp.db`, but the rules the GUI must not break:

| Rule | Why |
|---|---|
| Never share a connection across threads | `sqlite3` connections are thread-affine. `db.connect()` keeps a thread-local handle, so just call it again rather than passing one around. |
| WAL is on; leave it on | It is what lets the GUI read while the worker writes. Turning it off reintroduces `database is locked` mid-batch. |
| GUI reads go through `salp.core` | `core.list_runs()`, `core.get_run_detail()`. No SQL in view code, and no `QSqlTableModel`, which would put SQL in the view layer. |
| Call `core.close_connections()` in `closeEvent` | Releases the main thread's handle cleanly. |

This is not theoretical. The first version of `core.run_batch` wrapped the
write in `asyncio.to_thread`, which handed the connection to a different
thread; `test_batch_worker_runs_on_its_own_thread_and_persists` caught it
immediately. Keep that test.

**If a read ever gets slow** on a large history, move it to
`QThreadPool` + `QRunnable` rather than blocking paint. Today the queries
are indexed and return in single-digit milliseconds, so do not
pre-optimise.

---

## 5. Cancellation

`worker.cancel()` is safe to call from the Qt main thread; the token is a
`threading.Event` checked between sites and between pipeline stages.

The one thing to get right is the **copy on the Stop button**. Cancellation
is cooperative: in-flight HTTP requests finish, and with Phase 2 an
in-flight Lighthouse run finishes too, which can take 40 seconds. So:

```python
def on_stop(self):
    self.stop_button.setEnabled(False)
    self.stop_button.setText("Finishing in-flight sites...")
    self.bridge.cancel()
```

A Stop button that appears to do nothing for 40 seconds reads as a hang.
Say what is happening.

---

## 6. Screens

| Screen | Widget | Core call |
|---|---|---|
| **Composer** | `QPlainTextEdit` for pasted URLs, plus client/label fields | `core.prepare_urls()` live, to show the normalized list before running |
| **Monitor** | `QTableView` (one row per site) + `QProgressBar` + log pane | `BatchBridge` signals |
| **History** | batches table → runs table | `core.list_batches()`, `core.list_runs()` |
| **Detail** | findings list, severity-coloured; observations table | `core.get_run_detail()` |
| **Report** | see §7 | Phase 3 |
| **Settings** | CrUX key, concurrency, DB path, rules file | `Settings` |

Show `core.prepare_urls()` output in the composer *before* the run starts.
Pasting 60 lines from a spreadsheet and discovering afterwards that 12 were
duplicates is a bad first experience, and the function is already there.

### Models

Wrap the `list[dict]` the core returns in a `QAbstractTableModel`. The one
performance trap over a 100-minute batch:

```python
def update_site(self, row: int, outcome):
    self._rows[row] = outcome
    top = self.index(row, 0)
    bottom = self.index(row, self.columnCount() - 1)
    self.dataChanged.emit(top, bottom)     # NOT layoutChanged / modelReset
```

`layoutChanged` or `beginResetModel` on every event will flicker the table
and drop the user's selection and scroll position hundreds of times during
a long batch.

---

## 7. Showing the report

The report pipeline is built; see `docs/reports.md`. The GUI's job is only
to call it and show the result.

**Exporting.** `core.export_report()` is synchronous and raises if called
from a thread with a running event loop, so run it on `QThreadPool`:

```python
class ExportTask(QRunnable):
    def __init__(self, settings, run_id, signals):
        super().__init__()
        self.settings, self.run_id, self.signals = settings, run_id, signals

    def run(self):
        try:
            result = core.export_report(self.settings, self.run_id, pdf=True)
        except Exception as exc:
            self.signals.failed.emit(str(exc))
            return
        self.signals.done.emit(result)     # ExportResult
```

`ExportResult.pdf_error` is set (rather than raised) when the PDF backend
is missing, and the HTML is written regardless. Show that message; do not
treat it as a failed export.

**Settings screen.** Call `core.pdf_backend_status()` and render it. It
probes for Playwright and its Chromium without launching a browser, so a
teammate who skipped `playwright install chromium` finds out in
preferences rather than when they click Export in front of a client.

**Viewing.** Two ways:

**Start here: the system browser.** Render to a temp file and open it.

```python
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl

QDesktopServices.openUrl(QUrl.fromLocalFile(str(report_path)))
```

Zero extra dependency, zero packaging weight, and the user gets Ctrl+P and
their own bookmarks for free.

**Only if an embedded preview earns it: `QWebEngineView`.** It adds roughly
150MB to the installer and meaningfully complicates PyInstaller. Given the
report is a file the user sends to a client, they will usually want it in a
real browser anyway. Defer this until someone asks for it.

PDF export goes through Chromium's print-to-PDF in the core (Chromium is
already a Lighthouse dependency), not through Qt.

---

## 8. Packaging for teammates

- **PyInstaller, one-dir, not one-file.** One-file unpacks to a temp
  directory on every launch, which is slow and reliably trips Windows
  antivirus heuristics.
- **Ship the rules file as data**, and point `Settings.rules_path` at a
  writable copy. The whole reason rules are YAML is that they get tuned;
  burying them read-only inside the bundle defeats that.
- **Per-user database.** `Settings.db_path` already defaults under
  `%LOCALAPPDATA%\salp` on Windows. Never write beside the executable.
- **CrUX key via `CRUX_API_KEY`**, not a committed config file, so
  teammates use their own quota.
- **Licensing:** PySide6 is LGPL. Dynamically linked and unmodified, which
  is what PyInstaller produces, is fine for internal tooling. Worth a real
  look only if SALP is ever sold as a closed product.

---

## 9. Things not to do

- **Do not import PySide6 anywhere under `src/salp/`.** The GUI lives in a
  separate `salp_gui` package that depends on `salp`, never the reverse.
  This is the property that keeps the core testable headlessly and keeps
  the web-UI escape hatch open.
- **Do not put orchestration in a widget.** If a button handler needs
  something `salp.core` cannot express, add it to the core. Two divergent
  ways to run a batch is the failure mode this layering exists to prevent.
- **Do not let the GUI write SQL.** Add a read function to `core` instead.
- **Do not run collection on the Qt loop**, even "just for one quick
  request". That is how the first freeze gets shipped.
- **Do not widen Lighthouse concurrency from the GUI** when Phase 2 lands.
  The roadmap's warning holds: contended CPU inflates TBT and TTI and
  produces plausible, irreproducible numbers. If a concurrency spinbox
  exists at all, cap it at 4 and label why.


---

## 10. What building it surfaced

The plan above held. Five things it did not anticipate, all found by
running the app offscreen and looking at the result rather than by reading
the code.

### QRunnable signals get garbage-collected mid-emit

The failure is silent and confusing: the worker thread dies with
`RuntimeError: Signal source has been deleted` and the UI simply never
updates. A page does `task = ExportTask(...); run_task(task)` and returns;
the local goes out of scope, Python collects the task, and with it the
`_TaskSignals` QObject the thread is about to emit from.

`bridge.run_task()` now holds a strong reference in a module-level set
until one of the task's signals fires, and calls `setAutoDelete(False)` so
Qt does not delete the C++ object while a queued signal is still travelling
to the main thread. Both halves are needed.

### Background tasks outlive the window

Closing while an export or the backend probe is running tears down the
objects those threads are about to emit from. `closeEvent` now waits on
`QThreadPool.waitForDone()` before releasing anything.

### The progress table needed a new event, not a new widget

The design said "progress UI should reflect the stage a site is in". The
event vocabulary only had `CollectorFinished`, so the Stage column showed
the *last completed* collector, which meant a site sitting in a 90-second
Lighthouse run displayed `crux` the whole time.

The fix belonged in the core, not the GUI: `CollectorStarted` was added to
`salp.events`, and the model now tracks the set of in-flight collectors
(a stage runs several concurrently, so it is a set, not a name). This is
what the "if a front-end needs something the core cannot express, the core
is missing a function" rule looks like in practice.

### Qt table sizing needs the stretch column named

`stretch_table()` defaulted to stretching column 0. On the findings table
column 0 is the narrow Severity badge, so it swallowed the width and every
finding title was truncated mid-sentence. It takes a `stretch_column`
argument now, and each caller names the column worth reading.

A related trap: `header.setMinimumSectionSize()` is **global, not
per-column**. Using it to protect one column forces a horizontal scrollbar
on every narrow one. Size the fixed-width column to its contents and
stretch a flexible one instead.

### A stylesheet `color` on QWidget silently kills every disabled state

The worst bug in the GUI so far, reported as "'Also measure desktop' is not
selectable". The checkbox was behaving exactly as designed: disabled until
"Also run Lighthouse" is ticked. The problem was that it did not *look*
disabled.

`QWidget { color: ... }` at the top of the stylesheet overrides Qt's
palette for **every** colour role, including Disabled. Measured on the
rendered pixels, a disabled checkbox's label and an enabled one differed by
**0.0 of 255** in mean lightness. Identical. So the control looked
perfectly live and silently ignored clicks, which reads as a broken app
rather than as a dependency.

Two fixes, and both are needed:

1. **Explicit `:disabled` rules** in `theme.py`. Note that ID selectors
   (`QLabel#Caption`) outrank a plain `QLabel:disabled`, so anything with an
   explicit colour needs its own disabled rule or the hint text stays at
   full strength beside a greyed control. The rule of thumb: if you add a
   `color` to this stylesheet, add its `:disabled` in the same edit.
2. **Make the dependency structural.** The Lighthouse options now live in a
   *checkable* `QGroupBox` rather than being loose siblings of a plain
   checkbox. Qt disables the children itself, and the bordered group with a
   ticked title makes "these belong to that" unmistakable even before
   colour is considered.

`test_disabled_controls_are_visibly_different_from_enabled_ones` renders
both states offscreen and asserts a lightness gap. It is the only test in
the suite that would have caught this, because nothing about the widget
tree was wrong: `isEnabled()` returned the right answer the whole time.

The general lesson: **a headless test that asks the widget how it feels
cannot catch a bug about how the widget looks.** Render it and measure.

## 11. What the GUI is not

- **No embedded report view.** `QDesktopServices.openUrl()` opens the PDF or
  HTML with the system handler. `QWebEngineView` would add ~150MB and
  complicate PyInstaller for something the user usually wants in a real
  browser anyway.
- **No settings persistence yet.** Path changes apply to the session;
  writing them back to `config.toml` is a small addition when someone wants it.
- **No trend or comparison views.** That is Phase 4, and the immutable-run
  design already makes it cheap.

## 12. Packaging, unchanged from section 8

PyInstaller one-dir, rules file shipped writable, per-user database, CrUX
key from the environment. The one addition: `salp-gui` is registered as a
`gui-script` entry point, so on Windows it launches without a console
window.
