"""GUI tests, headless.

Run with ``QT_QPA_PLATFORM=offscreen`` (the fixture sets it), so these need
no display server and are safe in CI. They skip cleanly if PySide6 is not
installed, since the GUI is an optional extra.

What is worth testing here is the seam, not the pixels: the threading
bridge, the model update discipline, and the handful of rules that are easy
to regress by "tidying up" (status words, capped concurrency, dependency
direction).
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="GUI extra not installed")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from salp.config import Settings  # noqa: E402
from salp.events import (  # noqa: E402
    BatchFinished,
    BatchStarted,
    CollectorFinished,
    CollectorStarted,
    EventBus,
    SiteFinished,
    SiteStarted,
)
from salp_gui import theme  # noqa: E402
from salp_gui.models import SiteProgressModel  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(theme.STYLESHEET)
    yield app


@pytest.fixture
def settings(tmp_path):
    from salp import db

    s = Settings(
        db_path=tmp_path / "salp.sqlite3",
        report_dir=tmp_path / "reports",
        artifact_dir=tmp_path / "artifacts",
    )
    s.ensure_dirs()
    yield s
    db.close_thread_connections()


# --------------------------------------------------------------------------
# Layering
# --------------------------------------------------------------------------

def test_nothing_under_salp_imports_qt():
    """The rule the whole salp_gui package exists to respect.

    If ``salp`` ever imports Qt, the core stops being testable without a
    display and the web-UI escape hatch closes.
    """
    import ast
    import pathlib

    import salp

    root = pathlib.Path(salp.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # Real imports only. Grepping for the string catches every
            # docstring that merely mentions the GUI.
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(n.split(".")[0] in {"PySide6", "PyQt5", "PyQt6"} for n in names):
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")
    assert offenders == [], f"Qt imported inside salp/: {offenders}"


def test_gui_reuses_the_report_status_vocabulary():
    """Operator view and client PDF must not drift on what 'High' means."""
    from salp.report.model import SEVERITY_STATUS

    assert theme.SEVERITY_STATUS is SEVERITY_STATUS
    assert theme.severity_status("high") == "serious"
    assert theme.severity_status("medium") == "warning"


# --------------------------------------------------------------------------
# Progress model
# --------------------------------------------------------------------------

def test_model_starts_every_site_queued(qapp):
    model = SiteProgressModel(["https://a.test", "https://b.test"])
    assert model.rowCount() == 2
    assert model.index(0, 1).data() == "Queued"
    assert model.counts() == (0, 0, 2)


def test_status_column_always_carries_a_word(qapp):
    """Colour never travels alone; two status hues sit below the CVD floor."""
    model = SiteProgressModel(["https://a.test"])
    for state in ("queued", "running", "done", "failed"):
        model._rows[0].state = state
        assert model.index(0, 1).data(), state
        assert model.index(0, 1).data(Qt.ItemDataRole.ForegroundRole) is not None


def test_stage_shows_what_is_in_flight_not_what_last_finished(qapp):
    """A site inside a 90-second Lighthouse run must say 'lighthouse'.

    Driving the stage column from CollectorFinished showed the name of
    whichever collector completed *before* the slow one.
    """
    model = SiteProgressModel(["https://a.test"])
    model.mark_started("https://a.test")
    model.mark_collector_started("https://a.test", "crux")
    model.mark_collector_done("https://a.test", "crux", True)
    model.mark_collector_started("https://a.test", "lighthouse")
    assert model.index(0, 2).data() == "lighthouse"


def test_stage_lists_concurrent_collectors(qapp):
    model = SiteProgressModel(["https://a.test"])
    model.mark_started("https://a.test")
    for name in ("tls", "crux", "fingerprint"):
        model.mark_collector_started("https://a.test", name)
    assert model.index(0, 2).data() == "crux, fingerprint, tls"


def test_updates_touch_only_the_changed_row(qapp):
    """No layoutChanged/reset: a long batch would flicker and lose selection."""
    model = SiteProgressModel(["https://a.test", "https://b.test"])
    seen: list[tuple[int, int]] = []
    resets: list[int] = []
    model.dataChanged.connect(lambda tl, br, *_: seen.append((tl.row(), br.row())))
    model.modelReset.connect(lambda: resets.append(1))
    model.layoutChanged.connect(lambda *_: resets.append(1))

    model.mark_started("https://b.test")
    assert seen == [(1, 1)]
    assert resets == []


def test_finished_site_records_its_run_and_counts(qapp):
    model = SiteProgressModel(["https://a.test"])
    model.mark_started("https://a.test")
    model.mark_finished(SiteFinished(
        batch_id="b", url="https://a.test", run_id=7, observations=23,
        findings=5, ok=True,
    ))
    assert model.index(0, 1).data() == "Done"
    assert model.index(0, 3).data() == "23"
    assert model.run_ids() == [7]
    assert model.counts() == (1, 0, 1)


def test_sites_that_never_ran_are_marked_not_left_queued(qapp):
    """After a cancel, a row still saying 'Queued' is a lie."""
    model = SiteProgressModel(["https://a.test", "https://b.test"])
    model.mark_finished(SiteFinished(batch_id="b", url="https://a.test", ok=True))
    model.mark_all_stopped()
    assert model.index(1, 1).data() == "Failed"
    assert "cancelled" in model._rows[1].error


# --------------------------------------------------------------------------
# The bridge
# --------------------------------------------------------------------------

class _FakeWorker:
    """Stands in for BatchWorker without starting a thread."""

    def __init__(self) -> None:
        self.bus = EventBus()
        self.batch_id = "test0001"
        self.finished = False
        self.cancelled = False

    def start(self) -> None:
        pass

    def cancel(self) -> None:
        self.cancelled = True


def test_bridge_translates_events_into_signals(qapp):
    from salp_gui.bridge import BatchBridge

    worker = _FakeWorker()
    bridge = BatchBridge(worker)
    seen: dict[str, list] = {"started": [], "site": [], "stage": [], "done": []}
    bridge.batch_started.connect(lambda n: seen["started"].append(n))
    bridge.site_started.connect(lambda u, i, t: seen["site"].append(u))
    bridge.collector_started.connect(lambda u, c: seen["stage"].append(c))
    bridge.site_finished.connect(lambda e: seen["done"].append(e.url))

    bridge.start()
    worker.bus.emit(BatchStarted(batch_id="test0001", total=2))
    worker.bus.emit(SiteStarted(batch_id="test0001", url="https://a.test", index=1, total=2))
    worker.bus.emit(CollectorStarted(batch_id="test0001", url="https://a.test", collector="http"))
    worker.bus.emit(SiteFinished(batch_id="test0001", url="https://a.test", ok=True))
    bridge._drain()

    assert seen["started"] == [2]
    assert seen["site"] == ["https://a.test"]
    assert seen["stage"] == ["http"]
    assert seen["done"] == ["https://a.test"]


def test_bridge_drains_the_tail_before_reporting_stopped(qapp):
    """Events queued behind the worker's exit must not be dropped."""
    from salp_gui.bridge import BatchBridge

    worker = _FakeWorker()
    bridge = BatchBridge(worker)
    finishes: list = []
    stops: list = []
    bridge.batch_finished.connect(finishes.append)
    bridge.stopped.connect(lambda: stops.append(1))

    bridge.start()
    worker.bus.emit(BatchFinished(batch_id="test0001", total=1, succeeded=1))
    worker.finished = True          # worker exits with the event still queued
    bridge._drain()

    assert len(finishes) == 1
    assert stops == [1]


def test_bridge_cancel_reaches_the_worker(qapp):
    from salp_gui.bridge import BatchBridge

    worker = _FakeWorker()
    BatchBridge(worker).cancel()
    assert worker.cancelled is True


def test_bridge_drain_is_bounded(qapp):
    """One timer tick must not block painting on a huge backlog."""
    from salp_gui.bridge import BatchBridge

    worker = _FakeWorker()
    bridge = BatchBridge(worker)
    seen: list = []
    bridge.site_started.connect(lambda *a: seen.append(a))
    bridge.start()
    for i in range(BatchBridge.DRAIN_LIMIT + 50):
        worker.bus.emit(SiteStarted(batch_id="test0001", url=f"https://{i}.test"))
    bridge._drain()
    assert len(seen) == BatchBridge.DRAIN_LIMIT


def test_run_task_keeps_the_task_alive(qapp):
    """Regression: the signals QObject was collected mid-emit.

    The failure mode is silent, the worker thread dies with "Signal source
    has been deleted" and the UI simply never updates.
    """
    import gc

    from PySide6.QtCore import QObject, QRunnable, Signal

    from salp_gui.bridge import _ACTIVE_TASKS, run_task

    class _Signals(QObject):
        done = Signal(object)
        failed = Signal(str)

    class _NoopTask(QRunnable):
        """A real task would launch Chrome; the lifetime rule is the point."""

        def __init__(self):
            super().__init__()
            self.signals = _Signals()

        def run(self):
            pass

    task = _NoopTask()
    run_task(task)
    assert task in _ACTIVE_TASKS
    assert task.autoDelete() is False
    gc.collect()
    assert task in _ACTIVE_TASKS      # survived collection

    task.signals.done.emit({})
    assert task not in _ACTIVE_TASKS


# --------------------------------------------------------------------------
# Screens
# --------------------------------------------------------------------------

def test_lighthouse_concurrency_is_capped_and_separate(qapp, settings):
    """Two controls, and the dangerous one has a ceiling."""
    from salp_gui.pages.composer import MAX_LIGHTHOUSE_CONCURRENCY, ComposerPage

    page = ComposerPage(settings)
    assert page.lh_concurrency.maximum() == MAX_LIGHTHOUSE_CONCURRENCY
    assert page.http_concurrency.maximum() > MAX_LIGHTHOUSE_CONCURRENCY
    assert page.lh_concurrency is not page.http_concurrency


def test_composer_previews_normalization_before_running(qapp, settings):
    from salp_gui.pages.composer import ComposerPage

    page = ComposerPage(settings)
    page.input.setPlainText(
        "example.com\nhttps://example.com\n# note\n\nother.test"
    )
    page._revalidate()
    assert page.urls() == ["https://example.com", "https://other.test"]
    assert "2 site(s) ready" in page.summary.text()
    assert "duplicate" in page.summary.text()
    assert page.run_button.isEnabled()


def test_composer_disables_lighthouse_labels_with_their_controls(qapp, settings):
    """Greying only the spinboxes leaves the group looking half-enabled."""
    from salp_gui.pages.composer import ComposerPage

    page = ComposerPage(settings)
    page.lighthouse.setChecked(False)
    assert all(not w.isEnabled() for w in page._lh_widgets)
    page.lighthouse.setChecked(True)
    assert all(w.isEnabled() for w in page._lh_widgets)


def test_lighthouse_options_live_inside_a_checkable_group(qapp, settings):
    """The dependency must be structural, not just a colour cue.

    As siblings of a plain checkbox, a disabled "Also measure desktop" sat
    at the same indentation as everything else and read as broken rather
    than as waiting on its parent.
    """
    from PySide6.QtWidgets import QGroupBox

    from salp_gui.pages.composer import ComposerPage

    page = ComposerPage(settings)
    assert isinstance(page.lighthouse, QGroupBox)
    assert page.lighthouse.isCheckable()
    for widget in (page.lh_runs, page.lh_concurrency, page.lh_desktop):
        assert widget.parent() is page.lighthouse


def test_desktop_checkbox_responds_to_a_real_click(qapp, settings):
    """Regression: it looked enabled and silently ignored clicks."""
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtTest import QTest

    from salp_gui.pages.composer import ComposerPage

    page = ComposerPage(settings)
    page.lighthouse.setChecked(True)
    page.show()
    box = page.lh_desktop
    before = box.isChecked()
    QTest.mouseClick(box, Qt.MouseButton.LeftButton,
                     Qt.KeyboardModifier.NoModifier, QPoint(8, box.height() // 2))
    assert box.isChecked() is not before
    page.close()


def test_disabled_controls_are_visibly_different_from_enabled_ones(qapp):
    """The actual bug, and it is invisible to any non-rendering test.

    `QWidget {color: ...}` in the stylesheet overrides Qt's palette for the
    Disabled role too, so without explicit `:disabled` rules a greyed-out
    control renders pixel-identical to a live one: it looks clickable and
    does nothing. Measured difference was 0.0 before the fix.
    """
    from PySide6.QtWidgets import QCheckBox, QVBoxLayout, QWidget

    holder = QWidget()
    layout = QVBoxLayout(holder)
    enabled = QCheckBox("Also measure desktop")
    disabled = QCheckBox("Also measure desktop")
    disabled.setEnabled(False)
    layout.addWidget(enabled)
    layout.addWidget(disabled)
    holder.resize(300, 90)
    holder.show()
    qapp.processEvents()
    image = holder.grab().toImage()

    def mean_ink(widget) -> float:
        rect = widget.geometry()
        pixels = [
            image.pixelColor(x, y)
            for x in range(rect.x() + 22, rect.x() + 170)
            for y in range(rect.y(), rect.y() + rect.height())
        ]
        dark = [c for c in pixels if c.lightness() < 200]
        return sum(c.lightness() for c in dark) / max(1, len(dark))

    difference = abs(mean_ink(enabled) - mean_ink(disabled))
    holder.close()
    assert difference > 25, (
        f"disabled text is only {difference:.1f}/255 lighter than enabled; "
        "it will read as a broken control rather than an unavailable one"
    )


def test_composer_writes_both_concurrency_settings(qapp, settings):
    from salp_gui.pages.composer import ComposerPage

    page = ComposerPage(settings)
    page.http_concurrency.setValue(30)
    page.lighthouse.setChecked(True)
    page.lh_concurrency.setValue(4)
    page.lh_runs.setValue(5)
    page.apply_to_settings()

    assert settings.collector.http_concurrency == 30
    assert settings.lighthouse.concurrency == 4
    assert settings.lighthouse.runs == 5
    assert settings.lighthouse.enabled is True


def test_findings_table_stretches_the_title_column(qapp, settings):
    """Stretching column 0 truncated every finding title mid-sentence."""
    from PySide6.QtWidgets import QHeaderView

    from salp_gui.pages.history import HistoryPage

    page = HistoryPage(settings)
    header = page.findings.horizontalHeader()
    assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch
    assert header.sectionResizeMode(0) != QHeaderView.ResizeMode.Stretch


def test_history_empty_state_clears_once_a_batch_exists(qapp, settings, tmp_path):
    from salp import SCHEMA_VERSION, db
    from salp.schema import FormFactor, RunStatus

    from salp_gui.pages.history import HistoryPage

    page = HistoryPage(settings)
    page.refresh()
    assert "No audits yet" in page.header._subtitle.text()

    conn = db.init_db(settings.db_path)
    with db.transaction(conn):
        site_id = db.upsert_site(conn, "x.test")
        run_id = db.create_run(conn, batch_id="b1", site_id=site_id,
                               salp_version="0.1.0", schema_version=SCHEMA_VERSION)
        db.create_page(conn, run_id, "https://x.test", None, FormFactor.NONE)
        db.finish_run(conn, run_id, RunStatus.COMPLETED)

    page.refresh()
    assert "No audits yet" not in page.header._subtitle.text()


def test_main_window_builds_every_page(qapp, settings):
    from salp_gui.main_window import PAGES, MainWindow

    window = MainWindow(settings)
    assert window.stack.count() == len(PAGES)
    assert window.sidebar.count() == len(PAGES)
    window.close()
