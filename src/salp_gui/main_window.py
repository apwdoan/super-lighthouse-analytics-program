"""The window, and the only place pages talk to each other.

Layering, restated because it is the rule this whole package exists to
respect: ``salp_gui`` depends on ``salp.core`` and nothing below it. No
widget builds a pipeline, opens a database, or renders a template. If a
button needs something the core cannot express, the core is missing a
function.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QWidget,
)

from salp import core
from salp.config import Settings

from . import theme
from .bridge import BatchBridge
from .pages.composer import ComposerPage
from .pages.history import HistoryPage
from .pages.monitor import MonitorPage
from .pages.settings import SettingsPage

PAGES = ("New batch", "Progress", "History", "Settings")

#: How long to let background tasks finish on close. The backend
#: probe launches Chrome, so it needs a few seconds.
WORKER_SHUTDOWN_MS = 8000


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings
        self._bridge: BatchBridge | None = None

        self.setWindowTitle("SALP")
        self.resize(1180, 780)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(172)
        for name in PAGES:
            self.sidebar.addItem(QListWidgetItem(name))
        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self._on_nav)
        layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.composer = ComposerPage(settings)
        self.monitor = MonitorPage(settings)
        self.history = HistoryPage(settings)
        self.settings_page = SettingsPage(settings)
        for page in (self.composer, self.monitor, self.history, self.settings_page):
            self.stack.addWidget(page)
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(central)

        self.composer.start_requested.connect(self.start_batch)
        self.monitor.finished.connect(self._on_batch_finished)

        self.history.refresh()
        self.settings_page.check_backends()

    # ----------------------------------------------------------------------

    def _on_nav(self, row: int) -> None:
        self.stack.setCurrentIndex(row)
        if PAGES[row] == "History":
            self.history.refresh()

    def start_batch(self, urls: list[str]) -> None:
        if self.monitor.running:
            QMessageBox.information(
                self, "Batch already running",
                "Wait for the current batch to finish, or stop it first.",
            )
            return

        worker = core.BatchWorker(urls, self._settings)
        self._bridge = BatchBridge(worker, self)
        self.composer.set_running(True)
        self.monitor.attach(self._bridge, urls)
        self.sidebar.setCurrentRow(PAGES.index("Progress"))

    def _on_batch_finished(self, batch_id: str) -> None:
        self.composer.set_running(False)
        self.history.select_batch(batch_id)

    # ----------------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802
        """Stop a running batch politely, then release SQLite handles."""
        if self.monitor.running:
            answer = QMessageBox.question(
                self, "Batch still running",
                "A batch is still running. Stop it and close?\n\n"
                "Sites already audited are saved; nothing is lost.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            if self._bridge:
                self._bridge.cancel()

        # Let in-flight QRunnables (export, backend probe) finish before Qt
        # tears down the objects they are about to emit from. Without this,
        # closing during an export kills the thread with "Signal source has
        # been deleted" and, on some platforms, takes the process with it.
        pool = QThreadPool.globalInstance()
        if pool.activeThreadCount():
            pool.waitForDone(WORKER_SHUTDOWN_MS)

        # Thread-local connections belong to whichever thread opened them;
        # this releases the main thread's.
        core.close_connections()
        event.accept()
