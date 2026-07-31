"""Live batch progress.

Two things this screen has to get right:

* **Per-row updates.** A 100-site batch with Lighthouse runs for the better
  part of an hour. The model emits ``dataChanged`` for one row at a time so
  the table does not flicker or drop the user's selection.
* **Honest Stop copy.** Cancellation is cooperative: in-flight sites finish
  first, and with Lighthouse that can be 40 seconds. A Stop button that
  appears to do nothing for 40 seconds reads as a hang, so it disables
  itself and says what it is waiting for.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from salp.config import Settings

from .. import theme
from ..bridge import BatchBridge
from ..models import SiteProgressModel
from ..widgets import PageHeader, StatCard, stretch_table

MAX_LOG_LINES = 400


class MonitorPage(QWidget):
    """Drives one batch. Emits :attr:`finished` with the batch id."""

    finished = Signal(str)

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._bridge: BatchBridge | None = None
        self._model: SiteProgressModel | None = None
        self._total = 0
        self._findings = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        self.header = PageHeader("Batch", "Batch progress", "No batch running.")
        header_row.addWidget(self.header, 1)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("Danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._on_stop)
        header_row.addWidget(self.stop_button, 0)
        layout.addLayout(header_row)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_done = StatCard("Completed", "0", "Sites audited")
        self.card_failed = StatCard("Failed", "0", "Could not be reached")
        self.card_findings = StatCard("Findings", "0", "Across the batch")
        for card in (self.card_done, self.card_failed, self.card_findings):
            cards.addWidget(card)
        layout.addLayout(cards)

        self.table = QTableView()
        stretch_table(self.table)
        layout.addWidget(self.table, 1)

        log_label = QLabel("Activity")
        log_label.setObjectName("Eyebrow")
        layout.addWidget(log_label)
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(MAX_LOG_LINES)
        self.log.setFixedHeight(120)
        layout.addWidget(self.log)

    # ----------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._bridge is not None and not self._bridge.finished

    def attach(self, bridge: BatchBridge, urls: list[str]) -> None:
        """Take ownership of a started-or-startable bridge."""
        self._bridge = bridge
        self._total = len(urls)
        self._model = SiteProgressModel(urls)
        self.table.setModel(self._model)

        self.log.clear()
        self.progress.setRange(0, max(1, self._total))
        self.progress.setValue(0)
        self.card_done.set_value("0")
        self.card_failed.set_value("0")
        self.card_findings.set_value("0")
        self._findings = 0
        self.stop_button.setEnabled(True)
        self.stop_button.setText("Stop")
        self.header.set_subtitle(f"Batch {bridge.batch_id}: {self._total} site(s)")

        bridge.site_started.connect(self._on_site_started)
        bridge.collector_started.connect(self._on_collector_started)
        bridge.collector_done.connect(self._on_collector_done)
        bridge.site_finished.connect(self._on_site_finished)
        bridge.batch_finished.connect(self._on_batch_finished)
        bridge.log.connect(self._append_log)
        bridge.stopped.connect(self._on_stopped)

        bridge.start()

    # -- slots --------------------------------------------------------------

    def _on_site_started(self, url: str, index: int, total: int) -> None:
        if self._model:
            self._model.mark_started(url)

    def _on_collector_started(self, url: str, collector: str) -> None:
        if self._model:
            self._model.mark_collector_started(url, collector)

    def _on_collector_done(self, url: str, collector: str, ok: bool) -> None:
        if self._model:
            self._model.mark_collector_done(url, collector, ok)

    def _on_site_finished(self, event) -> None:
        if not self._model:
            return
        self._model.mark_finished(event)
        done, failed, total = self._model.counts()
        self.progress.setValue(done + failed)
        self.card_done.set_value(str(done))
        self.card_failed.set_value(str(failed))
        self._findings += event.findings
        self.card_findings.set_value(str(self._findings))

    def _on_batch_finished(self, event) -> None:
        self.header.set_subtitle(
            f"Batch {event.batch_id}: {event.message.lower()}"
        )

    def _on_stopped(self) -> None:
        """The worker thread has exited. Only now is the batch really over."""
        self.stop_button.setEnabled(False)
        self.stop_button.setText("Stop")
        if self._model:
            self._model.mark_all_stopped()
            done, failed, _ = self._model.counts()
            self.progress.setValue(done + failed)
            self.card_done.set_value(str(done))
            self.card_failed.set_value(str(failed))
        if self._bridge:
            self.finished.emit(self._bridge.batch_id)

    def _on_stop(self) -> None:
        if not self._bridge:
            return
        # Say what is actually happening. Cancellation lets in-flight sites
        # finish, which with Lighthouse enabled is up to ~40 seconds of
        # apparent nothing.
        self.stop_button.setEnabled(False)
        self.stop_button.setText("Finishing in-flight sites...")
        self._append_log("Cancelling. Sites already in progress will finish.", "warning")
        self._bridge.cancel()

    def _append_log(self, text: str, level: str = "info") -> None:
        prefix = {"warning": "! ", "error": "x ", "info": "  "}.get(level, "  ")
        self.log.appendPlainText(prefix + text)
