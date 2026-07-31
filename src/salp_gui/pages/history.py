"""Browse past runs and export reports.

Reads go through :mod:`salp.core`; this file contains no SQL. Exports run on
``QThreadPool`` because ``core.export_report`` is synchronous, spawns
Chromium, and takes seconds.

Viewing a report opens it with the system handler rather than embedding a
``QWebEngineView``: that widget adds ~150MB to the installer and
meaningfully complicates PyInstaller, and the report is a file the user
sends to a client, so they usually want it in a real browser anyway.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from salp import core
from salp.config import Settings

from .. import theme
from ..bridge import BatchExportTask, ExportTask, run_task
from ..models import BatchTableModel, FindingTableModel, RunTableModel
from ..widgets import PageHeader, StatusPill, stretch_table


class HistoryPage(QWidget):
    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._run_id: int | None = None
        self._batch_id: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)

        top = QHBoxLayout()
        self.header = PageHeader("History", "Past audits", "")
        top.addWidget(self.header, 1)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        top.addWidget(self.refresh_button)
        layout.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # -- batches --------------------------------------------------------
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 8, 0)
        left_layout.setSpacing(6)
        batches_label = QLabel("BATCHES")
        batches_label.setObjectName("Eyebrow")
        left_layout.addWidget(batches_label)
        self.batches = QTableView()
        self.batch_model = BatchTableModel(settings, self)
        self.batches.setModel(self.batch_model)
        # Stretch the timestamp, not the id: a batch id is fixed-width, so
        # sizing it to contents gives it exactly what it needs. (Forcing a
        # minimum section size instead applies it to EVERY column, which
        # pushed the narrow count columns into a horizontal scrollbar.)
        stretch_table(self.batches, stretch_column=1)
        self.batches.selectionModel().selectionChanged.connect(self._on_batch_selected)
        left_layout.addWidget(self.batches)
        splitter.addWidget(left)

        # -- runs + findings ------------------------------------------------
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 0, 0, 0)
        right_layout.setSpacing(6)

        runs_label = QLabel("RUNS")
        runs_label.setObjectName("Eyebrow")
        right_layout.addWidget(runs_label)
        self.runs = QTableView()
        self.run_model = RunTableModel(settings, self)
        self.runs.setModel(self.run_model)
        stretch_table(self.runs)
        self.runs.selectionModel().selectionChanged.connect(self._on_run_selected)
        right_layout.addWidget(self.runs, 1)

        self.verdict = StatusPill("muted", "Select a run")
        right_layout.addWidget(self.verdict)

        findings_label = QLabel("FINDINGS")
        findings_label.setObjectName("Eyebrow")
        right_layout.addWidget(findings_label)
        self.findings = QTableView()
        self.finding_model = FindingTableModel(self)
        self.findings.setModel(self.finding_model)
        stretch_table(self.findings, stretch_column=1)   # "Finding", not "Severity"
        right_layout.addWidget(self.findings, 2)

        self.detail = QLabel("")
        self.detail.setObjectName("Caption")
        self.detail.setWordWrap(True)
        self.detail.setMinimumHeight(48)
        self.detail.setAlignment(Qt.AlignmentFlag.AlignTop)
        right_layout.addWidget(self.detail)
        self.findings.selectionModel().selectionChanged.connect(self._on_finding_selected)

        splitter.addWidget(right)
        splitter.setSizes([390, 700])
        layout.addWidget(splitter, 1)

        # -- actions --------------------------------------------------------
        actions = QHBoxLayout()
        self.status = QLabel("")
        self.status.setObjectName("Caption")
        actions.addWidget(self.status, 1)

        self.export_run = QPushButton("Export this report")
        self.export_run.setEnabled(False)
        self.export_run.clicked.connect(self._on_export_run)
        actions.addWidget(self.export_run)

        self.export_batch = QPushButton("Export whole batch")
        self.export_batch.setEnabled(False)
        self.export_batch.clicked.connect(self._on_export_batch)
        actions.addWidget(self.export_batch)
        layout.addLayout(actions)

    # ----------------------------------------------------------------------

    def refresh(self) -> None:
        self.batch_model.refresh()
        self.run_model.refresh(self._batch_id)
        # Must be reset both ways, or the empty-state copy sticks around
        # forever after the first batch.
        count = self.batch_model.rowCount()
        self.header.set_subtitle(
            "No audits yet. Start one from New batch." if count == 0 else
            f"{count} batch(es) kept. Re-running never overwrites, so "
            "before-and-after comparison is exact."
        )

    def select_batch(self, batch_id: str) -> None:
        self.refresh()
        for row in range(self.batch_model.rowCount()):
            if self.batch_model.batch_id_at(row) == batch_id:
                self.batches.selectRow(row)
                return

    # -- selection ----------------------------------------------------------

    def _on_batch_selected(self, *_args) -> None:
        rows = self.batches.selectionModel().selectedRows()
        self._batch_id = self.batch_model.batch_id_at(rows[0].row()) if rows else None
        self.export_batch.setEnabled(self._batch_id is not None)
        self.run_model.refresh(self._batch_id)
        self._clear_run()

    def _on_run_selected(self, *_args) -> None:
        rows = self.runs.selectionModel().selectedRows()
        if not rows:
            self._clear_run()
            return
        self._run_id = self.run_model.run_id_at(rows[0].row())
        if self._run_id is None:
            self._clear_run()
            return

        detail = core.get_run_detail(self._settings, self._run_id)
        if detail is None:
            self._clear_run()
            return

        self.finding_model.set_findings(detail["findings"])
        self.export_run.setEnabled(True)
        self.detail.setText("")

        # Reuse the report's own view model so the operator view and the
        # client PDF can never disagree about a verdict.
        from salp.report.model import build_report_model

        model = build_report_model(detail)
        verdict = model.verdict
        if verdict.has_field_data:
            status = "good" if verdict.passes else "poor"
        elif verdict.has_lab_data:
            status = model.verdict.categories[0].status if verdict.categories else "muted"
        else:
            status = "muted"
        self.verdict.set_status(status, verdict.headline)

        run = detail["run"]
        engine = (f"Lighthouse {run['lh_version']} on Chrome {run['chrome_version']}"
                  if run.get("lh_version") else "Network checks only")
        self.status.setText(
            f"Run {run['id']} - {run['hostname']} - {engine} - "
            f"{len(detail['observations'])} measurements"
        )

    def _on_finding_selected(self, *_args) -> None:
        rows = self.findings.selectionModel().selectedRows()
        if not rows:
            self.detail.setText("")
            return
        finding = self.finding_model.finding_at(rows[0].row())
        if not finding:
            return
        parts = [" ".join((finding["detail"] or "").split())]
        if finding.get("remediation"):
            parts.append("Fix: " + " ".join(finding["remediation"].split()))
        if finding.get("wp_rocket_setting"):
            parts.append("In WP Rocket: " + finding["wp_rocket_setting"])
        self.detail.setText("\n\n".join(parts))

    def _clear_run(self) -> None:
        self._run_id = None
        self.finding_model.set_findings([])
        self.export_run.setEnabled(False)
        self.verdict.set_status("muted", "Select a run")
        self.detail.setText("")
        self.status.setText("")

    # -- export -------------------------------------------------------------

    def _choose_dir(self) -> Path | None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Save report to", str(self._settings.report_dir)
        )
        return Path(chosen) if chosen else None

    def _on_export_run(self) -> None:
        if self._run_id is None:
            return
        out_dir = self._choose_dir()
        if out_dir is None:
            return
        self._set_busy(True, "Rendering report...")
        task = ExportTask(self._settings, self._run_id, pdf=True, out_dir=out_dir)
        task.signals.done.connect(self._on_export_done)
        task.signals.failed.connect(self._on_export_failed)
        run_task(task)

    def _on_export_batch(self) -> None:
        if self._batch_id is None:
            return
        out_dir = self._choose_dir()
        if out_dir is None:
            return
        self._set_busy(True, "Rendering every report in the batch...")
        task = BatchExportTask(
            self._settings, self._batch_id, pdf=True, merge=True, out_dir=out_dir
        )
        task.signals.done.connect(self._on_batch_export_done)
        task.signals.failed.connect(self._on_export_failed)
        run_task(task)

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.export_run.setEnabled(not busy and self._run_id is not None)
        self.export_batch.setEnabled(not busy and self._batch_id is not None)
        if message:
            self.status.setText(message)

    def _on_export_done(self, result) -> None:
        self._set_busy(False)
        target = result.pdf_path or result.html_path
        if result.pdf_error:
            # A missing PDF backend is a partial success, not a failure: the
            # HTML is on disk either way.
            self.status.setText(f"HTML written to {result.html_path}. PDF unavailable.")
            QMessageBox.information(
                self, "PDF export unavailable",
                f"{result.pdf_error}\n\nThe HTML report was still written to:\n"
                f"{result.html_path}",
            )
        else:
            self.status.setText(f"Saved {target}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(target).resolve())))

    def _on_batch_export_done(self, result) -> None:
        self._set_busy(False)
        message = f"{len(result.sites)} report(s) written to {result.index_html.parent}"
        if result.merged_pdf:
            message += f", merged into {result.merged_pdf.name}"
        self.status.setText(message)
        if result.pdf_error:
            QMessageBox.information(
                self, "PDF export unavailable",
                f"{result.pdf_error}\n\nHTML reports were still written.",
            )
        target = result.index_pdf or result.index_html
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(target).resolve())))

    def _on_export_failed(self, message: str) -> None:
        self._set_busy(False)
        self.status.setText("Export failed.")
        QMessageBox.warning(self, "Export failed", message)
