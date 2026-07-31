"""Settings, and the backend status panel.

The status panel is the reason this screen exists rather than being a
menu item. Every optional backend in SALP degrades *quietly* by design: no
CrUX key means no field data, no Lighthouse means no lab data, no Playwright
means no PDF. Each of those still produces a report, so without somewhere
that says so out loud, a teammate discovers the gap in front of a client.

The probe launches Chrome to read its version, so it runs on a worker
thread. Running it inline is what makes a settings screen feel broken.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from salp.config import Settings

from .. import theme
from ..bridge import DoctorTask, run_task
from ..widgets import PageHeader, StatusPill

BACKENDS = [
    ("crux", "CrUX field data",
     "Real-user Core Web Vitals. Free key, 150 queries per minute. "
     "Set CRUX_API_KEY in your environment."),
    ("lighthouse", "Lighthouse lab audit",
     "npm install --prefix <package>/node_worker. Needs Node 22.19 or newer."),
    ("chrome", "Chromium for measurement",
     "playwright install chromium. Shared with PDF export so every teammate "
     "measures on the same build."),
    ("pdf", "PDF export",
     'pip install "salp[report]" then playwright install chromium.'),
]


class SettingsPage(QWidget):
    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._pills: dict[str, StatusPill] = {}
        self._details: dict[str, QLabel] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        layout.addWidget(PageHeader(
            "Settings", "Backends and storage",
            "SALP runs with any subset of these. What is missing narrows the "
            "report, and the report says so rather than pretending.",
        ))

        layout.addWidget(self._build_backends())
        layout.addWidget(self._build_paths())
        layout.addStretch(1)

        footer = QHBoxLayout()
        footer.addStretch(1)
        self.recheck = QPushButton("Re-check backends")
        self.recheck.clicked.connect(self.check_backends)
        footer.addWidget(self.recheck)
        layout.addLayout(footer)

    # ----------------------------------------------------------------------

    def _build_backends(self) -> QWidget:
        box = QGroupBox("Backends")
        grid = QGridLayout(box)
        grid.setVerticalSpacing(10)
        grid.setHorizontalSpacing(16)

        for row, (key, label, hint) in enumerate(BACKENDS):
            pill = StatusPill("muted", "Checking...")
            pill.setFixedWidth(150)
            self._pills[key] = pill

            name = QLabel(label)
            name.setStyleSheet("font-weight: 600;")

            detail = QLabel(hint)
            detail.setObjectName("Caption")
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._details[key] = detail

            grid.addWidget(pill, row, 0)
            grid.addWidget(name, row, 1)
            grid.addWidget(detail, row, 2)

        grid.setColumnStretch(2, 1)
        return box

    def _build_paths(self) -> QWidget:
        box = QGroupBox("Storage")
        grid = QGridLayout(box)
        grid.setVerticalSpacing(9)
        grid.setHorizontalSpacing(12)

        self._path_edits: dict[str, QLineEdit] = {}
        rows = [
            ("db_path", "Database", "Every run, immutable and append-only."),
            ("report_dir", "Reports", "Where exported HTML and PDF land by default."),
            ("artifact_dir", "Artifacts", "Gzipped Lighthouse results, kept for forensics."),
        ]
        for row, (attr, label, hint) in enumerate(rows):
            edit = QLineEdit(str(getattr(self._settings, attr)))
            edit.setReadOnly(True)
            self._path_edits[attr] = edit

            open_button = QPushButton("Open")
            open_button.clicked.connect(
                lambda _checked=False, a=attr: self._open_path(a)
            )
            change_button = QPushButton("Change")
            change_button.clicked.connect(
                lambda _checked=False, a=attr: self._change_path(a)
            )

            caption = QLabel(hint)
            caption.setObjectName("Caption")

            grid.addWidget(QLabel(label), row * 2, 0)
            grid.addWidget(edit, row * 2, 1)
            grid.addWidget(open_button, row * 2, 2)
            grid.addWidget(change_button, row * 2, 3)
            grid.addWidget(caption, row * 2 + 1, 1, 1, 3)

        grid.setColumnStretch(1, 1)
        return box

    # ----------------------------------------------------------------------

    def check_backends(self) -> None:
        for pill in self._pills.values():
            pill.set_status("muted", "Checking...")
        self.recheck.setEnabled(False)
        task = DoctorTask(self._settings)
        task.signals.done.connect(self._on_checked)
        task.signals.failed.connect(self._on_check_failed)
        run_task(task)

    def _on_checked(self, report: dict) -> None:
        self.recheck.setEnabled(True)
        for key, (ok, detail) in report.items():
            pill = self._pills.get(key)
            if pill is not None:
                pill.set_status("good" if ok else "critical",
                                "Available" if ok else "Not set up")
            label = self._details.get(key)
            if label is not None and detail:
                label.setText(detail)

    def _on_check_failed(self, message: str) -> None:
        self.recheck.setEnabled(True)
        for pill in self._pills.values():
            pill.set_status("critical", "Check failed")
        for label in self._details.values():
            label.setText(message)

    def _open_path(self, attr: str) -> None:
        path = Path(getattr(self._settings, attr))
        target = path if path.is_dir() else path.parent
        target.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target.resolve())))

    def _change_path(self, attr: str) -> None:
        current = Path(getattr(self._settings, attr))
        if attr == "db_path":
            chosen, _ = QFileDialog.getSaveFileName(
                self, "Database file", str(current), "SQLite (*.sqlite3)"
            )
        else:
            chosen = QFileDialog.getExistingDirectory(self, "Folder", str(current))
        if not chosen:
            return
        setattr(self._settings, attr, Path(chosen))
        self._path_edits[attr].setText(chosen)
