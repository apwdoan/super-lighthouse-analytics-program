"""Compose a batch: paste URLs, choose what runs, start.

The live normalization preview is the point of this screen. Pasting 60 rows
from a spreadsheet and finding out *afterwards* that 12 were duplicates is a
bad first experience, and ``core.prepare_urls`` already answers the question
before anything runs.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from slap import core
from slap.config import Settings

from .. import theme
from ..widgets import PageHeader

#: Hard ceiling on the Lighthouse concurrency spinbox.
#:
#: Contended CPU inflates Total Blocking Time and Time to Interactive, so a
#: wide fan-out produces plausible, irreproducible, pessimistic scores. The
#: control is capped rather than merely documented, because a free-form
#: spinbox is an invitation to turn it up.
MAX_LIGHTHOUSE_CONCURRENCY = 4


class ComposerPage(QWidget):
    """Emits :attr:`start_requested` with the URL list when Run is pressed."""

    start_requested = Signal(list)

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = settings

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        layout.addWidget(PageHeader(
            "New batch", "Sites to audit",
            "One per line. Bare hostnames are fine; blank lines and # comments "
            "are ignored.",
        ))

        self.input = QPlainTextEdit()
        self.input.setPlaceholderText(
            "example.com\nhttps://another-site.co.uk/landing\n# a comment"
        )
        self.input.setMinimumHeight(150)
        layout.addWidget(self.input, 1)

        self.summary = QLabel("Nothing to audit yet.")
        self.summary.setObjectName("Caption")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        # Created before _build_options(), which wires signals that fire
        # immediately and read this label.
        self.estimate = QLabel("")
        self.estimate.setObjectName("Caption")

        layout.addWidget(self._build_options())

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.estimate)
        self.run_button = QPushButton("Run audit")
        self.run_button.setObjectName("Primary")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self._on_run)
        buttons.addWidget(self.run_button)
        layout.addLayout(buttons)

        # Debounced so typing does not re-normalize on every keystroke.
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(250)
        self._debounce.timeout.connect(self._revalidate)
        self.input.textChanged.connect(self._debounce.start)

    # ----------------------------------------------------------------------

    def _build_options(self) -> QWidget:
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(10)
        outer.addWidget(self._build_network_group())
        outer.addWidget(self._build_lighthouse_group())
        return container

    def _build_network_group(self) -> QWidget:
        box = QGroupBox("Network checks: headers, TLS, redirects, CrUX")
        grid = QGridLayout(box)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(9)

        grid.addWidget(QLabel("Concurrent sites"), 0, 0)
        self.http_concurrency = QSpinBox()
        self.http_concurrency.setRange(1, 50)
        self.http_concurrency.setValue(self._settings.collector.http_concurrency)
        grid.addWidget(self.http_concurrency, 0, 1)
        hint = QLabel("Always on, seconds per site. Safe to raise.")
        hint.setObjectName("Caption")
        grid.addWidget(hint, 0, 2)

        grid.setColumnStretch(2, 1)
        return box

    def _build_lighthouse_group(self) -> QWidget:
        """A *checkable* group, not a checkbox followed by loose controls.

        The dependency has to be structural. When these were siblings of a
        plain "Also run Lighthouse" checkbox, a disabled "Also measure
        desktop" sat at the same indentation as everything else and read as
        a broken control rather than one waiting on its parent. A checkable
        QGroupBox draws the boundary, and Qt disables the children for us.
        """
        box = QGroupBox("Also run Lighthouse (lab audit)")
        box.setCheckable(True)
        box.setChecked(self._settings.lighthouse.enabled)
        box.toggled.connect(self._on_lighthouse_toggled)
        #: The group box *is* the toggle. `isChecked`, `setChecked` and
        #: `toggled` all behave like the checkbox this replaced.
        self.lighthouse = box

        grid = QGridLayout(box)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(9)

        runs_label = QLabel("Runs per site")
        grid.addWidget(runs_label, 0, 0)
        self.lh_runs = QSpinBox()
        self.lh_runs.setRange(1, 7)
        self.lh_runs.setValue(self._settings.lighthouse.runs)
        grid.addWidget(self.lh_runs, 0, 1)
        runs_hint = QLabel("Median is reported; the spread goes on the report.")
        runs_hint.setObjectName("Caption")
        grid.addWidget(runs_hint, 0, 2)

        lh_conc_label = QLabel("Concurrent Lighthouse runs")
        grid.addWidget(lh_conc_label, 1, 0)
        self.lh_concurrency = QSpinBox()
        # SEPARATE control from concurrent sites, and capped. See the
        # constant's comment.
        self.lh_concurrency.setRange(1, MAX_LIGHTHOUSE_CONCURRENCY)
        self.lh_concurrency.setValue(
            min(self._settings.lighthouse.concurrency, MAX_LIGHTHOUSE_CONCURRENCY)
        )
        grid.addWidget(self.lh_concurrency, 1, 1)
        cap_hint = QLabel(
            f"Capped at {MAX_LIGHTHOUSE_CONCURRENCY}. More Chrome instances "
            "contend for CPU, which inflates the blocking-time metrics and "
            "makes scores irreproducible."
        )
        cap_hint.setObjectName("Caption")
        cap_hint.setWordWrap(True)
        grid.addWidget(cap_hint, 1, 2)

        self.lh_desktop = QCheckBox("Also measure desktop")
        self.lh_desktop.setChecked("desktop" in self._settings.lighthouse.form_factors)
        grid.addWidget(self.lh_desktop, 2, 0, 1, 2)
        desktop_hint = QLabel("Doubles the run time. Mobile matches the field data.")
        desktop_hint.setObjectName("Caption")
        grid.addWidget(desktop_hint, 2, 2)

        grid.setColumnStretch(2, 1)
        # Qt disables these itself when the group is unchecked; the list is
        # kept so tests can assert it, not to drive the behaviour.
        self._lh_widgets = [
            self.lh_runs, self.lh_concurrency, self.lh_desktop,
            runs_label, lh_conc_label, runs_hint, cap_hint, desktop_hint,
        ]
        for spin in (self.lh_runs, self.lh_concurrency):
            spin.valueChanged.connect(self._update_estimate)
        self.lh_desktop.toggled.connect(lambda _: self._update_estimate())
        return box

    def _on_lighthouse_toggled(self, checked: bool) -> None:
        self._update_estimate()

    # ----------------------------------------------------------------------

    def urls(self) -> list[str]:
        return core.prepare_urls(self.input.toPlainText().splitlines())

    def _revalidate(self) -> None:
        raw_lines = [
            line for line in self.input.toPlainText().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        targets = self.urls()
        self.run_button.setEnabled(bool(targets))

        if not targets:
            self.summary.setText(
                "Nothing to audit yet." if not raw_lines
                else f"{len(raw_lines)} line(s), none usable as a URL."
            )
        else:
            dropped = len(raw_lines) - len(targets)
            text = f"{len(targets)} site(s) ready."
            if dropped > 0:
                text += f" {dropped} duplicate or unusable line(s) will be skipped."
            self.summary.setText(text)
        self._update_estimate()

    def _update_estimate(self) -> None:
        count = len(self.urls())
        if not count:
            self.estimate.setText("")
            return
        if not self.lighthouse.isChecked():
            self.estimate.setText(f"About {max(1, count // 8)} min for {count} site(s)")
            return
        form_factors = 2 if self.lh_desktop.isChecked() else 1
        runs = self.lh_runs.value() * form_factors * count
        minutes = max(1, round(runs * 30 / max(1, self.lh_concurrency.value()) / 60))
        self.estimate.setText(f"About {minutes} min: {runs} Lighthouse run(s)")

    def apply_to_settings(self) -> None:
        """Push the form into Settings. The only place this page writes."""
        self._settings.collector.http_concurrency = self.http_concurrency.value()
        self._settings.lighthouse.enabled = self.lighthouse.isChecked()
        self._settings.lighthouse.runs = self.lh_runs.value()
        self._settings.lighthouse.concurrency = self.lh_concurrency.value()
        self._settings.lighthouse.form_factors = (
            ("mobile", "desktop") if self.lh_desktop.isChecked() else ("mobile",)
        )

    def _on_run(self) -> None:
        targets = self.urls()
        if not targets:
            return
        self.apply_to_settings()
        self.start_requested.emit(targets)

    def set_running(self, running: bool) -> None:
        self.run_button.setEnabled(not running and bool(self.urls()))
        self.run_button.setText("Audit running..." if running else "Run audit")
