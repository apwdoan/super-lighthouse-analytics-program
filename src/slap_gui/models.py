"""Table models.

Two rules, both from ``docs/gui-architecture.md``:

* **No SQL in view code.** Every model reads through :mod:`slap.core`. If a
  model needs something core cannot express, add a function to core.
* **Emit ``dataChanged`` for the rows that changed, never ``layoutChanged``
  or ``beginResetModel``.** A 100-site batch with Lighthouse enabled runs
  for the better part of an hour and emits thousands of updates; resetting
  the model on each one flickers the table and throws away the user's
  selection and scroll position every time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from slap import core
from slap.config import Settings
from slap.report.model import format_ms

from . import theme

STATUS_ROLE = Qt.ItemDataRole.UserRole + 1
ID_ROLE = Qt.ItemDataRole.UserRole + 2


# --------------------------------------------------------------------------
# Live batch progress
# --------------------------------------------------------------------------

@dataclass(slots=True)
class SiteRow:
    url: str
    state: str = "queued"          # queued | running | done | failed
    #: Collectors currently in flight. A stage runs several concurrently, so
    #: this is a set rather than a single name, and it is driven by
    #: CollectorStarted/Finished pairs rather than by "last one that
    #: finished" (which leaves a site in a 90-second Lighthouse run showing
    #: the name of whatever completed before it).
    in_flight: set = field(default_factory=set)
    observations: int = 0
    findings: int = 0
    run_id: int | None = None
    error: str | None = None

    @property
    def stage(self) -> str:
        if self.state != "running":
            return ""
        if not self.in_flight:
            return "starting"
        return ", ".join(sorted(self.in_flight))

    @property
    def status_key(self) -> str:
        return {
            "queued": "muted", "running": "warning",
            "done": "good", "failed": "critical",
        }[self.state]

    @property
    def status_word(self) -> str:
        return {
            "queued": "Queued", "running": "Running",
            "done": "Done", "failed": "Failed",
        }[self.state]


class SiteProgressModel(QAbstractTableModel):
    """One row per site in the running batch."""

    COLUMNS = ("Site", "Status", "Stage", "Observations", "Findings")

    def __init__(self, urls: list[str], parent=None) -> None:
        super().__init__(parent)
        self._rows: list[SiteRow] = [SiteRow(url=u) for u in urls]
        self._index_by_url: dict[str, int] = {u: i for i, u in enumerate(urls)}

    # -- Qt plumbing --------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return (
                _short_url(row.url),
                row.status_word,
                row.stage,
                str(row.observations) if row.observations else "",
                str(row.findings) if row.findings else "",
            )[column]

        if role == Qt.ItemDataRole.ToolTipRole:
            return row.error or row.url

        if role == Qt.ItemDataRole.ForegroundRole and column == 1:
            # Status colour on the status column only, and it always sits
            # beside the status WORD, never replacing it.
            return theme.colour(row.status_key)

        if role == Qt.ItemDataRole.FontRole and column == 1 and row.state != "queued":
            font = QFont()
            font.setBold(True)
            return font

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (3, 4):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        if role == STATUS_ROLE:
            return row.status_key
        if role == ID_ROLE:
            return row.run_id
        return None

    # -- Updates ------------------------------------------------------------

    def _touch(self, row_index: int) -> None:
        """Repaint exactly one row. See the module docstring."""
        top = self.index(row_index, 0)
        bottom = self.index(row_index, self.columnCount() - 1)
        self.dataChanged.emit(top, bottom)

    def mark_started(self, url: str) -> None:
        index = self._index_by_url.get(url)
        if index is None:
            return
        self._rows[index].state = "running"
        self._touch(index)

    def mark_collector_started(self, url: str, collector: str) -> None:
        index = self._index_by_url.get(url)
        if index is None:
            return
        self._rows[index].in_flight.add(collector)
        self._touch(index)

    def mark_collector_done(self, url: str, collector: str, ok: bool) -> None:
        index = self._index_by_url.get(url)
        if index is None:
            return
        self._rows[index].in_flight.discard(collector)
        self._touch(index)

    def mark_finished(self, event: Any) -> None:
        index = self._index_by_url.get(event.url)
        if index is None:
            return
        row = self._rows[index]
        row.state = "done" if event.ok else "failed"
        row.in_flight.clear()
        row.observations = event.observations
        row.findings = event.findings
        row.run_id = event.run_id or None
        row.error = event.error
        self._touch(index)

    def mark_all_stopped(self) -> None:
        """Anything still queued when a batch ends never ran. Say so."""
        for i, row in enumerate(self._rows):
            if row.state in ("queued", "running"):
                row.state = "failed"
                row.in_flight.clear()
                row.error = row.error or "cancelled before this site ran"
                self._touch(i)

    def run_ids(self) -> list[int]:
        return [r.run_id for r in self._rows if r.run_id]

    def counts(self) -> tuple[int, int, int]:
        done = sum(1 for r in self._rows if r.state == "done")
        failed = sum(1 for r in self._rows if r.state == "failed")
        return done, failed, len(self._rows)


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------

class BatchTableModel(QAbstractTableModel):
    # "Done" is Sites minus Failed, so the column was pure redundancy and it
    # squeezed the batch id into an ellipsis.
    COLUMNS = ("Batch", "Started", "Sites", "Failed")

    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._rows: list[dict[str, Any]] = []

    def refresh(self) -> None:
        self.beginResetModel()          # a full reload genuinely is a reset
        self._rows = core.list_batches(self._settings, limit=200)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                row["batch_id"],
                _short_time(row["started_at"]),
                str(row["run_count"]),
                str(row["failed"] or 0),
            )[index.column()]
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() >= 2:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == ID_ROLE:
            return row["batch_id"]
        return None

    def batch_id_at(self, row: int) -> str | None:
        return self._rows[row]["batch_id"] if 0 <= row < len(self._rows) else None


class RunTableModel(QAbstractTableModel):
    COLUMNS = ("Site", "Status", "Findings", "Started")

    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._rows: list[dict[str, Any]] = []
        self._batch_id: str | None = None

    def refresh(self, batch_id: str | None = None) -> None:
        self.beginResetModel()
        self._batch_id = batch_id
        self._rows = core.list_runs(self._settings, batch_id=batch_id, limit=1000)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        status_key, status_word = theme.RUN_STATUS.get(
            row["status"], ("muted", row["status"])
        )
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                row["hostname"],
                status_word,
                str(row["finding_count"]),
                _short_time(row["started_at"]),
            )[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 1:
            return theme.colour(status_key)
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() == 2:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == ID_ROLE:
            return row["id"]
        return None

    def run_id_at(self, row: int) -> int | None:
        return self._rows[row]["id"] if 0 <= row < len(self._rows) else None


class FindingTableModel(QAbstractTableModel):
    """Findings for one run. Severity always renders as a WORD."""

    COLUMNS = ("Severity", "Finding", "Impact", "Effort")

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[dict[str, Any]] = []

    def set_findings(self, findings: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self._rows = findings
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        status = theme.severity_status(row["severity"])
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                row["severity"].capitalize(),
                row["title"],
                format_ms(row["impact_ms"]) if row["impact_ms"] else "",
                (row["effort"] or "").capitalize(),
            )[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 0:
            return theme.colour(status)
        if role == Qt.ItemDataRole.FontRole and index.column() == 0:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.ToolTipRole:
            parts = [" ".join((row["detail"] or "").split())]
            if row.get("remediation"):
                parts.append("Fix: " + " ".join(row["remediation"].split()))
            if row.get("wp_rocket_setting"):
                parts.append("WP Rocket: " + row["wp_rocket_setting"])
            return "\n\n".join(parts)
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() == 2:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def finding_at(self, row: int) -> dict[str, Any] | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None


# --------------------------------------------------------------------------

def _short_url(url: str) -> str:
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    return url[:80]


def _short_time(value: Any) -> str:
    text = str(value or "")
    return text.replace("T", " ").replace("+00:00", "")[:19]
