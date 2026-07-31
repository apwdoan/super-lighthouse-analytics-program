"""Small reusable pieces.

:class:`StatusPill` is the one to be careful with: it always renders a dot
*and* a word. Reducing it to a bare dot would break the palette rule
inherited from the report, where two adjacent severity colours sit below
the normal-vision separation floor.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QPaintEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")


class Divider(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Divider")
        self.setFixedHeight(1)
        self.setFrameShape(QFrame.Shape.NoFrame)


class StatusPill(QWidget):
    """A coloured dot next to a word. The word is NOT optional."""

    def __init__(self, status: str = "muted", text: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._status = status
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(7)
        self._dot = _Dot(status)
        self._label = QLabel(text)
        self._label.setStyleSheet("font-weight: 600;")
        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        layout.addStretch(1)

    def set_status(self, status: str, text: str) -> None:
        self._status = status
        self._dot.set_status(status)
        self._label.setText(text)

    @property
    def text(self) -> str:
        return self._label.text()


class _Dot(QWidget):
    SIZE = 9

    def __init__(self, status: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._status = status
        self.setFixedSize(self.SIZE, self.SIZE)

    def set_status(self, status: str) -> None:
        self._status = status
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(theme.colour(self._status))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(0, 0, self.SIZE, self.SIZE)


class StatCard(Card):
    """Label, big value, caption. A KPI tile, not a chart."""

    def __init__(self, label: str, value: str = "0", caption: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 12)
        layout.setSpacing(1)

        self._label = QLabel(label)
        self._label.setStyleSheet(
            f"font-size: 11px; font-weight: 600; color: {theme.INK_SECONDARY};"
        )
        self._value = QLabel(value)
        self._value.setObjectName("StatValue")
        self._caption = QLabel(caption)
        self._caption.setObjectName("Caption")
        self._caption.setWordWrap(True)

        layout.addWidget(self._label)
        layout.addWidget(self._value)
        layout.addWidget(self._caption)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, value: str, caption: str | None = None) -> None:
        self._value.setText(value)
        if caption is not None:
            self._caption.setText(caption)

    @property
    def value(self) -> str:
        return self._value.text()


class PageHeader(QWidget):
    def __init__(self, eyebrow: str, title: str, subtitle: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        brow = QLabel(eyebrow.upper())
        brow.setObjectName("Eyebrow")
        heading = QLabel(title)
        heading.setObjectName("Title")
        layout.addWidget(brow)
        layout.addWidget(heading)

        self._subtitle = QLabel(subtitle)
        self._subtitle.setObjectName("Subtitle")
        self._subtitle.setWordWrap(True)
        layout.addWidget(self._subtitle)
        self._subtitle.setVisible(bool(subtitle))

    def set_subtitle(self, text: str) -> None:
        self._subtitle.setText(text)
        self._subtitle.setVisible(bool(text))


def stretch_table(view, stretch_column: int = 0) -> None:
    """Sensible defaults for every table in this app.

    ``stretch_column`` is the one that absorbs spare width; every other
    column sizes to its contents. Getting this wrong is not cosmetic: with
    the default of 0 on the findings table, the narrow Severity column
    swallowed the width and every finding title was truncated mid-sentence.
    """
    from PySide6.QtWidgets import QAbstractItemView, QHeaderView

    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setAlternatingRowColors(False)
    view.setWordWrap(False)
    view.setTextElideMode(Qt.TextElideMode.ElideRight)
    view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    view.verticalHeader().setVisible(False)
    view.setShowGrid(False)

    header = view.horizontalHeader()
    header.setStretchLastSection(False)
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    header.setSectionResizeMode(stretch_column, QHeaderView.ResizeMode.Stretch)
    view.verticalHeader().setDefaultSectionSize(28)
