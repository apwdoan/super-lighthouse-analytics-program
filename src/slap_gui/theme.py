"""Shared visual vocabulary.

Colours and status words are imported from the report layer rather than
redefined, because the operator view and the client-facing report must not
drift. If a severity reads "High" and burnt orange in the PDF, it reads the
same here.

Two rules inherited from the report's palette, and they are load-bearing:

1. ``serious`` (#ec835a, the HIGH badge) and ``warning`` (#fab219, the
   MEDIUM badge) sit only ΔE 13.6 apart in normal vision. They appear
   adjacent in every findings list, so a badge must ALWAYS carry its
   severity word. Never reduce one to a bare coloured dot.
2. Both are below 3:1 contrast on a light surface, so status colours are
   used as fills and dots beside dark ink, never as text colour.
"""

from __future__ import annotations

from PySide6.QtGui import QColor

# Imported, not redeclared: one source of truth with the report.
from slap.report.model import SEVERITY_STATUS, STATUS_WORDS  # noqa: F401

SURFACE = "#fcfcfb"
PAGE = "#f9f9f7"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
BORDER = "rgba(11, 11, 11, 0.10)"
#: Text colour for disabled controls. Must be far enough from INK to
#: read as "not available" at a glance, and it is the only thing
#: distinguishing a control that is waiting on its parent from one
#: that is simply broken.
DISABLED_INK = "#b3b1a9"
ACCENT = "#2a78d6"

STATUS_COLOURS: dict[str, str] = {
    "good": "#0ca30c",
    "warning": "#fab219",
    "serious": "#ec835a",
    "critical": "#d03b3b",
    "muted": "#898781",
    "needs-improvement": "#fab219",
    "poor": "#d03b3b",
    "unknown": "#898781",
}

#: Run status -> (status key, display word).
RUN_STATUS = {
    "pending": ("muted", "Queued"),
    "running": ("warning", "Running"),
    "completed": ("good", "Done"),
    "failed": ("critical", "Failed"),
    "cancelled": ("muted", "Cancelled"),
}

FONT_STACK = '"Segoe UI", system-ui, -apple-system, sans-serif'
MONO_STACK = '"Cascadia Mono", Consolas, ui-monospace, monospace'


def colour(status: str) -> QColor:
    return QColor(STATUS_COLOURS.get(status, INK_MUTED))


def severity_status(severity: str) -> str:
    return SEVERITY_STATUS.get(severity, "muted")


STYLESHEET = f"""
QWidget {{
    background: {SURFACE};
    color: {INK};
    font-family: {FONT_STACK};
    font-size: 13px;
}}
QLabel#Title {{ font-size: 20px; font-weight: 600; }}
QLabel#Subtitle {{ color: {INK_SECONDARY}; }}
QLabel#Caption {{ color: {INK_MUTED}; font-size: 11px; }}
QLabel#Eyebrow {{
    color: {INK_MUTED};
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1px;
}}
QLabel#StatValue {{ font-size: 26px; font-weight: 600; }}

QFrame#Card {{
    background: {PAGE};
    border: 1px solid {GRID};
    border-radius: 8px;
}}
QFrame#Divider {{ background: {GRID}; max-height: 1px; border: none; }}

QPushButton {{
    background: {PAGE};
    border: 1px solid {BASELINE};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{ background: {GRID}; }}
QPushButton:disabled {{ color: {INK_MUTED}; border-color: {GRID}; }}
QPushButton#Primary {{
    background: {ACCENT};
    border-color: {ACCENT};
    color: #ffffff;
    font-weight: 600;
}}
QPushButton#Primary:hover {{ background: #256abf; }}
QPushButton#Primary:disabled {{ background: {BASELINE}; border-color: {BASELINE}; color: {PAGE}; }}
QPushButton#Danger {{ border-color: #d03b3b; color: #d03b3b; }}

QPlainTextEdit, QLineEdit, QSpinBox, QComboBox {{
    background: #ffffff;
    border: 1px solid {BASELINE};
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: {ACCENT};
}}
QPlainTextEdit#Log {{
    font-family: {MONO_STACK};
    font-size: 11px;
    color: {INK_SECONDARY};
    background: {PAGE};
}}

QTableView {{
    background: {SURFACE};
    border: 1px solid {GRID};
    border-radius: 6px;
    gridline-color: {GRID};
    selection-background-color: #e6effb;
    selection-color: {INK};
}}
QHeaderView::section {{
    background: {SURFACE};
    border: none;
    border-bottom: 1px solid {BASELINE};
    padding: 6px 8px;
    color: {INK_MUTED};
    font-size: 10px;
    font-weight: 700;
}}

QProgressBar {{
    background: {GRID};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 3px; }}

QListWidget#Sidebar {{
    background: {PAGE};
    border: none;
    border-right: 1px solid {GRID};
    outline: none;
    padding-top: 8px;
}}
QListWidget#Sidebar::item {{
    padding: 9px 16px;
    margin: 1px 8px;
    border-radius: 6px;
    color: {INK_SECONDARY};
}}
QListWidget#Sidebar::item:selected {{
    background: {SURFACE};
    color: {INK};
    font-weight: 600;
}}
QCheckBox {{ spacing: 8px; }}
QGroupBox {{
    border: 1px solid {GRID};
    border-radius: 8px;
    margin-top: 14px;
    padding: 14px 12px 10px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
    color: {INK_SECONDARY};
}}
QGroupBox::indicator {{ width: 15px; height: 15px; }}
QGroupBox:!checked::title {{ color: {INK_MUTED}; }}

/* ---------------------------------------------------------------------
 * Disabled states. These MUST be declared explicitly.
 *
 * `QWidget {{ color: ... }}` at the top of this sheet overrides Qt's
 * palette for every colour role INCLUDING Disabled. Without the rules
 * below, a greyed-out control renders pixel-identical to a live one
 * (measured: zero difference in mean text lightness) so it looks
 * perfectly clickable and simply does not respond. That is what made
 * "Also measure desktop" read as a broken checkbox rather than as one
 * waiting on its parent.
 *
 * If you add a new widget type to this sheet with an explicit `color`,
 * add its `:disabled` rule at the same time.
 * ------------------------------------------------------------------ */
/* The ID selectors above (QLabel#Caption etc.) set an explicit colour and
 * outrank a plain `QLabel:disabled`, so each one needs its own disabled
 * rule or the hint text stays at full strength beside a greyed control. */
QLabel#Caption:disabled, QLabel#Subtitle:disabled, QLabel#Eyebrow:disabled {{
    color: {DISABLED_INK};
}}
QLabel:disabled,
QCheckBox:disabled,
QRadioButton:disabled,
QGroupBox:disabled {{ color: {DISABLED_INK}; }}
QSpinBox:disabled, QComboBox:disabled, QLineEdit:disabled, QPlainTextEdit:disabled {{
    color: {DISABLED_INK};
    background: {PAGE};
    border-color: {GRID};
}}
QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {{
    border: 1px solid {GRID};
    background: {PAGE};
}}
"""
