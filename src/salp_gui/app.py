"""Application entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from salp.config import Settings

from . import theme
from .main_window import MainWindow


def build_app(argv: list[str] | None = None) -> tuple[QApplication, MainWindow]:
    app = QApplication.instance() or QApplication(argv or sys.argv)
    app.setApplicationName("SALP")
    app.setOrganizationName("SALP")
    app.setStyleSheet(theme.STYLESHEET)

    settings = Settings.load()
    settings.ensure_dirs()
    window = MainWindow(settings)
    return app, window


def main(argv: list[str] | None = None) -> int:
    app, window = build_app(argv)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
