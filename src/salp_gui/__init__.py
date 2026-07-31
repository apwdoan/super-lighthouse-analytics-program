"""SALP desktop front-end (PySide6).

A client of :mod:`salp.core` and nothing below it. The dependency points
one way and must stay that way: nothing under ``salp/`` imports Qt, which
is what keeps the core testable without a display server and keeps a web
front-end possible later at no ongoing cost.
"""

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    from .app import main as _main

    return _main(argv)
