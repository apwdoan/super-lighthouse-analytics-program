"""SLAP's web front-end.

A client of :mod:`slap.core` and nothing below it, exactly as the PySide6
front-end was. The same rule applies and is enforced by the same test: no
module under ``src/slap/`` may import a UI framework, and nothing here may
open a database, build a pipeline, or write SQL. If this package needs
something the core cannot express, the core is missing a function.

Why a web UI replaced the Qt one is written up in ``docs/ui-redesign.md``.
The short version: ``report/model.py`` is already a pure view model feeding
Jinja2 templates, so a browser front-end collapses the presentation layer
from two to one, and ``EventBus`` maps to server-sent events without the
queue-and-QTimer machinery every threading bug in this project lived in.
"""

from __future__ import annotations

__all__ = ["create_app", "main"]


def create_app(*args, **kwargs):  # noqa: ANN002, ANN003, ANN201
    """Deferred import so ``import slap_web`` does not require FastAPI."""
    from .app import create_app as _create_app

    return _create_app(*args, **kwargs)


def main() -> int:
    from .server import main as _main

    return _main()
