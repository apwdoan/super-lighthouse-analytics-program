"""SLAP: Super Lighthouse Analytics Project.

Layering rule enforced throughout this package:

    collectors  ->  observations  ->  findings  ->  report

Collectors never format. The findings engine is data (YAML), not code.
Nothing under ``slap`` imports a GUI toolkit; front-ends (CLI, PySide6)
are clients of :mod:`slap.core` and are the only layer allowed to know
what a widget is.
"""

__version__ = "0.1.0"

SCHEMA_VERSION = 1

# Must run before anything imports Playwright: it reads
# PLAYWRIGHT_BROWSERS_PATH at import time to locate its browser. No-op from
# a source checkout.
from . import bundle as _bundle  # noqa: E402

_bundle.configure_environment()
