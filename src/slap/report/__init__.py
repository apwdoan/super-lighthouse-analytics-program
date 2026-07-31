"""Report rendering. Jinja2 to HTML, then Chromium to PDF.

Front-ends should not import this directly; :mod:`slap.core` exposes
``export_report`` / ``export_batch_report`` which handle paths, settings,
and the HTML-then-PDF ordering.
"""

from .model import (
    BatchModel,
    ReportModel,
    build_batch_model,
    build_report_model,
    cwv_status,
    flatten_observations,
)
from .pdf import (
    BackendStatus,
    PdfError,
    check_backend,
    html_file_to_pdf,
    html_file_to_pdf_async,
    merge_pdfs,
)
from .render import (
    render_batch_html,
    render_report_html,
    report_filename,
    safe_filename,
    write_html,
)

__all__ = [
    "ReportModel", "BatchModel", "build_report_model", "build_batch_model",
    "cwv_status", "flatten_observations",
    "render_report_html", "render_batch_html", "write_html", "safe_filename",
    "report_filename",
    "PdfError", "BackendStatus", "check_backend", "html_file_to_pdf",
    "html_file_to_pdf_async", "merge_pdfs",
]
