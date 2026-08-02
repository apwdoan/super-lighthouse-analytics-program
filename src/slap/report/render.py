"""Jinja2 rendering. HTML is the deliverable; PDF is a rendering of it.

That ordering is deliberate and comes from the roadmap: the HTML is the
artifact of record, and :mod:`slap.report.pdf` prints it. It means the PDF
can never contain something the HTML does not, and a client who wants a
link instead of an attachment is already served.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .model import (
    BatchModel,
    ReportModel,
    build_batch_model,
    build_report_model,
    short_path,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # Shortening a URL to its path is presentation, but it is presentation the
    # model already owns: `short_path` is the same function the page inventory
    # uses, exposed as a filter rather than reimplemented in the template.
    # Two implementations would let the inventory and the affected-pages list
    # disagree about what a page is called.
    env.filters["short_path"] = short_path
    return env


def safe_filename(text: str, *, fallback: str = "report") -> str:
    """A filename safe on Windows, macOS, and Linux.

    Windows is the binding constraint here: reserved characters plus the
    reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9), which fail
    even with an extension appended.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    if not cleaned:
        return fallback
    stem = cleaned.split(".")[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)[1-9]", stem):
        cleaned = f"site-{cleaned}"
    return cleaned[:120]


def render_report_html(detail: dict[str, Any], *,
                       branding: dict[str, Any] | None = None,
                       generated_at: datetime | None = None,
                       min_top: int = 3) -> str:
    model: ReportModel = build_report_model(
        detail, branding=branding, generated_at=generated_at, min_top=min_top
    )
    return _environment().get_template("report.html.j2").render(
        m=model, branding=model.branding
    )


def render_batch_html(batch_id: str, runs: list[dict[str, Any]],
                      details: dict[int, dict[str, Any]], *,
                      branding: dict[str, Any] | None = None,
                      generated_at: datetime | None = None) -> str:
    model: BatchModel = build_batch_model(
        batch_id, runs, details, branding=branding, generated_at=generated_at
    )
    return _environment().get_template("batch.html.j2").render(
        b=model, branding=model.branding
    )


def write_html(html: str, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def report_filename(hostname: str, run_id: int, suffix: str = ".html") -> str:
    return f"{safe_filename(hostname)}-{run_id}{suffix}"
