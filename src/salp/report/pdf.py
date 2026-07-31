"""HTML to PDF via Playwright's pinned Chromium.

Chosen over WeasyPrint because teammates run this on Windows, where
WeasyPrint needs GTK/Pango DLLs installed out of band. Chosen over driving
whatever Chrome happens to be installed because a client-facing document
should not silently change layout between one teammate's machine and
another's, and because ``--headless --print-to-pdf`` gives no control over
running headers, footers, or page numbers.

The cost is one setup step per machine, so the error raised when it has
not been done names the exact two commands rather than surfacing a
Playwright traceback.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

SETUP_HINT = (
    'Install the PDF backend with:\n'
    '    pip install "salp[report]"\n'
    "    playwright install chromium"
)

DEFAULT_MARGIN = {"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"}


class PdfError(RuntimeError):
    """PDF rendering is unavailable or failed."""


@dataclass(frozen=True, slots=True)
class BackendStatus:
    """Whether PDF export will work. A settings screen can render this."""

    available: bool
    detail: str

    def __bool__(self) -> bool:
        return self.available


def check_backend() -> BackendStatus:
    """Probe for Playwright and its Chromium without launching a browser."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        return BackendStatus(False, f"Playwright is not installed.\n{SETUP_HINT}")

    # Actually launch. Checking that the executable file exists is not
    # enough: it reported healthy while export failed, because Playwright
    # was launching a *different* binary (the headless shell) than the one
    # being stat-ed. A status check that can disagree with the real code
    # path is worse than no status check.
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            path = p.chromium.executable_path
            browser = p.chromium.launch(channel="chromium")
            try:
                version = browser.version
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        message = str(exc).strip().splitlines()[0] if str(exc).strip() else str(exc)
        return BackendStatus(
            False, f"Chromium could not be launched: {message}\n{SETUP_HINT}"
        )

    if not path or not Path(path).exists():
        return BackendStatus(
            False,
            "Playwright is installed but its Chromium is missing.\n"
            "    playwright install chromium",
        )
    return BackendStatus(True, f"Chromium {version} at {path}")


def _header_template(title: str) -> str:
    # Playwright's header/footer live in their own document: they inherit no
    # page CSS and default to font-size 0, so every property is set inline.
    return (
        '<div style="font-family: system-ui, -apple-system, \'Segoe UI\', sans-serif;'
        ' font-size:7.5pt; color:#898781; width:100%; padding:0 14mm;'
        ' display:flex; justify-content:space-between;">'
        f'<span>{title}</span>'
        "</div>"
    )


def _footer_template(left: str) -> str:
    return (
        '<div style="font-family: system-ui, -apple-system, \'Segoe UI\', sans-serif;'
        ' font-size:7.5pt; color:#898781; width:100%; padding:0 14mm;'
        ' display:flex; justify-content:space-between;">'
        f'<span>{left}</span>'
        '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>'
        "</div>"
    )


async def html_file_to_pdf_async(html_path: str | Path, pdf_path: str | Path, *,
                                 title: str = "Site audit",
                                 footer_left: str = "",
                                 margin: dict[str, str] | None = None,
                                 paper_format: str = "Letter") -> Path:
    """Render an HTML file to PDF. Await this from inside an event loop."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise PdfError(f"Playwright is not installed.\n{SETUP_HINT}") from exc

    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        async with async_playwright() as p:
            # channel="chromium" selects the FULL Chromium build. Without
            # it, Playwright launches `chromium_headless_shell`, a separate
            # ~320MB download that exists only for headless work. Using the
            # full build means one browser serves both PDF export and the
            # Lighthouse runner, so a bundled distributable ships one copy
            # instead of two.
            browser = await p.chromium.launch(channel="chromium")
            try:
                page = await browser.new_page()
                await page.goto(html_path.as_uri(), wait_until="load")
                # Chromium applies screen media by default when scripting the
                # PDF; force print so the @media print rules actually apply.
                await page.emulate_media(media="print")
                await page.pdf(
                    path=str(pdf_path),
                    format=paper_format,
                    print_background=True,           # or every badge prints white
                    display_header_footer=True,
                    header_template=_header_template(title),
                    footer_template=_footer_template(footer_left),
                    margin=margin or DEFAULT_MARGIN,
                    prefer_css_page_size=False,
                )
            finally:
                await browser.close()
    except PdfError:
        raise
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "Executable doesn't exist" in message or "playwright install" in message:
            # Keep the original text. An earlier version replaced it with a
            # flat "Chromium is not installed", which was actively wrong
            # when Chromium *was* installed and Playwright was reaching for
            # the headless shell instead. The path in Playwright's message
            # is the entire diagnosis; never throw it away.
            raise PdfError(
                "Chromium could not be launched.\n"
                "    playwright install chromium\n\n"
                f"Playwright reported:\n{message.strip()}"
            ) from exc
        raise PdfError(f"PDF rendering failed: {message}") from exc

    return pdf_path


def html_file_to_pdf(html_path: str | Path, pdf_path: str | Path, **kwargs) -> Path:
    """Synchronous wrapper. Do not call from inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(html_file_to_pdf_async(html_path, pdf_path, **kwargs))
    raise PdfError(
        "html_file_to_pdf() was called from inside a running event loop; "
        "await html_file_to_pdf_async() instead."
    )


def merge_pdfs(paths: list[str | Path], output: str | Path) -> Path:
    """Concatenate per-site PDFs into one file, in the order given."""
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError as exc:
        raise PdfError(
            'Merging needs pypdf. Install it with: pip install "salp[report]"'
        ) from exc

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    writer = PdfWriter()
    for path in paths:
        reader = PdfReader(str(path))
        for page in reader.pages:
            writer.add_page(page)
    with output.open("wb") as handle:
        writer.write(handle)
    return output
