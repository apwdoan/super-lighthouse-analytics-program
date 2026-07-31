"""The core API. Every front-end calls exactly this and nothing below it.

The CLI in :mod:`slap.cli` and the PySide6 GUI planned for Phase 2 are both
clients of this module. Nothing here imports Qt, argparse, or a template
engine; if a front-end ever needs to reach past this file into
:mod:`slap.db` or :mod:`slap.collectors`, that is the signal that a
function is missing here rather than that the rule should be bent.

Threading contract for the GUI:

* :class:`BatchWorker` owns a thread with its own asyncio event loop.
  Qt's loop is never involved, so a slow TLS handshake cannot jank the UI.
* Progress arrives via :class:`~slap.events.EventBus`. The GUI attaches a
  ``QueueSink`` and drains it from the main thread on a ``QTimer``.
* :meth:`BatchWorker.cancel` is safe to call from the Qt main thread.
* Every database write happens on the worker thread; the GUI's reads use
  its own thread-local connection. WAL mode keeps them out of each
  other's way.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

import httpx

from . import SCHEMA_VERSION, __version__, db
from .collectors import (
    CollectorConfig,
    LighthouseError,
    LighthouseRunner,
    PageContext,
    Pipeline,
    TokenBucket,
    default_pipeline,
    normalize_url,
)
from .collectors.http_probe import http2_available
from .config import Settings
from .events import (
    BatchCancelled,
    BatchFinished,
    BatchStarted,
    CancelToken,
    CollectorFinished,
    CollectorStarted,
    EventBus,
    SiteFinished,
    SiteStarted,
)
from .findings import FindingsEngine
from .schema import FormFactor, PageResult, RunStatus


@dataclass(slots=True)
class SiteOutcome:
    url: str
    run_id: int | None
    ok: bool
    observations: int = 0
    findings: int = 0
    error: str | None = None


@dataclass(slots=True)
class BatchResult:
    batch_id: str
    outcomes: list[SiteOutcome] = field(default_factory=list)
    cancelled: bool = False

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def succeeded(self) -> int:
        return sum(1 for o in self.outcomes if o.ok)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if not o.ok)

    @property
    def run_ids(self) -> list[int]:
        # Outcomes arrive in completion order, which is not insertion order.
        return sorted(o.run_id for o in self.outcomes if o.run_id is not None)


def new_batch_id() -> str:
    return uuid.uuid4().hex[:12]


def prepare_urls(raw: Iterable[str]) -> list[str]:
    """Normalize and de-duplicate a pasted list, preserving order.

    Accepts bare hostnames, blank lines, and ``#`` comments, because the
    GUI's input box and a text file are the same thing to this function.
    """
    seen: set[str] = set()
    out: list[str] = []
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            url = normalize_url(line)
        except ValueError:
            continue
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

async def collect_page(ctx: PageContext, pipeline: Pipeline, *,
                       bus: EventBus, batch_id: str,
                       cancel: CancelToken) -> PageResult:
    """Run every stage of the pipeline against one URL."""
    result = PageResult(url=ctx.url, form_factor=FormFactor.NONE)

    for stage in pipeline:
        cancel.raise_if_cancelled()

        async def run_one(collector: Any) -> None:
            bus.emit(CollectorStarted(
                batch_id=batch_id, url=ctx.url, collector=collector.name,
            ))
            try:
                observations = await collector.collect(ctx)
            except Exception as exc:  # one bad collector must not lose the rest
                message = f"{type(exc).__name__}: {exc}"
                result.errors.append(f"{collector.name}: {message}")
                bus.emit(CollectorFinished(
                    batch_id=batch_id, url=ctx.url, collector=collector.name,
                    ok=False, error=message,
                ))
                return
            result.extend(observations)
            bus.emit(CollectorFinished(
                batch_id=batch_id, url=ctx.url, collector=collector.name,
                observations=len(observations),
            ))

        await asyncio.gather(*(run_one(c) for c in stage))

        # The first stage is what establishes the document. If it produced
        # nothing at all, later stages have nothing to work with.
        if ctx.document is None and stage is pipeline[0]:
            result.errors.append("fetch failed; skipping remaining collectors")
            break

    if ctx.document is not None:
        result.final_url = ctx.document.final_url
    result.errors.extend(ctx.errors)
    result.extras.update(ctx.extras)
    return result


def _persist(conn: sqlite3.Connection, *, batch_id: str, url: str,
             result: PageResult, engine: FindingsEngine) -> SiteOutcome:
    """Write one page's run, observations, and findings in a single transaction."""
    hostname = httpx.URL(url).host
    with db.transaction(conn):
        site_id = db.upsert_site(conn, hostname)
        run_id = db.create_run(
            conn, batch_id=batch_id, site_id=site_id,
            slap_version=__version__, schema_version=SCHEMA_VERSION,
        )
        page_id = db.create_page(conn, run_id, url, result.final_url, result.form_factor)
        n_obs = db.insert_observations(conn, page_id, result.observations)

        # Lighthouse hands back things observations cannot carry: the gzipped
        # LHR blobs and the engine versions that make a run reproducible.
        lighthouse = result.extras.get("lighthouse")
        if lighthouse is not None:
            for artifact in lighthouse.artifacts:
                db.insert_artifact(
                    conn, run_id, kind=artifact.kind, path=str(artifact.path),
                    page_id=page_id, sha256=artifact.sha256, size=artifact.bytes,
                )
            meta = lighthouse.meta or {}
            db.set_run_provenance(
                conn, run_id,
                lh_version=meta.get("lighthouseVersion"),
                chrome_version=meta.get("chromeVersion"),
                throttling_profile=meta.get("throttlingProfile"),
            )

        failed = not result.observations

        # Do NOT derive findings from an empty observation set. Many rules
        # fire on `missing: true`, so a site we could not connect to would
        # otherwise report "No HSTS header", "No Content-Security-Policy",
        # and so on. Confidently describing a site we never reached is the
        # fastest way to get an entire report dismissed.
        n_findings = 0
        if not failed:
            values = {o.metric_key: o.value for o in result.observations}
            n_findings = db.insert_findings(conn, page_id, engine.run(values))

        db.finish_run(
            conn, run_id,
            RunStatus.FAILED if failed else RunStatus.COMPLETED,
            error="; ".join(result.errors) if result.errors else None,
        )

    return SiteOutcome(
        url=url, run_id=run_id, ok=not failed,
        observations=n_obs, findings=n_findings,
        error="; ".join(result.errors) if result.errors else None,
    )


async def run_batch(urls: Iterable[str], settings: Settings, *,
                    bus: EventBus | None = None,
                    cancel: CancelToken | None = None,
                    batch_id: str | None = None,
                    pipeline: Pipeline | None = None) -> BatchResult:
    """Audit every URL and persist the results. The one entry point.

    Safe to call from any thread that owns an event loop. The CLI awaits it
    directly; the GUI goes through :class:`BatchWorker`.
    """
    bus = bus or EventBus()
    cancel = cancel or CancelToken()
    batch_id = batch_id or new_batch_id()
    settings.ensure_dirs()

    targets = prepare_urls(urls)
    result = BatchResult(batch_id=batch_id)
    bus.emit(BatchStarted(batch_id=batch_id, total=len(targets)))
    if not targets:
        bus.emit(BatchFinished(batch_id=batch_id, total=0))
        return result

    conn = db.init_db(settings.db_path)
    engine = FindingsEngine.load(settings.rules_path)
    cfg: CollectorConfig = settings.collector
    bucket = TokenBucket(cfg.crux_rate_per_second)

    runner: LighthouseRunner | None = None
    if pipeline is None and settings.lighthouse.enabled:
        runner = LighthouseRunner(
            settings.lighthouse,
            artifact_dir=settings.artifact_dir / batch_id,
        )
        ok, detail = runner.check()
        if not ok:
            # Do not fail the batch: the Phase 1 collectors are still worth
            # running, and the report says which engine produced it.
            bus.log(batch_id, f"Lighthouse disabled: {detail}", "warning")
            runner = None
        else:
            try:
                versions = await runner.probe()
                bus.log(batch_id, "Lighthouse {lighthouseVersion}, Chrome {chromeVersion}, "
                        "{n} run(s) per site at concurrency {c}".format(
                            n=settings.lighthouse.runs,
                            c=settings.lighthouse.concurrency, **versions))
            except LighthouseError as exc:
                bus.log(batch_id, f"Lighthouse disabled: {exc}", "warning")
                runner = None

    pipeline = pipeline or default_pipeline(bucket, runner)

    semaphore = asyncio.Semaphore(max(1, cfg.http_concurrency))
    counter = {"done": 0}
    total = len(targets)

    limits = httpx.Limits(
        max_connections=cfg.http_concurrency * 2,
        max_keepalive_connections=cfg.http_concurrency,
    )

    async with httpx.AsyncClient(
        timeout=cfg.timeout, verify=cfg.verify_tls, limits=limits,
        follow_redirects=True, max_redirects=cfg.max_redirects,
        http2=http2_available(),
    ) as client:

        async def audit(url: str, index: int) -> SiteOutcome:
            async with semaphore:
                cancel.raise_if_cancelled()
                bus.emit(SiteStarted(batch_id=batch_id, url=url,
                                     index=index, total=total))
                ctx = PageContext(url=url, client=client, config=cfg)
                try:
                    page = await collect_page(ctx, pipeline, bus=bus,
                                              batch_id=batch_id, cancel=cancel)
                except BatchCancelled:
                    raise
                except Exception as exc:
                    page = PageResult(url=url)
                    page.errors.append(f"{type(exc).__name__}: {exc}")

                # Persist synchronously, on purpose. `conn` belongs to this
                # thread and sqlite3 connections are thread-affine, so an
                # asyncio.to_thread here would hand the handle to a worker
                # thread and raise "created in a different thread". The call
                # has no await inside it, which also makes it atomic with
                # respect to the event loop: no second writer can interleave.
                outcome = _persist(conn, batch_id=batch_id, url=url,
                                   result=page, engine=engine)

                counter["done"] += 1
                bus.emit(SiteFinished(
                    batch_id=batch_id, url=url, run_id=outcome.run_id or 0,
                    index=counter["done"], total=total,
                    observations=outcome.observations, findings=outcome.findings,
                    ok=outcome.ok, error=outcome.error,
                ))
                return outcome

        tasks = [asyncio.create_task(audit(u, i + 1)) for i, u in enumerate(targets)]
        try:
            for completed in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(completed, BatchCancelled):
                    result.cancelled = True
                elif isinstance(completed, BaseException):
                    result.outcomes.append(
                        SiteOutcome(url="?", run_id=None, ok=False,
                                    error=f"{type(completed).__name__}: {completed}")
                    )
                else:
                    result.outcomes.append(completed)
        finally:
            for task in tasks:
                task.cancel()

    if cancel.cancelled:
        result.cancelled = True

    bus.emit(BatchFinished(
        batch_id=batch_id, total=total, succeeded=result.succeeded,
        failed=result.failed, cancelled=result.cancelled,
    ))
    return result


# --------------------------------------------------------------------------
# The Qt-facing wrapper
# --------------------------------------------------------------------------

class BatchWorker:
    """Runs a batch on a background thread with its own event loop.

    This is the class the PySide6 GUI drives::

        worker = BatchWorker(urls, settings)
        sink = worker.bus.queue_sink()
        worker.start()
        # ... QTimer drains sink on the main thread, emits Qt signals ...
        worker.cancel()          # safe from the GUI thread
        worker.wait(timeout=30)
    """

    def __init__(self, urls: Iterable[str], settings: Settings, *,
                 bus: EventBus | None = None,
                 batch_id: str | None = None) -> None:
        self.urls = list(urls)
        self.settings = settings
        self.bus = bus or EventBus()
        self.batch_id = batch_id or new_batch_id()
        self.cancel_token = CancelToken()
        self._thread: threading.Thread | None = None
        self._done = threading.Event()
        self._result: BatchResult | None = None
        self._error: BaseException | None = None

    def start(self) -> "BatchWorker":
        if self._thread is not None:
            raise RuntimeError("BatchWorker already started")
        self._thread = threading.Thread(
            target=self._run, name=f"slap-batch-{self.batch_id}", daemon=True
        )
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            self._result = asyncio.run(run_batch(
                self.urls, self.settings, bus=self.bus,
                cancel=self.cancel_token, batch_id=self.batch_id,
            ))
        except BaseException as exc:  # noqa: BLE001 - surfaced via result()
            self._error = exc
        finally:
            # Connections are thread-local; this thread is about to die.
            db.close_thread_connections()
            self._done.set()

    def cancel(self) -> None:
        """Request cancellation. Safe to call from the Qt main thread."""
        self.cancel_token.cancel()

    @property
    def finished(self) -> bool:
        return self._done.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    def result(self) -> BatchResult:
        if not self._done.is_set():
            raise RuntimeError("batch is still running")
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result


# --------------------------------------------------------------------------
# Reads. The GUI's models call these; it never writes SQL itself.
# --------------------------------------------------------------------------

def _conn(settings: Settings) -> sqlite3.Connection:
    return db.init_db(settings.db_path)


def list_batches(settings: Settings, limit: int = 50) -> list[dict[str, Any]]:
    return db.list_batches(_conn(settings), limit)


def list_runs(settings: Settings, *, batch_id: str | None = None,
              limit: int = 200) -> list[dict[str, Any]]:
    return db.list_runs(_conn(settings), batch_id=batch_id, limit=limit)


def get_run(settings: Settings, run_id: int) -> dict[str, Any] | None:
    return db.get_run(_conn(settings), run_id)


def get_run_detail(settings: Settings, run_id: int) -> dict[str, Any] | None:
    """Everything one report needs about one run, in a single call."""
    conn = _conn(settings)
    run = db.get_run(conn, run_id)
    if run is None:
        return None
    return {
        "run": run,
        "observations": db.get_observations(conn, run_id),
        "findings": db.get_findings(conn, run_id),
    }


# --------------------------------------------------------------------------
# Site-centric reads
#
# The UI is organised around the site, not the batch. These live here rather
# than in the front end because of the rule that has held all project: if a
# front-end needs to reach past salp.core, the core is missing a function.
# The web layer never opens a database or writes SQL.
# --------------------------------------------------------------------------

#: What a trend line is drawn from. Lab score first because it is the only
#: one present on every run; the CrUX metrics need field data to exist.
TREND_METRICS: tuple[str, ...] = (
    "lh.score.performance", "lh.lcp", "crux.lcp.p75", "crux.inp.p75",
)


def list_sites(settings: Settings, limit: int = 500) -> list[dict[str, Any]]:
    """Every site with its most recent completed run summarised onto it."""
    return db.list_sites(_conn(settings), limit)


def _rule_ids(findings: Iterable[dict[str, Any]]) -> set[str]:
    return {f["rule_id"] for f in findings}


def get_site_detail(settings: Settings, site_id: int) -> dict[str, Any] | None:
    """One site over time: trend, runs, and findings split open vs fixed.

    The open/fixed split is a set difference on ``rule_id`` between the
    latest completed run and the one before it. Deliberately rule ids and
    not titles: a title carries a formatted number ("Images could load 3.9s
    faster") that moves between runs, so comparing titles would report every
    improved finding as simultaneously fixed and newly discovered.

    ``fixed`` is therefore "present last time, absent now", which is the
    claim a client cares about and the one the immutable-run design can
    actually support.
    """
    conn = _conn(settings)
    site = db.get_site(conn, site_id)
    if site is None:
        return None

    runs = db.site_runs(conn, site_id)
    completed = [r for r in runs if r["status"] == "completed"]
    latest = completed[0] if completed else None
    previous = completed[1] if len(completed) > 1 else None

    current = db.get_findings(conn, latest["id"]) if latest else []
    prior = db.get_findings(conn, previous["id"]) if previous else []

    current_ids, prior_ids = _rule_ids(current), _rule_ids(prior)
    return {
        "site": site,
        "runs": runs,
        "latest": latest,
        "previous": previous,
        "history": db.site_metric_history(conn, site_id, TREND_METRICS),
        "observations": (
            db.observations_as_dict(
                conn,
                conn.execute("SELECT id FROM page WHERE run_id = ? LIMIT 1",
                             (latest["id"],)).fetchone()["id"],
            ) if latest else {}
        ),
        "open": current,
        "new": [f for f in current if previous and f["rule_id"] not in prior_ids],
        "fixed": [f for f in prior if f["rule_id"] not in current_ids],
    }


def findings_across_sites(settings: Settings,
                          limit: int = 200) -> dict[str, Any]:
    """Every open finding grouped by rule, plus how many sites it affects.

    The screen this feeds turns one fix into a portfolio-wide conversation,
    and it is a single query against data that has been stored since Phase
    0. It only looked expensive because the UI was organised around batches.
    """
    conn = _conn(settings)
    rules = db.findings_across_sites(conn, limit)
    total = db.count_sites_with_a_completed_run(conn)
    for rule in rules:
        rule["hosts"] = (rule.pop("hostnames") or "").split(",")
        rule["share"] = (rule["site_count"] / total) if total else 0.0
    return {"rules": rules, "total_sites": total}


def find_site(settings: Settings, hostname: str) -> dict[str, Any] | None:
    return db.find_site_by_hostname(_conn(settings), hostname)


def close_connections() -> None:
    """Release this thread's SQLite handles. Call from a GUI's closeEvent."""
    db.close_thread_connections()


# --------------------------------------------------------------------------
# Report export
#
# HTML is written first and always; the PDF is a rendering of that file, per
# the roadmap. So a failure in the PDF backend never costs the user the
# report, and the HTML on disk is exactly what the PDF contains.
# --------------------------------------------------------------------------

@dataclass(slots=True)
class ExportResult:
    run_id: int
    hostname: str
    html_path: Path
    pdf_path: Path | None = None
    pdf_error: str | None = None


@dataclass(slots=True)
class BatchExportResult:
    batch_id: str
    index_html: Path
    index_pdf: Path | None = None
    sites: list[ExportResult] = field(default_factory=list)
    merged_pdf: Path | None = None
    pdf_error: str | None = None

    @property
    def pdf_paths(self) -> list[Path]:
        paths = [self.index_pdf] if self.index_pdf else []
        return paths + [s.pdf_path for s in self.sites if s.pdf_path]


def pdf_backend_status() -> "report.BackendStatus":
    """Whether PDF export will work here. Render this in a settings screen."""
    from . import report

    return report.check_backend()


def _report_paths(settings: Settings, hostname: str, run_id: int,
                  out_dir: Path | None) -> tuple[Path, Path]:
    from . import report

    directory = Path(out_dir) if out_dir else settings.report_dir
    stem = f"{report.safe_filename(hostname)}-{run_id}"
    return directory / f"{stem}.html", directory / f"{stem}.pdf"


def render_report(settings: Settings, run_id: int, *,
                  out_dir: Path | str | None = None,
                  out_path: Path | str | None = None) -> Path:
    """Write the HTML report for one run and return its path."""
    from . import report

    detail = get_run_detail(settings, run_id)
    if detail is None:
        raise ValueError(f"no run with id {run_id}")

    settings.ensure_dirs()
    html = report.render_report_html(detail, branding=settings.branding)
    if out_path:
        target = Path(out_path)
    else:
        target, _ = _report_paths(
            settings, detail["run"]["hostname"], run_id,
            Path(out_dir) if out_dir else None,
        )
    return report.write_html(html, target)


async def export_report_async(settings: Settings, run_id: int, *,
                              pdf: bool = True,
                              out_dir: Path | str | None = None) -> ExportResult:
    """Render one run's report, optionally to PDF. Awaitable variant."""
    from . import report

    detail = get_run_detail(settings, run_id)
    if detail is None:
        raise ValueError(f"no run with id {run_id}")

    hostname = detail["run"]["hostname"]
    html_path, pdf_path = _report_paths(
        settings, hostname, run_id, Path(out_dir) if out_dir else None
    )
    settings.ensure_dirs()
    report.write_html(
        report.render_report_html(detail, branding=settings.branding), html_path
    )

    result = ExportResult(run_id=run_id, hostname=hostname, html_path=html_path)
    if not pdf:
        return result

    try:
        result.pdf_path = await report.html_file_to_pdf_async(
            html_path, pdf_path,
            title=f"Site audit: {hostname}",
            footer_left=f"Audit reference {run_id}",
        )
    except report.PdfError as exc:
        # The HTML is already on disk, so this degrades rather than fails.
        result.pdf_error = str(exc)
    return result


def export_report(settings: Settings, run_id: int, *, pdf: bool = True,
                  out_dir: Path | str | None = None) -> ExportResult:
    """Render one run's report, optionally to PDF.

    Call from a thread with no running event loop (a plain CLI call, or a
    ``QRunnable`` in the GUI). Inside a loop, await
    :func:`export_report_async` instead.
    """
    return asyncio.run(export_report_async(settings, run_id, pdf=pdf, out_dir=out_dir))


async def export_batch_report_async(settings: Settings, batch_id: str, *,
                                    pdf: bool = True,
                                    per_site: bool = True,
                                    merge: bool = False,
                                    out_dir: Path | str | None = None
                                    ) -> BatchExportResult:
    """Render a batch index, and optionally every site's report under it."""
    from . import report

    runs = list_runs(settings, batch_id=batch_id, limit=10_000)
    if not runs:
        raise ValueError(f"no runs in batch {batch_id}")

    directory = Path(out_dir) if out_dir else settings.report_dir / f"batch-{batch_id}"
    directory.mkdir(parents=True, exist_ok=True)

    details = {r["id"]: get_run_detail(settings, r["id"]) for r in runs}
    index_html = report.write_html(
        report.render_batch_html(batch_id, runs, details, branding=settings.branding),
        directory / "index.html",
    )
    result = BatchExportResult(batch_id=batch_id, index_html=index_html)

    if pdf:
        try:
            result.index_pdf = await report.html_file_to_pdf_async(
                index_html, directory / "index.pdf",
                title="Batch audit summary",
                footer_left=f"Batch {batch_id}",
            )
        except report.PdfError as exc:
            result.pdf_error = str(exc)
            pdf = False  # do not retry per-site; the failure is systemic

    if per_site:
        for run in runs:
            result.sites.append(await export_report_async(
                settings, run["id"], pdf=pdf, out_dir=directory
            ))

    if merge and result.pdf_paths:
        result.merged_pdf = report.merge_pdfs(
            result.pdf_paths, directory / f"batch-{batch_id}.pdf"
        )
    return result


def export_batch_report(settings: Settings, batch_id: str, **kwargs) -> BatchExportResult:
    """Synchronous wrapper. See :func:`export_report` on loop context."""
    return asyncio.run(export_batch_report_async(settings, batch_id, **kwargs))


__all__ = [
    "BatchResult", "BatchWorker", "SiteOutcome", "run_batch", "prepare_urls",
    "new_batch_id", "list_batches", "list_runs", "get_run", "get_run_detail",
    "close_connections",
    "ExportResult", "BatchExportResult", "render_report", "export_report",
    "export_report_async", "export_batch_report", "export_batch_report_async",
    "pdf_backend_status",
]
