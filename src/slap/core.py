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
    ExposureCollector,
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
from .discovery import (
    DiscoveryResult,
    canonical_url,
    choose_lighthouse_pages,
    classify_template,
    discover,
)
from .findings import FindingsEngine
from .vulndb import VulnDatabase
from .schema import (
    AuditDepth,
    DiscoveredVia,
    FormFactor,
    PageResult,
    PageRole,
    RunStatus,
    Scope,
)


@dataclass(slots=True)
class SiteOutcome:
    url: str
    run_id: int | None
    ok: bool
    observations: int = 0
    findings: int = 0
    error: str | None = None
    #: Pages audited, and how many of them got the browser audit. Reported so
    #: a caller can say "12 pages, 4 measured" rather than implying that a
    #: number exists for every page.
    pages: int = 1
    lighthouse_pages: int = 0
    #: Discovered but not audited, because the cap bit. A cap that is applied
    #: and not stated reads as full coverage.
    pages_dropped: int = 0


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

def split_pipeline(pipeline: Pipeline) -> tuple[Pipeline, Pipeline, Pipeline]:
    """Separate the pipeline into three passes by what each collector needs.

    Per-page collection runs in passes because each one needs what the last
    produced:

    ``light``
        No browser. Fetches the document, reads headers, TLS, fingerprint and
        subresources. Runs on every discovered page.
    ``heavy``
        Lighthouse. Runs only on the sampled representatives, and it can only
        be sampled once the light pass has produced a template class per page.
    ``final``
        Collectors that consume what the others produced. Component detection
        is the case: its best version source is the browser's own reading of
        the running library, which does not exist until Lighthouse has run.

    Membership is declared by the collector (``needs_browser``, ``runs_last``)
    rather than inferred from stage position, because the pipeline is a
    caller-supplied list and a test that appends a stage would otherwise have
    its collector silently promoted into the Lighthouse pass.
    """
    light: Pipeline = []
    heavy: Pipeline = []
    final: Pipeline = []
    for stage in pipeline:
        last = [c for c in stage if getattr(c, "runs_last", False)]
        rest = [c for c in stage if not getattr(c, "runs_last", False)]
        browser = [c for c in rest if getattr(c, "needs_browser", False)]
        cheap = [c for c in rest if not getattr(c, "needs_browser", False)]
        if cheap:
            light.append(cheap)
        if browser:
            heavy.append(browser)
        if last:
            final.append(last)
    return light, heavy, final


def _applies_to(collector: Any, is_home: bool) -> bool:
    """Origin-scoped collectors run once per site, on the home page.

    One certificate serves every page and the CrUX collector queries the
    origin, so running them per page is N identical results, N handshakes and
    N times the API quota. Filtering the *observations* afterwards would be
    the same data at the same cost; filtering the collector is the point.
    """
    return is_home or getattr(collector, "scope", Scope.PAGE) is not Scope.ORIGIN


async def collect_page(ctx: PageContext, pipeline: Pipeline, *,
                       bus: EventBus, batch_id: str,
                       cancel: CancelToken,
                       is_home: bool = True,
                       result: PageResult | None = None) -> PageResult:
    """Run every stage of the pipeline against one URL.

    ``result`` lets a second pass accumulate into the page built by the first,
    so the Lighthouse observations land on the same PageResult as the HTTP
    ones instead of arriving as a separate page.
    """
    if result is None:
        result = PageResult(url=ctx.url, form_factor=FormFactor.NONE)

    for stage_index, stage in enumerate(pipeline):
        cancel.raise_if_cancelled()
        stage = [c for c in stage if _applies_to(c, is_home)]
        if not stage:
            continue

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
        #
        # `stage` is rebound above by the scope filter, so identity against
        # pipeline[0] no longer holds; compare the index instead. Getting this
        # wrong does not raise, it just stops skipping the rest of a failed
        # page's collectors, which is how "no HSTS header" ends up on a host
        # that never answered.
        if ctx.document is None and stage_index == 0:
            result.errors.append("fetch failed; skipping remaining collectors")
            break

    if ctx.document is not None:
        result.final_url = ctx.document.final_url
    result.errors.extend(ctx.errors)
    result.extras.update(ctx.extras)
    return result


def _persist(conn: sqlite3.Connection, *, batch_id: str, url: str,
             results: list[PageResult], engine: FindingsEngine,
             discovery: DiscoveryResult | None = None,
             vuln_db: VulnDatabase | None = None) -> SiteOutcome:
    """Write one site's run and every page under it, in a single transaction.

    One transaction for the whole site, not one per page. A site audit is
    atomic history: a batch cancelled halfway through a twelve-page site
    should leave no run at all rather than a run that silently covers four
    pages and reads as complete.
    """
    hostname = httpx.URL(url).host
    n_obs = 0
    n_findings = 0
    lighthouse_pages = 0

    with db.transaction(conn):
        site_id = db.upsert_site(conn, hostname)
        run_id = db.create_run(
            conn, batch_id=batch_id, site_id=site_id,
            slap_version=__version__, schema_version=SCHEMA_VERSION,
        )

        provenance: dict[str, Any] = {}
        for result in results:
            page_id = db.create_page(
                conn, run_id, result.url, result.final_url, result.form_factor,
                role=result.role, discovered_via=result.discovered_via,
                audit_depth=result.audit_depth,
                template_class=result.template_class,
            )
            n_obs += db.insert_observations(conn, page_id, result.observations)

            # CrUX history is a time series, which the observation table
            # cannot hold: it is one row per week per metric, keyed by origin
            # rather than by this run. It goes to its own table, where two
            # audits a week apart share 24 of their 25 periods instead of
            # storing them twice.
            history = result.extras.get("crux_history")
            if history:
                db.insert_crux_history(
                    conn, history["origin"], history["form_factor"],
                    history["points"])

            # Lighthouse hands back things observations cannot carry: the
            # gzipped LHR blobs and the engine versions that make a run
            # reproducible.
            lighthouse = result.extras.get("lighthouse")
            if lighthouse is not None:
                lighthouse_pages += 1
                for artifact in lighthouse.artifacts:
                    db.insert_artifact(
                        conn, run_id, kind=artifact.kind, path=str(artifact.path),
                        page_id=page_id, sha256=artifact.sha256, size=artifact.bytes,
                    )
                # Engine versions are a property of the machine and the
                # session, so every page of a run agrees on them and the first
                # page to report them wins. The CPU benchmark does NOT agree
                # across pages, which is why it is a per-page observation and
                # not run provenance.
                meta = lighthouse.meta or {}
                for key in ("lighthouseVersion", "chromeVersion", "throttlingProfile"):
                    if meta.get(key) and key not in provenance:
                        provenance[key] = meta[key]

            # Do NOT derive findings from an empty observation set. Many rules
            # fire on `missing: true`, so a page we could not fetch would
            # otherwise report "No HSTS header", "No Content-Security-Policy",
            # and so on. Confidently describing a page we never reached is the
            # fastest way to get an entire report dismissed. Per page now, so
            # one unreachable page in twelve does not poison the other eleven.
            if result.observations:
                values = {o.metric_key: o.value for o in result.observations}
                n_findings += db.insert_findings(conn, page_id, engine.run(values))

        if provenance:
            db.set_run_provenance(
                conn, run_id,
                lh_version=provenance.get("lighthouseVersion"),
                chrome_version=provenance.get("chromeVersion"),
                throttling_profile=provenance.get("throttlingProfile"),
            )

        # A run failed when it learned nothing at all. One page of twelve
        # failing is a finding about that page, not a failed audit.
        #
        # Counted BEFORE the discovery metadata is written, and that ordering
        # is load-bearing. Attaching "discovery.method = manual" to an
        # unreachable host puts a row in `observation` and makes `n_obs`
        # non-zero, so the run reports completed, the findings engine runs
        # against an empty value set, and the report tells a client that a
        # host we never reached has no HSTS header. That is the failure this
        # project's oldest guard exists to prevent, and metadata is exactly
        # the shape of thing that walks around it.
        failed = n_obs == 0

        if results and not failed:
            home_id = db.home_page_id(conn, run_id)
            if home_id is not None:
                metadata: list[Any] = []
                if discovery is not None:
                    metadata += _discovery_observations(discovery, len(results))
                if vuln_db is not None:
                    metadata += _vulndb_observations(vuln_db)
                if metadata:
                    db.insert_observations(conn, home_id, metadata)

        errors = [e for r in results for e in r.errors]
        db.finish_run(
            conn, run_id,
            RunStatus.FAILED if failed else RunStatus.COMPLETED,
            error="; ".join(errors) if errors else None,
        )

    return SiteOutcome(
        url=url, run_id=run_id, ok=not failed,
        observations=n_obs, findings=n_findings,
        error="; ".join(errors) if errors else None,
        pages=len(results), lighthouse_pages=lighthouse_pages,
        pages_dropped=discovery.dropped if discovery else 0,
    )


def _vulndb_observations(vuln_db: VulnDatabase) -> list["Observation"]:
    """How old the vulnerability data is, and what it covers.

    Printed in the appendix beside the Lighthouse and Chrome versions. A
    bundle built once and run for a year carries a year-old database, and a
    report that does not say so is wrong in a way nobody can detect.
    """
    from .schema import obs

    if not vuln_db.available:
        return [obs("vuln.db_sources", "none configured")]
    out = [obs("vuln.db_sources", ", ".join(
        f"{k} ({v})" for k, v in sorted(vuln_db.sources.items())))]
    if vuln_db.generated_at:
        out.append(obs("vuln.db_generated", vuln_db.generated_at))
    age = vuln_db.age_days
    if age is not None:
        out.append(obs("vuln.db_age_days", age))
    return out


def _discovery_observations(found: DiscoveryResult,
                            audited: int) -> list["Observation"]:
    """Record how the page list was arrived at, and what it left out.

    These ride on the home page because observations are page-keyed and the
    facts are origin-scoped. They exist so the report can print "12 of 3,400
    pages audited" instead of "12 pages audited", which is the difference
    between a stated cap and an implied claim of full coverage.
    """
    from .schema import obs

    out = [
        obs("discovery.method", found.method.value),
        obs("discovery.found", found.found),
        obs("discovery.audited", audited),
        obs("discovery.dropped", found.dropped),
    ]
    if found.sitemaps:
        out.append(obs("discovery.sitemap_urls", ", ".join(found.sitemaps[:10])))
    return out


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

    # Loaded once per batch, not per page. Never raises: a missing database
    # degrades to "not checked", which the report states, rather than to a
    # failed audit.
    vuln_db = VulnDatabase.load(settings.vulndb_path)
    if settings.probe_enabled:
        authorised = frozenset(db.authorised_probe_hosts(conn))
        prober = ExposureCollector(
            enabled=True, rate_per_second=settings.probe_rate_per_second,
            authorised_hosts=authorised)
        bus.log(batch_id, "Endpoint probing enabled for {} authorised host(s)".format(
            len(authorised)), "warning")
    else:
        prober = None

    pipeline = pipeline or default_pipeline(bucket, runner, vuln_db=vuln_db,
                                            exposure=prober)
    light_pipeline, heavy_pipeline, final_pipeline = split_pipeline(pipeline)

    disc_cfg = settings.discovery

    # Concurrency is two-dimensional now, and both dimensions have to be
    # bounded explicitly. `http_concurrency` used to bound sites and pages at
    # once because a site was one page; with twenty pages per site the naive
    # version is 20 x 20 = 400 concurrent requests. The connection pool would
    # cap that at `http_concurrency * 2` and the batch would not fall over, it
    # would just serialise unpredictably behind the pool, which is worse than
    # failing because it looks like it works.
    semaphore = asyncio.Semaphore(max(1, cfg.http_concurrency))
    page_semaphore = asyncio.Semaphore(max(1, disc_cfg.page_concurrency))
    counter = {"done": 0}
    total = len(targets)

    # Sized for the real ceiling: sites x pages in flight, not sites alone.
    # An undersized pool is invisible in tests and shows up as a slow batch.
    peak = max(1, cfg.http_concurrency * max(1, disc_cfg.page_concurrency))
    limits = httpx.Limits(
        max_connections=peak * 2,
        max_keepalive_connections=peak,
    )

    async with httpx.AsyncClient(
        timeout=cfg.timeout, verify=cfg.verify_tls, limits=limits,
        follow_redirects=True, max_redirects=cfg.max_redirects,
        http2=http2_available(),
    ) as client:

        async def collect_site(url: str) -> tuple[list[PageResult], DiscoveryResult | None]:
            """Discover, audit every page cheaply, then measure a sample.

            Two passes, because the decision the second pass needs is made
            from data only the first pass has: a page's template class is read
            from its fetched HTML, and the template classes are what decide
            which pages are worth ninety seconds of browser time.
            """
            home_url = canonical_url(url)
            found: DiscoveryResult | None = None
            urls = [home_url]

            if disc_cfg.enabled and disc_cfg.pages_per_site > 1:
                found = await discover(
                    client, url, cfg,
                    limit=disc_cfg.pages_per_site,
                    crawl_depth=disc_cfg.crawl_depth,
                    allow_crawl=disc_cfg.allow_crawl,
                )
                urls = found.urls or [home_url]
                for message in found.errors:
                    bus.log(batch_id, f"{home_url}: discovery {message}", "warning")
                if found.dropped:
                    bus.log(batch_id, "{}: {} pages found, auditing {}".format(
                        home_url, found.found, len(urls)), "warning")

            contexts: dict[str, PageContext] = {}
            results: dict[str, PageResult] = {}

            async def light(page_url: str) -> None:
                async with page_semaphore:
                    cancel.raise_if_cancelled()
                    is_home = page_url == home_url
                    ctx = PageContext(url=page_url, client=client, config=cfg)
                    contexts[page_url] = ctx
                    result = PageResult(url=page_url, form_factor=FormFactor.NONE)
                    result.role = PageRole.HOME if is_home else PageRole.DISCOVERED
                    result.discovered_via = (
                        DiscoveredVia.MANUAL if is_home or found is None
                        else found.method
                    )
                    result.audit_depth = AuditDepth.LIGHT
                    results[page_url] = result
                    try:
                        await collect_page(ctx, light_pipeline, bus=bus,
                                           batch_id=batch_id, cancel=cancel,
                                           is_home=is_home, result=result)
                    except BatchCancelled:
                        raise
                    except Exception as exc:      # noqa: BLE001
                        result.errors.append(f"{type(exc).__name__}: {exc}")
                    document = ctx.document
                    result.template_class = classify_template(
                        page_url, document.text if document else None,
                        is_home=is_home,
                    )

            await asyncio.gather(*(light(u) for u in urls))

            ordered = [results[u] for u in urls if u in results]

            # NO early return when the browser pass is absent.
            #
            # This used to `return ordered, found` when `heavy_pipeline` was
            # empty, which skipped the final pass along with it. Lighthouse is
            # opt-in, so that is the DEFAULT configuration: every audit
            # without `--lighthouse`, including every audit the web UI starts,
            # silently did no component detection and no CVE matching at all.
            # Nothing raised, the run completed, and the report said
            # "components were checked against OSV" having checked nothing.
            #
            # The two passes are independent: the browser pass needs pages to
            # measure, the final pass needs pages to read. Only the first is
            # conditional.

            # Only pages that were actually fetched can be measured, and only
            # one representative per template class is worth measuring.
            fetched = {r.url: r.template_class or "unknown"
                       for r in ordered
                       if r.observations and contexts.get(r.url, None)
                       and contexts[r.url].document is not None}
            chosen = choose_lighthouse_pages(
                fetched, limit=disc_cfg.lighthouse_pages_per_site,
                home_url=home_url if home_url in fetched else None,
            ) if heavy_pipeline else []

            async def heavy(page_url: str) -> None:
                async with page_semaphore:
                    cancel.raise_if_cancelled()
                    result = results[page_url]
                    result.audit_depth = AuditDepth.FULL
                    if result.role is not PageRole.HOME:
                        result.role = PageRole.TEMPLATE
                    try:
                        await collect_page(contexts[page_url], heavy_pipeline,
                                           bus=bus, batch_id=batch_id,
                                           cancel=cancel,
                                           is_home=page_url == home_url,
                                           result=result)
                    except BatchCancelled:
                        raise
                    except Exception as exc:      # noqa: BLE001
                        result.errors.append(f"{type(exc).__name__}: {exc}")

            await asyncio.gather(*(heavy(u) for u in chosen))

            # The final pass consumes what the other two produced: component
            # detection reads the browser's own view of the running libraries,
            # which does not exist until Lighthouse has finished. It runs on
            # every page, including the ones never measured, where it falls
            # back to the markup and says so.
            if final_pipeline:
                async def last(page_url: str) -> None:
                    async with page_semaphore:
                        cancel.raise_if_cancelled()
                        result = results[page_url]
                        try:
                            await collect_page(contexts[page_url], final_pipeline,
                                               bus=bus, batch_id=batch_id,
                                               cancel=cancel,
                                               is_home=page_url == home_url,
                                               result=result)
                        except BatchCancelled:
                            raise
                        except Exception as exc:      # noqa: BLE001
                            result.errors.append(f"{type(exc).__name__}: {exc}")

                await asyncio.gather(*(last(r.url) for r in ordered
                                       if r.url in contexts
                                       and contexts[r.url].document is not None))
            return ordered, found

        async def audit(url: str, index: int) -> SiteOutcome:
            async with semaphore:
                cancel.raise_if_cancelled()
                bus.emit(SiteStarted(batch_id=batch_id, url=url,
                                     index=index, total=total))
                found: DiscoveryResult | None = None
                try:
                    pages, found = await collect_site(url)
                except BatchCancelled:
                    raise
                except Exception as exc:
                    page = PageResult(url=url)
                    page.errors.append(f"{type(exc).__name__}: {exc}")
                    pages = [page]

                # Persist synchronously, on purpose. `conn` belongs to this
                # thread and sqlite3 connections are thread-affine, so an
                # asyncio.to_thread here would hand the handle to a worker
                # thread and raise "created in a different thread". The call
                # has no await inside it, which also makes it atomic with
                # respect to the event loop: no second writer can interleave.
                outcome = _persist(conn, batch_id=batch_id, url=url,
                                   results=pages, engine=engine,
                                   discovery=found, vuln_db=vuln_db)

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
    """Everything one report needs about one run, in a single call.

    ``observations`` is every page's, and ``home_values`` is the home page's
    alone. Both are needed and they are not interchangeable: the verdict, the
    TLS section and the technology fingerprint describe the site and must come
    from one page, while the appendix and the per-page sections want the lot.

    Flattening *all* observations into one dict is the trap here. It reads
    fine, renders fine, and silently reports whichever page happened to be
    written last, so a site verdict would change depending on which product
    page sorted highest.
    """
    conn = _conn(settings)
    run = db.get_run(conn, run_id)
    if run is None:
        return None
    home_id = db.home_page_id(conn, run_id)
    values = db.observations_as_dict(conn, home_id) if home_id else {}

    # The field-data series is keyed by ORIGIN, not by this run, so it is
    # fetched separately rather than joined: the same 25 weeks back every
    # audit of the same site, which is the point of storing it once.
    origin = origin_for(values, run.get("hostname"))
    history = field_history_for(conn, origin)

    return {
        "run": run,
        "observations": db.get_observations(conn, run_id),
        "findings": db.get_findings(conn, run_id),
        "pages": db.run_pages(conn, run_id),
        "home_page_id": home_id,
        "home_values": values,
        "crux_history": history,
        "origin": origin,
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


#: The three metrics a field-data chart ever plots.
FIELD_METRICS: tuple[str, ...] = ("crux.lcp.p75", "crux.inp.p75", "crux.cls.p75")


def origin_for(values: dict[str, Any], hostname: str | None) -> str | None:
    """The origin an audit stored its field history under.

    Derived from the final URL the audit actually reached, because that is
    what the collector used. Rebuilding it from the hostname instead drops
    the port, so a site on anything but 80 or 443 stores under
    ``http://host:8080`` and is looked up under ``http://host`` — which
    returns nothing and renders as "this site has no field data".

    Shared by the run detail and the site detail rather than written twice:
    the two came apart immediately when they were, and the symptom was
    silence rather than an error.
    """
    final_url = values.get("redirect.final_url")
    if final_url:
        parsed = httpx.URL(final_url)
        netloc = parsed.netloc.decode() if isinstance(parsed.netloc, bytes) \
            else str(parsed.netloc)
        if netloc:
            return f"{parsed.scheme}://{netloc}"
    return f"https://{hostname}" if hostname else None


def field_history_for(conn: sqlite3.Connection,
                      origin: str | None) -> dict[str, list[dict[str, Any]]]:
    if not origin:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for metric_key in FIELD_METRICS:
        series = db.crux_history(conn, origin, metric_key)
        if series:
            out[metric_key] = series
    return out


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

    # The home page's observations, not "whichever page came back first".
    # `LIMIT 1` with no ORDER BY was correct while a run held exactly one page
    # and became a coin toss the moment it held twenty: the site's headline
    # score and CWV tiles would come from an arbitrary product page, and
    # change between runs for no reason a reader could see.
    latest_values = (
        db.observations_as_dict(conn, db.home_page_id(conn, latest["id"]) or 0)
        if latest else {}
    )
    return {
        "site": site,
        "runs": runs,
        "latest": latest,
        "previous": previous,
        "history": db.site_metric_history(conn, site_id, TREND_METRICS),
        "observations": latest_values,
        "pages": db.run_pages(conn, latest["id"]) if latest else [],
        # Real-user history, keyed by origin rather than by any of these
        # runs. On a site audited once this is still 25 weeks deep, which
        # the run-derived trend beside it cannot be until next spring.
        "field_history": field_history_for(
            conn, origin_for(latest_values, site["hostname"])),
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
