"""The FastAPI application. Routes only: no SQL, no pipeline, no thresholds.

Every route is a thin translation between an HTTP request and a call into
:mod:`slap.core`, plus one call into :mod:`slap_web.viewmodel` to shape the
result. If a route grows a condition about what a number *means*, that
condition belongs in the view model or the core, not here.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from slap import core
from slap.config import Settings

from . import viewmodel as vm
from .activity import ActivityManager

HERE = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(title="SLAP", docs_url=None, redoc_url=None)
    app.state.settings = settings
    activity = ActivityManager(settings)
    app.state.activity = activity

    templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def page(request: Request, name: str, **context) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=name,
            context={"nav": name.split(".")[0],
                     "activity": activity.snapshot(), **context},
        )

    @app.get("/", response_class=HTMLResponse)
    def sites(request: Request) -> HTMLResponse:
        rows = core.list_sites(settings)
        # One history read per site. Fine at this scale (tens of sites) and
        # honest: if it ever hurts, it becomes one grouped query in the core,
        # not a cache here.
        histories = {
            s["id"]: core.get_site_detail(settings, s["id"])["history"]
            for s in rows
        }
        sites_view = vm.build_site_rows(rows, histories)
        return page(
            request, "sites.html.j2",
            sites=sites_view,
            total_open=sum(s.open_count for s in sites_view),
            audited_today=sum(1 for s in sites_view if s.audited == "today"),
            clients=len({s.client for s in sites_view if s.client}),
        )

    @app.get("/site/{site_id}", response_class=HTMLResponse)
    def site_detail(request: Request, site_id: int) -> HTMLResponse:
        detail = core.get_site_detail(settings, site_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="No such site")

        latest = detail["latest"]
        score = detail["observations"].get("lh.score.performance")
        status, word = vm.score_status(score)
        # Group the operator's finding lists by rule for the same reason the
        # client report does: twenty pages produce a few hundred rows
        # describing a dozen problems.
        pages_total = max(1, len(detail.get("pages") or []))
        return page(
            request, "site.html.j2",
            pages=detail.get("pages") or [],
            pages_total=pages_total,
            site=detail["site"],
            latest=latest,
            runs=detail["runs"],
            score=int(round(score)) if score is not None else None,
            score_status=status,
            score_word=word,
            tiles=vm.build_tiles(detail["observations"]),
            trend=vm.build_trend(detail["history"]),
            field_trend=vm.build_field_trend(detail.get("field_history") or {}),
            open_findings=vm.decorate_findings(detail["open"], pages_total=pages_total),
            fixed_findings=vm.decorate_findings(detail["fixed"], pages_total=pages_total),
            new_findings=vm.decorate_findings(detail["new"], pages_total=pages_total),
            humanise=vm.humanise,
        )

    @app.get("/findings", response_class=HTMLResponse)
    def findings(request: Request) -> HTMLResponse:
        data = core.findings_across_sites(settings)
        return page(
            request, "findings.html.j2",
            rules=vm.decorate_findings(data["rules"]),
            total_sites=data["total_sites"],
        )

    # ----------------------------------------------------------------
    # Report preview.
    #
    # Served in an iframe rather than inlined. report.css declares its own
    # :root tokens and is written for a 190mm print page; dropping it into
    # this document would have the two stylesheets fight, and the point of
    # a preview is to show EXACTLY what the client receives.
    # ----------------------------------------------------------------
    @app.get("/run/{run_id}", response_class=HTMLResponse)
    def run_preview(request: Request, run_id: int) -> HTMLResponse:
        detail = core.get_run_detail(settings, run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="No such run")
        pages = detail.get("pages") or []
        scores = {
            row["page_id"]: row["numeric_value"]
            for row in detail["observations"]
            if row["metric_key"] == "lh.score.performance"
        }
        page_rows = vm.build_page_rows(pages, scores)
        return page(
            request, "run.html.j2",
            run=detail["run"],
            findings=vm.decorate_findings(detail["findings"],
                                          pages_total=max(1, len(page_rows))),
            observation_count=len(detail["observations"]),
            pages=page_rows,
            measured=sum(1 for r in page_rows if r["measured"]),
            pdf_backend=core.pdf_backend_status(),
            branding=settings.branding,
            humanise=vm.humanise,
        )

    @app.get("/run/{run_id}/report.html", response_class=HTMLResponse)
    def run_report_html(run_id: int) -> HTMLResponse:
        """The report itself, for the iframe. Rendered, never cached."""
        from slap import report

        detail = core.get_run_detail(settings, run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="No such run")
        return HTMLResponse(
            report.render_report_html(detail, branding=settings.branding)
        )

    @app.post("/run/{run_id}/export")
    def run_export(run_id: int, pdf: str = Form(default="")) -> RedirectResponse:
        result = core.export_report(settings, run_id, pdf=bool(pdf))
        app.state.last_export = result
        return RedirectResponse(f"/run/{run_id}?exported=1", status_code=303)

    @app.post("/branding")
    def set_branding(company_name: str = Form(default=""),
                     accent: str = Form(default=""),
                     run_id: int = Form(default=0)) -> RedirectResponse:
        # In memory for now. Persisting to config.toml is its own decision:
        # the file is user-owned and round-tripping TOML without destroying
        # their comments needs more than tomllib, which is read-only.
        settings.branding = {
            k: v for k, v in
            {"company_name": company_name.strip(), "accent": accent.strip()}.items()
            if v
        }
        return RedirectResponse(f"/run/{run_id}" if run_id else "/", status_code=303)

    # ----------------------------------------------------------------
    # Activity: starting audits, and streaming progress.
    #
    # Progress is a state, not a place. A 24-site batch with Lighthouse on
    # is roughly 40 minutes, so it lives in a dock every page carries
    # rather than a screen the operator is held on.
    # ----------------------------------------------------------------
    @app.post("/audit")
    def start_audit(urls: str = Form(default=""),
                    site_id: str = Form(default=""),
                    lighthouse: str = Form(default="")) -> RedirectResponse:
        targets = [u for u in urls.replace(",", "\n").splitlines() if u.strip()]
        if site_id:
            site = core.get_site_detail(settings, int(site_id))
            if site and site["runs"]:
                # Re-audit the URL actually measured last time, not the bare
                # hostname: the port and path matter and a hostname alone
                # would silently audit a different page.
                last = core.get_run_detail(settings, site["runs"][0]["id"])
                observed = last["observations"][0]["url"] if last["observations"] else None
                targets.append(observed or site["site"]["hostname"])
        settings.lighthouse.enabled = bool(lighthouse)
        started, message = activity.start(targets)
        app.state.last_message = message
        return RedirectResponse(request_back(site_id), status_code=303)

    def request_back(site_id: str) -> str:
        return f"/site/{site_id}" if site_id else "/"

    @app.post("/audit/cancel")
    def cancel_audit() -> RedirectResponse:
        activity.cancel()
        return RedirectResponse("/", status_code=303)

    @app.get("/activity")
    def activity_snapshot() -> dict:
        return activity.snapshot()

    @app.get("/activity/stream")
    def activity_stream() -> StreamingResponse:
        return StreamingResponse(
            activity.stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
