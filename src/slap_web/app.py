"""The FastAPI application. Routes only: no SQL, no pipeline, no thresholds.

Every route is a thin translation between an HTTP request and a call into
:mod:`slap.core`, plus one call into :mod:`slap_web.viewmodel` to shape the
result. If a route grows a condition about what a number *means*, that
condition belongs in the view model or the core, not here.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from slap import core
from slap.config import Settings

from . import viewmodel as vm
from .activity import ActivityManager
from .jobs import DatabaseUpdate

HERE = Path(__file__).resolve().parent

#: The page served after quitting (and its two refusal variants). A plain
#: string, not a template: the base layout's scripts poll the server, and
#: this page outlives it.
_QUIT_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>SLAP</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; display: grid;
         place-items: center; min-height: 90vh; color: #333; }}
  main {{ text-align: center; }}
  h1 {{ font-size: 20px; }}
</style></head>
<body><main><h1>{title}</h1><p>{body}</p></main></body></html>"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(title="SLAP", docs_url=None, redoc_url=None)
    app.state.settings = settings
    activity = ActivityManager(settings)
    app.state.activity = activity
    database_update = DatabaseUpdate(settings)
    app.state.database_update = database_update
    #: Set by the launcher to a callable that stops the server. None
    #: everywhere else (tests, the verify checks), where there is no server
    #: to stop -- and the Quit button hides itself accordingly.
    app.state.shutdown = None

    templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def page(request: Request, name: str, **context) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=name,
            context={"nav": name.split(".")[0],
                     "activity": activity.snapshot(),
                     "can_quit": app.state.shutdown is not None, **context},
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
            # The real path, because "the report directory" answered a
            # question nobody asked while the actual question was "where?".
            report_dir=str(settings.report_dir),
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

    @app.get("/run/{run_id}/download/{kind}")
    def run_download(run_id: int, kind: str) -> FileResponse:
        """Export and hand the file to the browser as a download.

        This replaced a POST that wrote into the app's data directory and
        flashed "Written to the report directory." In a browser that is a
        button that appears to do nothing: no download, no link, and a
        directory the user has never seen named only by its role. The
        deliverable of a click in a browser arrives through the browser.

        The on-disk copy is still written first, to the same reports
        directory as always, because that archive is what the CLI, the
        batch exports and "find me the report from March" all rely on. The
        run page now prints that directory's real path instead of alluding
        to it.
        """
        if kind not in ("html", "pdf"):
            raise HTTPException(status_code=404, detail="html or pdf")
        if core.get_run_detail(settings, run_id) is None:
            raise HTTPException(status_code=404, detail="No such run")

        result = core.export_report(settings, run_id, pdf=(kind == "pdf"))
        if kind == "pdf":
            if not result.pdf_path:
                # The HTML was still written; say why the PDF was not.
                raise HTTPException(
                    status_code=503,
                    detail=result.pdf_error or "no PDF backend available")
            path, media = result.pdf_path, "application/pdf"
        else:
            path, media = result.html_path, "text/html"
        return FileResponse(path, media_type=media, filename=path.name)

    # ----------------------------------------------------------------
    # Settings. The one place configuration is edited, and the seam rule
    # holds: persistence and the live key test are core functions
    # (`core.save_crux_api_key`, `core.check_crux_key`); this layer only
    # translates a form post.
    # ----------------------------------------------------------------
    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request) -> HTMLResponse:
        import os

        from slap import config as config_module

        return page(
            request, "settings.html.j2",
            crux_masked=vm.mask_key(settings.collector.crux_api_key),
            env_override=bool(os.environ.get("CRUX_API_KEY")),
            key_check=getattr(app.state, "key_check", None),
            key_error=getattr(app.state, "key_error", None),
            config_path=str(settings.config_path
                            or config_module.default_data_dir() / "config.toml"),
            db_path=str(settings.db_path),
            report_dir=str(settings.report_dir),
            vulndb_path=str(settings.vulndb_path),
            pdf_backend=core.pdf_backend_status(),
            totals=core.history_totals(settings),
            clear_result=getattr(app.state, "clear_result", None),
            clear_error=getattr(app.state, "clear_error", None),
            probe_hosts=core.probe_authorisations(settings),
            probe=vm.probe_state(settings.probe_enabled,
                                 core.probe_authorisations(settings)),
            probe_error=getattr(app.state, "probe_error", None),
            probe_note=getattr(app.state, "probe_note", None),
            humanise=vm.humanise,
            # What `slap doctor` used to print. It was a command, which
            # meant the only way to find out why a report was thin was to
            # open a terminal that this application does not have.
            backends=core.backend_status(settings),
            vulndb=core.vulndb_status(settings),
            update=database_update.snapshot(),
            audit_defaults=core.audit_defaults(settings),
            defaults_error=getattr(app.state, "defaults_error", None),
            defaults_note=getattr(app.state, "defaults_note", None),
        )

    @app.post("/settings/audit-defaults")
    async def save_audit_defaults(request: Request) -> RedirectResponse:
        # The raw form rather than Form() parameters: the fields are named
        # "discovery.pages_per_site" and a dot cannot be a Python argument
        # name. Async only to await the body; the saves below are a few
        # hundred bytes of file IO.
        form = await request.form()
        app.state.defaults_error = None
        app.state.defaults_note = None
        changed = 0
        for row in core.audit_defaults(settings):
            field = f"{row['section']}.{row['key']}"
            if field not in form or str(form[field]) == str(row["value"]):
                continue
            try:
                core.save_audit_default(settings, row["section"], row["key"],
                                        form[field])
            except ValueError as exc:
                app.state.defaults_error = str(exc)
                return RedirectResponse("/settings", status_code=303)
            changed += 1
        app.state.defaults_note = (
            f"{changed} setting{'' if changed == 1 else 's'} saved. They "
            "apply to the next audit." if changed else "Nothing changed.")
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/vulndb/update")
    def update_vulndb(source: str = Form(default="nvd")) -> RedirectResponse:
        started, message = database_update.start(source)
        app.state.defaults_error = None if started else message
        app.state.defaults_note = message if started else None
        return RedirectResponse("/settings", status_code=303)

    @app.get("/settings/vulndb/progress")
    def vulndb_progress() -> dict:
        """Polled by the settings page while a refresh runs.

        A keyless NVD refresh is about five minutes, which is far past any
        browser's patience for a form post; the button starts a background
        job and the page watches it here.
        """
        return database_update.snapshot()

    @app.get("/rules", response_class=HTMLResponse)
    def rules(request: Request) -> HTMLResponse:
        """Every rule the findings engine will apply, as a page.

        The rules are data, not code, and this is the screen that makes
        that true for somebody who is not reading YAML: what SLAP checks
        for, what it will say, and what it will recommend, before it is
        said to a client.
        """
        from slap.findings import RuleError

        try:
            found = core.list_rules(settings)
            error = None
        except RuleError as exc:
            found, error = [], str(exc)
        return page(request, "rules.html.j2",
                    rules=vm.group_rules(found), total=len(found), error=error)

    # ----------------------------------------------------------------
    # Endpoint probing. Two separate switches, deliberately: the global
    # one below, and a recorded authorisation per host. Neither alone
    # probes anything, which is the whole design -- a single flag gets
    # switched on once for a client who agreed and then silently applies
    # to the next one, who did not.
    # ----------------------------------------------------------------
    @app.post("/settings/probe")
    def set_probing(enabled: str = Form(default="")) -> RedirectResponse:
        app.state.probe_error = None
        core.set_probe_enabled(settings, bool(enabled))
        app.state.probe_note = (
            "Probing switched on. It still only touches hosts authorised "
            "below." if enabled else "Probing switched off.")
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/probe/authorise")
    def authorise_probing(hostname: str = Form(default=""),
                          by: str = Form(default=""),
                          note: str = Form(default="")) -> RedirectResponse:
        app.state.probe_error = None
        app.state.probe_note = None
        try:
            host = core.authorise_probe(settings, hostname, by=by, note=note)
        except ValueError as exc:
            app.state.probe_error = str(exc)
        else:
            app.state.probe_note = f"Probing authorised for {host}."
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/probe/revoke")
    def revoke_probing(hostname: str = Form(default="")) -> RedirectResponse:
        app.state.probe_error = None
        found = core.revoke_probe(settings, hostname)
        app.state.probe_note = (f"Authorisation withdrawn for {hostname}."
                                if found else
                                f"{hostname} was not authorised.")
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/clear-history")
    def clear_history(confirm: str = Form(default="")) -> RedirectResponse:
        """Delete all audit history, after the operator typed the word.

        The confirmation is checked HERE, not only in the browser: a JS
        confirm() can be clicked through in half a second and disappears
        entirely when someone scripts the endpoint. Typing "delete" is the
        smallest act that cannot happen by accident.

        Refused while a batch is running, because wiping tables under a
        writer mid-transaction turns "fresh start" into "corrupted run that
        looks like a bug next week".
        """
        app.state.clear_result = None
        app.state.clear_error = None
        if activity.snapshot()["running"]:
            app.state.clear_error = ("An audit is running. Stop it first; "
                                     "clearing history under a live batch "
                                     "corrupts the run being written.")
        elif confirm.strip().lower() != "delete":
            app.state.clear_error = ('Not cleared: type "delete" in the '
                                     "confirmation box to confirm.")
        else:
            app.state.clear_result = core.clear_history(settings).text
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/crux")
    def save_crux(key: str = Form(default="")) -> RedirectResponse:
        """Save (or clear) the key, then test what was saved.

        Saving and testing are one action on purpose: the key this page
        exists for was valid, well-formed, and rejected on every request by
        its own API restrictions. A page that said "saved" and stopped
        would have called that key configured.
        """
        app.state.key_error = None
        app.state.key_check = None
        try:
            core.save_crux_api_key(settings, key)
        except ValueError as exc:
            app.state.key_error = str(exc)
            return RedirectResponse("/settings", status_code=303)
        if settings.collector.crux_api_key:
            app.state.key_check = core.check_crux_key(settings)
        return RedirectResponse("/settings", status_code=303)

    @app.post("/settings/crux/test")
    def test_crux() -> RedirectResponse:
        """Re-test the stored key without retyping it. Keys do not expire so
        much as get their restrictions edited; this answers "is it still
        good" in one click."""
        app.state.key_error = None
        app.state.key_check = core.check_crux_key(settings)
        return RedirectResponse("/settings", status_code=303)

    @app.post("/quit", response_class=HTMLResponse)
    def quit_app() -> HTMLResponse:
        """Stop the server, which for the bundle means quit the app.

        The distributable is a windowed executable: no console, no window of
        its own, nothing in the taskbar. Closing the browser tab closes the
        VIEW of the app and leaves the process running invisibly forever;
        before this button, quitting meant Task Manager. That is the same
        class of bug as the export button that wrote to a directory nobody
        could see: the app must be operable entirely from the page it shows.

        Refused while a batch is running, for the same reason clearing
        history is: a batch deserves an explicit Stop, not a quit that
        doubles as one. The goodbye page is self-contained on purpose --
        extending base.html.j2 would ship the activity-stream script, which
        would poll a server that no longer exists.
        """
        if activity.snapshot()["running"]:
            return HTMLResponse(_QUIT_PAGE.format(
                title="An audit is running",
                body="Stop it first (the Stop button in the dock), then "
                     'quit. <a href="/">Back to SLAP</a>'), status_code=409)
        if app.state.shutdown is None:
            return HTMLResponse(_QUIT_PAGE.format(
                title="Nothing to quit",
                body="This instance is not running as the packaged app. "
                     "Stop it however it was started."), status_code=503)
        app.state.shutdown()
        return HTMLResponse(_QUIT_PAGE.format(
            title="SLAP has stopped",
            body="The application has quit. You can close this tab."))

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
