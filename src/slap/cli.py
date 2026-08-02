"""Command-line front-end.

Deliberately thin. Its job is to prove that :mod:`slap.core` is front-end
agnostic before the PySide6 GUI is written: this file drives a batch
through exactly the same :class:`~slap.core.BatchWorker` and event bus the
GUI will use, including cancellation. If a feature needs something the CLI
cannot express through the core API, the core API is what needs fixing.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import httpx

from . import __version__, bundle, config, core, db
from .config import Settings
from .events import BatchFinished, CollectorFinished, Event, SiteFinished
from .findings import FindingsEngine, RuleError

_SEVERITY_COLOURS = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[90m",
}
_RESET = "\033[0m"


def _supports_colour(stream: Any) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _paint(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_SEVERITY_COLOURS.get(severity, '')}{text}{_RESET}"


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------

def cmd_audit(args: argparse.Namespace, settings: Settings) -> int:
    urls: list[str] = list(args.urls)
    if args.file:
        urls.extend(Path(args.file).read_text(encoding="utf-8").splitlines())
    if not urls:
        print("No URLs given. Pass them as arguments or with --file.", file=sys.stderr)
        return 2

    if args.concurrency:
        settings.collector.http_concurrency = args.concurrency
    if args.lighthouse:
        settings.lighthouse.enabled = True
    if args.lh_runs:
        settings.lighthouse.runs = args.lh_runs
    if args.lh_concurrency:
        # Deliberately a separate flag from -c. Widening Lighthouse
        # concurrency to match HTTP concurrency is the contention mistake
        # that produces plausible, irreproducible scores.
        settings.lighthouse.concurrency = args.lh_concurrency
    if args.lh_desktop:
        settings.lighthouse.form_factors = ("mobile", "desktop")
    if getattr(args, "probe", False):
        settings.probe_enabled = True
    if args.no_discover:
        settings.discovery.enabled = False
    if args.pages:
        settings.discovery.pages_per_site = args.pages
    if args.lh_pages:
        settings.discovery.lighthouse_pages_per_site = args.lh_pages
    if args.page_concurrency:
        # Separate from -c for the same reason --lh-concurrency is: sites and
        # pages are two dimensions of fan-out and they multiply. Twenty sites
        # of twenty pages under one shared cap is 400 requests in flight.
        settings.discovery.page_concurrency = args.page_concurrency

    targets = core.prepare_urls(urls)
    if not targets:
        print("No usable URLs after normalization.", file=sys.stderr)
        return 2

    verbose = args.verbose

    def on_event(event: Event) -> None:
        if isinstance(event, CollectorFinished) and not verbose and event.ok:
            return
        print(event.message, flush=True)

    worker = core.BatchWorker(targets, settings)
    worker.bus.subscribe(on_event)
    worker.start()

    try:
        while not worker.wait(0.2):
            pass
    except KeyboardInterrupt:
        print("\nCancelling (finishing in-flight sites)...", flush=True)
        worker.cancel()
        worker.wait(30)

    result = worker.result()
    total_pages = sum(o.pages for o in result.outcomes)
    if total_pages > len(result.outcomes):
        measured = sum(o.lighthouse_pages for o in result.outcomes)
        dropped = sum(o.pages_dropped for o in result.outcomes)
        line = f"\n{total_pages} pages audited across {len(result.outcomes)} site(s)"
        if measured:
            line += f", {measured} measured with Lighthouse"
        # A cap applied and not stated reads as full coverage.
        if dropped:
            line += f"; {dropped} discovered page(s) not audited (--pages cap)"
        print(line)
    if result.run_ids:
        print(f"\nBatch {result.batch_id}: "
              f"run ids {result.run_ids[0]}-{result.run_ids[-1]}")
        print(f"Inspect one with:  slap show {result.run_ids[0]}")
    return 1 if result.failed and not result.succeeded else 0


# --------------------------------------------------------------------------
# reads
# --------------------------------------------------------------------------

def cmd_batches(args: argparse.Namespace, settings: Settings) -> int:
    rows = core.list_batches(settings, limit=args.limit)
    if not rows:
        print("No batches yet. Run:  slap audit example.com")
        return 0
    print(f"{'BATCH':<14} {'STARTED':<22} {'RUNS':>5} {'OK':>4} {'FAIL':>5}")
    for r in rows:
        print(f"{r['batch_id']:<14} {r['started_at']:<22} "
              f"{r['run_count']:>5} {r['completed'] or 0:>4} {r['failed'] or 0:>5}")
    return 0


def cmd_runs(args: argparse.Namespace, settings: Settings) -> int:
    rows = core.list_runs(settings, batch_id=args.batch, limit=args.limit)
    if not rows:
        print("No runs found.")
        return 0
    print(f"{'ID':>6}  {'HOST':<38} {'STATUS':<10} {'FINDINGS':>8}  STARTED")
    for r in rows:
        print(f"{r['id']:>6}  {r['hostname'][:38]:<38} {r['status']:<10} "
              f"{r['finding_count']:>8}  {r['started_at']}")
    return 0


def cmd_show(args: argparse.Namespace, settings: Settings) -> int:
    detail = core.get_run_detail(settings, args.run_id)
    if detail is None:
        print(f"No run with id {args.run_id}.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(detail, indent=2, default=str))
        return 0

    colour = _supports_colour(sys.stdout)
    run = detail["run"]
    print(f"\nRun {run['id']}  {run['hostname']}")
    print(f"  status     {run['status']}")
    print(f"  started    {run['started_at']}")
    print(f"  slap       {run['slap_version']} (schema v{run['schema_version']})")
    if run["error"]:
        print(f"  errors     {run['error']}")

    pages = detail.get("pages") or []
    if len(pages) > 1:
        measured = sum(1 for p in pages if p["audit_depth"] == "full")
        print(f"\nPages ({len(pages)}, {measured} measured)")
        for p in pages:
            path = p["url"].split("/", 3)[-1] if p["url"].count("/") > 2 else ""
            note = "" if p["audit_depth"] == "full" else "  not measured"
            print(f"  /{path:<40} {p['template_class'] or 'page':<12}"
                  f" {p['finding_count']:>3} issue(s){note}")

    # Grouped by rule, with the pages each affects. Ungrouped, a twenty-page
    # site prints a few hundred lines describing a dozen problems.
    #
    # `build_finding_views` rather than a grouping loop here, because the
    # first version of this WAS a grouping loop and it immediately drifted:
    # it printed "1 of 8 pages" for an invalid TLS certificate, which lives on
    # the home page only because storage is page-keyed and actually takes down
    # all eight. The model already knows that. Rule 7 again: the presentation
    # layer decides nothing the model can decide.
    from .report.model import build_finding_views

    total_pages = max(1, len(pages))
    views = build_finding_views(detail["findings"], pages_total=total_pages)
    print(f"\nIssues ({len(views)})")
    if not views:
        print("  Nothing fired. Either the site is clean or the rules need work.")
    for f in views:
        tag = _paint(f"[{f.severity.upper()}]", f.severity, colour)
        scope = f"  {f.scope_text.lower()}" if f.scope_text else ""
        print(f"  {tag} {f.title}{scope}")
        if args.verbose:
            print(f"      {f.detail}")
            if f.remediation:
                print(f"      Fix: {f.remediation}")
            if f.wp_rocket_setting:
                print(f"      WP Rocket: {f.wp_rocket_setting}")
            if not f.is_sitewide and total_pages > 1:
                for url in f.pages[:5]:
                    print(f"      on {url}")

    if args.observations:
        print(f"\nObservations ({len(detail['observations'])})")
        for o in detail["observations"]:
            value = o["numeric_value"] if o["numeric_value"] is not None else o["text_value"]
            if isinstance(value, str) and len(value) > 90:
                value = value[:87] + "..."
            unit = "" if o["unit"] in ("none", "bool") else f" {o['unit']}"
            print(f"  {o['metric_key']:<32} {value}{unit}")
    return 0


def _doctor_vulndb(settings: Settings) -> tuple[bool, str]:
    """The database is a backend like any other, and fails the same way.

    `doctor` exists because every failure mode here is "it silently did less
    than you think". A missing vulnerability database does not raise: every
    audit simply reports nothing, forever, and looks clean doing it.
    """
    from .vulndb import VulnDatabase

    database = VulnDatabase.load(settings.vulndb_path)
    if not database.available:
        return False, ("no vulnerability database at "
                       f"{settings.vulndb_path}. Run `slap vulndb update`. "
                       "Until then components are inventoried, not checked.")
    age = database.age_days
    detail = f"{database.count} advisories, {database.sources}"
    if age is not None:
        detail += f", {age} day(s) old"
        if age > 30:
            return False, detail + " -- stale, run `slap vulndb update`"
    return True, detail


def cmd_doctor(args: argparse.Namespace, settings: Settings) -> int:
    """Report on every optional backend, in one place.

    Exists because the failure modes here are all "it silently did less than
    you think": no CrUX key means no field data, no Lighthouse means no lab
    data, no Playwright means no PDF. Each degrades quietly by design, so
    there has to be somewhere that says so out loud.
    """
    from .collectors.lighthouse import LighthouseRunner, default_chrome_path

    ok_all = True

    def line(label: str, ok: bool, detail: str) -> None:
        nonlocal ok_all
        ok_all = ok_all and ok
        print(f"  [{'ok ' if ok else 'MISSING'}] {label}")
        for part in detail.splitlines():
            print(f"          {part}")

    print("SLAP backends\n")

    # Actually call CrUX rather than checking a key is set. A key can be
    # present, well-formed and rejected on every request, and the audit
    # then records crux.available: false while this line says ok.
    from .collectors.crux import check_key

    crux_ok, crux_detail = asyncio.run(check_key(settings.collector.crux_api_key))
    line("CrUX field data", crux_ok, crux_detail)

    runner = LighthouseRunner(settings.lighthouse)
    lh_ok, lh_detail = runner.check()
    if lh_ok:
        try:
            versions = asyncio.run(runner.probe())
            lh_detail = (f"Lighthouse {versions.get('lighthouseVersion')}, "
                         f"Chrome {versions.get('chromeVersion')}, "
                         f"Node {versions.get('node')}")
        except Exception as exc:  # noqa: BLE001
            lh_ok, lh_detail = False, str(exc)
    line("Lighthouse lab data", lh_ok, lh_detail)

    chrome = default_chrome_path()
    line("Chromium for measurement", bool(chrome),
         chrome or "No Chromium found. Run: playwright install chromium")

    status = core.pdf_backend_status()
    line("PDF export", bool(status), status.detail)

    vulndb_ok, vulndb_detail = _doctor_vulndb(settings)
    line("Vulnerability database", vulndb_ok, vulndb_detail)

    # Not a backend, but the same class of surprise: probing that is switched
    # on globally and authorised for nobody runs against nothing and looks
    # exactly like probing that found nothing.
    hosts = db.authorised_probe_hosts(db.init_db(settings.db_path))
    if settings.probe_enabled or hosts:
        detail = (f"{len(hosts)} host(s) authorised"
                  if hosts else "no host authorised; nothing will be probed")
        line("Endpoint probing", bool(hosts) and settings.probe_enabled,
             detail + ("" if settings.probe_enabled
                       else "; probe_enabled is false"))

    if bundle.is_frozen():
        # What the bundle actually resolved, printed unconditionally.
        #
        # A frozen build finds Node, the worker and Chromium through three
        # separate lookups, and a teammate reporting "Lighthouse says
        # missing" cannot tell you which one came back empty. This is the
        # first question anyone asks and it costs four lines to answer.
        print()
        print("  [bundle]")
        for key, value in bundle.describe().items():
            print(f"          {key + ':':<14}{value}")

    # Where output goes when there is nowhere for it to go. A user whose
    # bundle dies on launch sees a message box and nothing else; this is the
    # one line that turns "it just closes" into a traceback somebody can
    # read. Printed always, because the moment it is needed is the moment
    # the user cannot run `doctor` to find out.
    from .streams import attachment, default_log_path

    print()
    attached = attachment()
    print(f"  [log]   {default_log_path()}")
    print("          Written only when the app is launched with no console, "
          "which is")
    print("          what a double-click does."
          + ("  In use now." if attached and attached.attached else ""))

    if config.using_legacy_data_dir():
        # Not a failure, so it does not touch ok_all. But someone wondering
        # where their audits went should find the answer here rather than
        # by guessing at directory names.
        print()
        print(f"  [note] Using the pre-rename data directory: "
              f"{config.default_data_dir()}")
        print(f"          Database: {settings.db_path}")
        print( "          It is kept because it holds your run history and the")
        print( "          artifact paths recorded against it. To start fresh")
        print(f"          instead, create {config.data_dir_base() / config.DIRNAME}")
        print( "          and this note goes away.")

    print()
    print("All backends available." if ok_all else
          "Some backends are missing. SLAP still runs; the report will be "
          "narrower and will say so.")
    return 0 if ok_all else 1


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    if args.check:
        status = core.pdf_backend_status()
        print(("PDF export is available.\n  " if status else "PDF export is NOT available.\n")
              + status.detail)
        return 0 if status else 1

    if not args.batch and args.run_id is None:
        print("Give a run id, or --batch <id>. See: slap runs", file=sys.stderr)
        return 2

    want_pdf = not args.no_pdf
    opened: Path | None = None

    if args.batch:
        result = core.export_batch_report(
            settings, args.batch, pdf=want_pdf,
            per_site=not args.index_only, merge=args.merge,
            out_dir=args.out,
        )
        print(f"Batch {result.batch_id}: {len(result.sites)} site report(s)")
        print(f"  index  {result.index_html}")
        if result.index_pdf:
            print(f"  index  {result.index_pdf}")
        if result.merged_pdf:
            print(f"  merged {result.merged_pdf}")
        if result.pdf_error:
            print(f"\nPDF export unavailable, HTML was still written:\n{result.pdf_error}",
                  file=sys.stderr)
        failed = [s for s in result.sites if s.pdf_error]
        if failed and not result.pdf_error:
            print(f"\n{len(failed)} site PDF(s) failed: {failed[0].pdf_error}",
                  file=sys.stderr)
        opened = result.index_pdf or result.index_html
    else:
        result = core.export_report(
            settings, args.run_id, pdf=want_pdf, out_dir=args.out
        )
        print(f"{result.hostname} (run {result.run_id})")
        print(f"  html {result.html_path}")
        if result.pdf_path:
            print(f"  pdf  {result.pdf_path}")
        if result.pdf_error:
            print(f"\nPDF export unavailable, HTML was still written:\n{result.pdf_error}",
                  file=sys.stderr)
            opened = result.html_path
        else:
            opened = result.pdf_path or result.html_path

    if args.open and opened:
        import webbrowser

        webbrowser.open(Path(opened).resolve().as_uri())
    return 0


def cmd_rules(args: argparse.Namespace, settings: Settings) -> int:
    try:
        engine = FindingsEngine.load(args.path or settings.rules_path)
    except RuleError as exc:
        print(f"Rule file is invalid: {exc}", file=sys.stderr)
        return 1
    print(f"{len(engine.rules)} rule(s) loaded and valid.\n")
    for rule in engine.rules:
        print(f"  [{rule.severity.value:<8}] {rule.id:<28} {rule.title}")
    return 0


# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slap",
        description="Super Lighthouse Analytics Project: batch website auditing.",
    )
    parser.add_argument("--version", action="version", version=f"slap {__version__}")
    parser.add_argument("--config", help="path to config.toml")
    parser.add_argument("--db", help="override the SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("audit", help="audit one or more URLs")
    p.add_argument("urls", nargs="*", help="URLs or bare hostnames")
    p.add_argument("-f", "--file", help="file with one URL per line")
    p.add_argument("-c", "--concurrency", type=int, help="concurrent sites")
    p.add_argument("-v", "--verbose", action="store_true", help="show each collector")
    p.add_argument("-l", "--lighthouse", action="store_true",
                   help="also run Lighthouse (much slower: ~90s per site)")
    p.add_argument("--lh-runs", type=int, metavar="N",
                   help="Lighthouse runs per site to take the median of (default 3)")
    p.add_argument("--lh-concurrency", type=int, metavar="N",
                   help="concurrent Lighthouse runs (default 3; raising this "
                        "inflates TBT and TTI and makes scores irreproducible)")
    p.add_argument("--pages", type=int, metavar="N",
                   help="max pages to audit per site (default 20)")
    p.add_argument("--no-discover", action="store_true",
                   help="audit only the URL given, as before per-page analysis")
    p.add_argument("--lh-pages", type=int, metavar="N",
                   help="pages per site given the browser audit (default 5). "
                        "One per page template; ~90s each at concurrency 3")
    p.add_argument("--page-concurrency", type=int, metavar="N",
                   help="concurrent pages WITHIN one site (default 5). "
                        "Separate from -c: the two multiply")
    p.add_argument("--probe", action="store_true",
                   help="probe for exposed endpoints on AUTHORISED hosts only "
                        "(see `slap probe allow`)")
    p.add_argument("--lh-desktop", action="store_true",
                   help="also measure the desktop form factor")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("batches", help="list batches")
    p.add_argument("-n", "--limit", type=int, default=25)
    p.set_defaults(func=cmd_batches)

    p = sub.add_parser("runs", help="list runs")
    p.add_argument("-b", "--batch", help="filter to one batch id")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(func=cmd_runs)

    p = sub.add_parser("show", help="show one run's findings")
    p.add_argument("run_id", type=int)
    p.add_argument("-v", "--verbose", action="store_true", help="include detail and fixes")
    p.add_argument("-o", "--observations", action="store_true", help="dump raw observations")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("doctor", help="check every optional backend")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("report", help="export an HTML and PDF report")
    p.add_argument("run_id", nargs="?", type=int, help="run id to report on")
    p.add_argument("-b", "--batch", help="report on a whole batch instead")
    p.add_argument("-o", "--out", help="output directory")
    p.add_argument("--no-pdf", action="store_true", help="write HTML only")
    p.add_argument("--merge", action="store_true",
                   help="also concatenate the batch's PDFs into one file")
    p.add_argument("--index-only", action="store_true",
                   help="batch summary only, skip the per-site reports")
    p.add_argument("--open", action="store_true", help="open the result when done")
    p.add_argument("--check", action="store_true",
                   help="report whether the PDF backend is installed and exit")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("rules", help="validate and list the findings rules")
    p.add_argument("-p", "--path", help="alternate rules.yaml")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser(
        "verify",
        help="prove this build works: audits a page it serves itself, "
             "exports a PDF, and drives the web server")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-lighthouse", action="store_true",
                   help="skip the browser audit (much faster)")
    p.add_argument("--no-web", action="store_true", help="skip the web server")
    p.add_argument("--max-vulndb-age", type=int, metavar="DAYS",
                   help="fail if the vulnerability database is older than this")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("vulndb", help="the offline vulnerability database")
    p.add_argument("action", choices=["status", "update"], nargs="?",
                   default="status")
    p.set_defaults(func=cmd_vulndb)

    p = sub.add_parser(
        "probe",
        help="authorise endpoint probing for a host (off by default)")
    p.add_argument("action", choices=["list", "allow", "revoke"])
    p.add_argument("hostname", nargs="?")
    p.add_argument("--by", help="who authorised it (recorded)")
    p.add_argument("--note", help="reference for the authorisation, e.g. an SOW")
    p.set_defaults(func=cmd_probe)

    return parser


def cmd_verify(args: argparse.Namespace, settings: Settings) -> int:
    """Prove the build works, on any platform, from one place.

    Exists because this used to be two 145-line CI steps, one bash and one
    PowerShell, asserting the same things in different languages. Nothing
    stopped a check landing on only one of them.
    """
    import tempfile

    from . import verify as verify_module

    # A scratch database and report directory, so verifying never writes into
    # a teammate's real history. `slap verify` should be safe to run twice on
    # a machine that has audits worth keeping.
    with tempfile.TemporaryDirectory(prefix="slap-verify-") as scratch:
        root = Path(scratch)
        settings.db_path = root / "verify.sqlite3"
        settings.artifact_dir = root / "artifacts"
        settings.report_dir = root / "reports"
        settings.discovery.enabled = False       # one page is the point
        settings.collector.crux_api_key = None   # no network dependency

        # The web check lives in `slap_web`, because it drives uvicorn and
        # nothing under `slap/` may import a web framework. The CLI is the
        # seam that puts the two together.
        extra = []
        if not args.no_web:
            try:
                from slap_web.verify import check_headless_launch, check_web_server

                extra.extend([check_web_server, check_headless_launch])
            except ImportError:
                pass

        report = verify_module.verify(
            settings,
            lighthouse=not args.no_lighthouse,
            max_vulndb_age_days=args.max_vulndb_age,
            extra_checks=extra,
        )
        print(verify_module.render(report, as_json=args.json))
        core.close_connections()
    return 0 if report.ok else 1


def cmd_vulndb(args: argparse.Namespace, settings: Settings) -> int:
    from .vulndb import VulnDatabase, build_from_osv

    path = settings.vulndb_path
    if args.action == "status":
        db_ = VulnDatabase.load(path)
        print(f"\nVulnerability database  {path}")
        if not db_.available:
            print("  status     not present")
            print("  Run `slap vulndb update` to build it. Until then,")
            print("  components are inventoried and NOT checked, and the")
            print("  report says so rather than implying they are clean.")
            return 1
        age = db_.age_days
        print(f"  advisories {db_.count} across {len(db_.index)} packages")
        print(f"  generated  {db_.generated_at}"
              + (f"  ({age} day(s) ago)" if age is not None else ""))
        print(f"  sources    {', '.join(f'{k}: {v}' for k, v in db_.sources.items())}")
        # Stale data produces confidently out-of-date findings, which is the
        # same failure as a wrong version with a slower fuse.
        if age is not None and age > 30:
            print(f"  WARNING    {age} days old. Run `slap vulndb update`.")
        missing = [e for e in ("wordpress", "wordpress-plugin", "wordpress-theme")
                   if not db_.covers(e)]
        if missing:
            print(f"  not covered {', '.join(missing)}")
            print("             WPScan forbids caching its data and requires an")
            print("             Enterprise account for commercial use; Wordfence")
            print("             now requires credentials. Configure a source or")
            print("             these stay unchecked, and the report says so.")
        return 0

    print("Querying OSV for every library Lighthouse can identify...")
    seen = {"n": 0}

    def progress(i, package, message):
        seen["n"] = i
        print(f"  [{i:>3}] {package:<26} {message}", flush=True)

    # The existing database is the baseline: a package that had advisories
    # and now returns none is a failed query, not good news.
    database = build_from_osv(previous=VulnDatabase.load(path), progress=progress)
    if database.failures:
        print(f"\n{len(database.failures)} package(s) could not be queried: "
              f"{', '.join(database.failures[:8])}", file=sys.stderr)
        print("Refusing to write a database that is quietly smaller than the "
              "one it replaces. Try again; OSV rate-limits bursts.",
              file=sys.stderr)
        return 1
    if not database.available:
        # An empty result would overwrite good data with nothing, and the
        # next audit would report zero vulnerabilities and look clean.
        print("OSV returned no advisories. Keeping the existing database.",
              file=sys.stderr)
        return 1

    # NOT `settings.vulndb_path`: that resolves to whichever copy is newer,
    # which inside a frozen bundle is the bundled one. Writing there either
    # fails (Program Files, a signed .app) or succeeds and is silently
    # discarded by the next upgrade. `writable_vulndb_path` picks the
    # per-user copy when that is the case.
    destination = config.writable_vulndb_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(database.to_json(), encoding="utf-8")
    print(f"\n{database.count} advisories across {len(database.index)} packages")
    print(f"Written to {destination} "
          f"({destination.stat().st_size / 1024:.0f} KB)")
    if destination != path:
        print("This copy is used in preference to the bundled one while it "
              "is newer, and survives replacing the application.")
    return 0


def cmd_probe(args: argparse.Namespace, settings: Settings) -> int:
    """Authorisation for endpoint probing.

    A separate command, and per host, on purpose. Probing requests paths the
    site hopes are not there; that is a thing to do deliberately for a client
    who has agreed, not a flag that stays on and applies to whoever is audited
    next.
    """
    conn = db.init_db(settings.db_path)

    if args.action == "list":
        hosts = db.authorised_probe_hosts(conn)
        if not hosts:
            print("No host is authorised for endpoint probing.")
            return 0
        print(f"\n{len(hosts)} host(s) authorised for endpoint probing:")
        for hostname, row in sorted(hosts.items()):
            print(f"  {hostname:<34} {row['probe_authorised_at']}"
                  f"  by {row['probe_authorised_by'] or 'unknown'}")
            if row["probe_note"]:
                print(f"      {row['probe_note']}")
        return 0

    if not args.hostname:
        print("A hostname is required.", file=sys.stderr)
        return 2
    hostname = httpx.URL(core.normalize_url(args.hostname)).host

    if args.action == "revoke":
        found = db.revoke_probe(conn, hostname)
        conn.commit()
        print(f"Revoked for {hostname}." if found else f"{hostname} was not authorised.")
        return 0

    if not args.by:
        # Recorded, so "who turned this on" has an answer months later.
        print("--by is required: authorisation is recorded against a person.",
              file=sys.stderr)
        return 2
    db.authorise_probe(conn, hostname, by=args.by, note=args.note)
    conn.commit()
    print(f"Endpoint probing authorised for {hostname}.")
    print("It still needs `probe_enabled = true` in config.toml or --probe "
          "to actually run.")
    return 0


def main(argv: list[str] | None = None) -> int:
    # A no-op with a console, which is how the CLI is nearly always run. It
    # matters for the bundle: `SLAP.exe --cli ...` from a shortcut is a
    # windowed process with no streams, and argparse's own `--help` and
    # error paths write to stdout and stderr before any of our code runs.
    from .streams import attach_output

    attach_output()

    args = build_parser().parse_args(argv)
    settings = Settings.load(args.config)
    if args.db:
        settings.db_path = Path(args.db).expanduser()
    try:
        return int(args.func(args, settings))
    finally:
        core.close_connections()


if __name__ == "__main__":
    raise SystemExit(main())
