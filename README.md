# SLAP: Super Lighthouse Analytics Project

**Per-page** website performance and security auditing. Finds a site's pages,
audits each one, turns the result into findings a site owner will act on, and
renders a client-facing HTML and PDF report.

```
discovery  ──►  collectors  ──►  observations  ──►  findings  ──►  report
(sitemap,      (many, dumb,     (one schema,       (rules,       (grouped by
 crawl)         per page)        immutable)         tunable)      rule → PDF)
```

**Status: per-page analysis is built, and it packages into a self-contained
distributable teammates can run with nothing installed.** Schema frozen,
sitemap-and-crawl page discovery, no-browser collectors running on every
page, Lighthouse sampling one page per template against a pinned Chromium,
findings engine running off 50 YAML rules and reported once per rule with the
pages each affects, client-facing HTML and PDF reports rendering, and both
front-ends (CLI and a local web app) driving the same core. See `docs/per-page.md`, `docs/ui-redesign.md`, `docs/lighthouse.md`,
and `docs/reports.md`.

---

## Install

```bash
pip install -e ".[dev,all]"
playwright install chromium                    # PDF export and Lighthouse
slap doctor                                    # confirm every backend
```

Lighthouse itself installs from *inside* the worker directory:

```bash
cd src/slap/node_worker
npm install
```

**Do not use `npm install --prefix src/slap/node_worker`.** On Windows npm
ignores the prefix and reads the package.json in the current directory, so
it fails at the repo root with a confusing `ENOENT ... package.json`. The
bug is open ([npm/cli#7722](https://github.com/npm/cli/issues/7722)) and
does not reproduce on macOS or Linux, which is exactly what makes it easy
to ship. `packaging/build.py` and the CI workflow both run npm with a
working directory instead.

Extras: `report` (PDF), `web` (the app), `all` (both).

Node **>= 22.19** is required for the Lighthouse runner. Everything except
`pip install` is optional: without them SLAP still audits, and the report
says which engines produced it rather than pretending.

Requires Python 3.11+. The `httpx[http2]` extra is **not** optional: without
it, every site reports as HTTP/1.1 and the `no-http2` rule fires against
sites that are actually on HTTP/2.

Set a CrUX key to get real-user field data (free, 150 queries/minute):

```bash
export CRUX_API_KEY=...          # Windows: setx CRUX_API_KEY ...
```

Without a key the audit still runs; it just reports `crux.available: false`
and the report says so rather than pretending lab data is field data.

## Use

```bash
slap audit example.com another-site.com     # bare hostnames are fine
slap audit -f sites.txt -c 20               # one URL per line, 20 at a time
slap audit example.com --lighthouse         # add the lab audit (~90s/page)

slap audit example.com --pages 40           # audit up to 40 pages of the site
slap audit example.com --no-discover        # just the one URL, as before
slap audit example.com -l --lh-pages 8      # measure 8 page templates, not 5
slap audit example.com --page-concurrency 8 # pages in flight WITHIN one site
slap doctor                                 # which backends are available
slap batches                                # what has been run
slap runs -b <batch-id>                     # runs in a batch
slap show 42 -v                             # findings, with fixes
slap show 42 -o                             # plus raw observations
slap rules                                  # validate and list the rules

slap report 42 --open                       # HTML + PDF for one site
slap report -b <batch-id> --merge           # every site, plus one combined PDF
slap report --check                         # is the PDF backend installed?
```

Or run the app:

```bash
slap-web            # starts a local server and opens your browser
```

## Shipping it to someone

```bash
python packaging/build.py --zip
```

Produces `dist/SLAP/` (~700MB, ~300MB zipped) containing the Python runtime,
the app, Node, Lighthouse and Chromium. Double-clicking it starts a local
server and opens the default browser. A teammate unzips it and runs it;
they install nothing.

PyInstaller is not a cross-compiler, so build on the platform you are
shipping to. To get every target without owning every machine, run the
**Build distributables** workflow on GitHub: it builds Windows, macOS on
both Apple Silicon and Intel, and Linux natively, and each job runs the
bundle it just built before uploading it.

See `docs/packaging.md` for the size breakdown, Windows SmartScreen, and
macOS Gatekeeper.

## Per-page analysis

By default an audit covers the **whole site**, not just the URL you give it.

Pages come from `robots.txt` and the site's sitemap (including nested indexes
and gzipped `.xml.gz` shards), falling back to a shallow same-origin crawl.
Every discovered page gets the security, header, cookie and mixed-content
checks. Only a **sample** gets the browser performance audit: one page per
detected template, chosen by how many pages that template covers, because
Lighthouse costs ~90s per page against a concurrency cap of 3 and a client
acts on "product pages are slow", not on the 400th product page.

Two numbers control the cost:

| Flag | Default | What it bounds |
|---|---|---|
| `--pages` | 20 | pages audited per site |
| `--lh-pages` | 5 | pages given the browser audit |

Findings are reported **once per rule** with the pages they affect. Twenty
pages missing HSTS is one thing to fix, not twenty findings, and a report that
prints it twenty times buries the three that only affect checkout.

The report says what it did not cover. If a site publishes 3,400 pages and 20
were audited, it prints "20 of 3,400" — a cap that is applied and not stated
reads as full coverage. Pages without a performance score print "not measured"
rather than a blank cell, because a blank reads as a zero to some people and
as a pass to others.

Reports land in `report_dir` (per-user, under `%LOCALAPPDATA%\slap` on
Windows) unless you pass `-o`. The HTML is the artifact of record and the
PDF is a rendering of it, so if the PDF backend is missing you still get
the report and a message saying what to install.

Ctrl+C cancels cooperatively: in-flight sites finish and every run row
lands in a terminal state, so history is never left half-written.

## Layout

```
src/slap/
  schema.py              Phase 0: the frozen observation contract
  bundle.py              finds Node, Chromium and the worker when frozen
  db.py                  SQLite, WAL, thread-local connections
  events.py              progress events; the front-end seam
  core.py                THE API. Both front-ends call only this
  config.py              settings from defaults / TOML / environment
  discovery.py           finding a site's pages: sitemap, then crawl
  collectors/
    base.py              Collector protocol, shared fetch context
    http_probe.py        headers, compression, caching, cookies, redirects
    subresources.py      mixed content, insecure forms, third-party origins
    tls_probe.py         certificate validity, expiry, protocol
    fingerprint.py       CMS, CDN, page builder, WP Rocket + cache state
    crux.py              CrUX field data, token-bucket rate limited
    lighthouse.py        Lighthouse runner: median-of-N, spread, artifacts
  node_worker/
    worker.js            THE only Node code. Job on stdin, LHR on stdout
  findings/
    rules.yaml           the rules. DATA, not code
    engine.py            small declarative interpreter (no eval)
  report/
    model.py             pure view model: every threshold and sentence
    render.py            Jinja2 to HTML
    pdf.py               Chromium print-to-PDF, plus pypdf merge
    templates/           report.html.j2, batch.html.j2, report.css
  cli.py                 thin front-end over core
src/slap_web/            the front-end. Depends on slap.core, never back
  app.py                 routes only: no SQL, no thresholds
  viewmodel.py           every number, word and SVG path the templates print
  activity.py            batches and progress over server-sent events
  templates/             sites, site, findings, run
packaging/               build script and PyInstaller spec
docs/per-page.md         page discovery, sampling, and the silent aggregation bugs
docs/ui-redesign.md      why the UI is site-centric and browser-based
docs/packaging.md        building the self-contained distributable
docs/lighthouse.md       lab runner, concurrency, the LH13 audit-ID trap
docs/reports.md          report pipeline, palette rules, PDF backend
```

## The rules that keep this honest

1. **Collectors never format.** They emit numbers and raw artifacts.
2. **Runs are immutable and append-only.** A report is a pure function of a
   run id, which is what makes trend and before/after reports free later.
3. **The findings engine is data.** Tuning a severity threshold is a YAML
   edit, never a code change. Conditions are evaluated by a small
   interpreter rather than `eval`, because a rules file is the thing most
   likely to be edited casually.
4. **Every metric key is registered** in `schema.METRIC_REGISTRY` before a
   collector may emit it. A typo raises at collection time instead of
   producing a column nothing knows how to render.
5. **Nothing under `src/slap/` imports a UI framework.** Front-ends are
   clients of `slap.core`. If a front-end needs to reach past it, the core
   is missing a function.
6. **Provenance on every run.** Version and schema version are recorded per
   run. Reports without provenance get argued with.
7. **The templates compute nothing.** Every threshold comparison, formatted
   number, and plain-language sentence is decided in `report/model.py`,
   where it is unit tested without rendering HTML.
8. **A status colour never travels alone.** Every severity badge and metric
   tile prints its status word. Two steps of the status palette are only
   ΔE 13.6 apart and both sit below 3:1 contrast, so hue cannot carry
   meaning by itself. See the header comment in `report.css`.
9. **Lighthouse concurrency is separate from HTTP concurrency**, and capped
   at 3. Contended CPU inflates TBT and TTI and yields plausible,
   irreproducible scores. The spread across runs and the machine's CPU
   benchmark are recorded so the report can say when this happened.
10. **The Node worker is dumb.** Job on stdin, raw LHR on stdout, exit. No
   thresholds, no storage, no formatting. One language boundary, enforced.
11. **The front-end is a client, not a layer.** `slap_web` calls `slap.core`
   and nothing below it; no route opens a database, builds a pipeline, or
   renders a template. A test walks the AST of every module under `slap/`
   and fails if any of them imports a UI framework.
12. **A run holds many pages; the home page is the anchor.** It is what a
   site's trend line follows and where origin-scoped observations live.
   Aggregate queries count DISTINCT rules and DISTINCT pages, never finding
   rows: the naive version reports 240 open findings for a site with twelve
   problems, and it renders perfectly.
13. **Metric scope is declared.** `Metric.scope` says whether a fact
   describes a page or the origin. Origin-scoped collectors run once per
   site, not once per page, and the report prints their findings as
   "site-wide" rather than "1 of 20 pages".
14. **State the cap.** Any limit that reduces coverage is printed in the
   report and logged in the CLI. Silent truncation reads as completeness.

## Adding a collector

1. Register its metric keys in `schema.METRIC_REGISTRY`.
2. Write a class with `name` and `async def collect(ctx) -> list[Observation]`.
3. Add it to a stage in `collectors.default_pipeline()`. Collectors in a
   stage run concurrently; stages run in order. Stage 1 establishes the
   fetched document that later stages read.
4. Keep the parsing in module-level pure functions so it is testable with a
   string. Every parser in this repo is tested without network access.

## Tests

```bash
pytest -q          # 317 tests, no network and no display required
```

The suite runs local HTTP servers for the end-to-end paths, so the whole
thing is offline-safe. Lighthouse extraction is tested against a recorded
LHR from a deliberately awful fixture page (`tests/fixtures/slowsite/`),
because a clean page yields zero savings everywhere and cannot tell a
working extractor from a broken one. Web tests drive the real routes
against a real temporary database through FastAPI's TestClient. Tests needing
a real browser skip cleanly when it is absent.

`tests/multipage_server.py` is a ten-page offline site with a **nested,
partly gzipped sitemap index**, four page templates, an insecure cookie on
`/checkout` and a payment form posting over plain HTTP. Every discovery bug
worth having is silent — an index parsed as a page list audits nothing and
reports success — so the fixture is built to make each one fail loudly.
