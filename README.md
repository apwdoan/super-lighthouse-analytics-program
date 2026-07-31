# SALP: Super Awesome Lighthouse Project

Batch website performance and security auditing. Retrieves the data, turns
it into findings a site owner will act on, and renders a client-facing
HTML and PDF report.

```
collectors  ──►  normalized observations  ──►  findings engine  ──►  report
(many, dumb)     (one schema, immutable)       (rules, tunable)      (HTML → PDF)
```

**Status: every planned phase is built, and it packages into a
self-contained distributable teammates can run with nothing installed.** Schema frozen, no-browser
collectors working, Lighthouse runner driving a pinned Chromium, findings
engine running off 46 YAML rules, client-facing HTML and PDF reports
rendering, and both front-ends (CLI and PySide6 desktop app) driving the
same core. See `docs/gui-architecture.md`, `docs/lighthouse.md`, and
`docs/reports.md`.

---

## Install

```bash
pip install -e ".[dev,all]"
playwright install chromium                    # PDF export and Lighthouse
npm install --prefix src/salp/node_worker      # Lighthouse itself
salp doctor                                    # confirm every backend
```

Extras: `report` (PDF), `gui` (desktop app), `all` (both).

Node **>= 22.19** is required for the Lighthouse runner. Everything except
`pip install` is optional: without them SALP still audits, and the report
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
salp audit example.com another-site.com     # bare hostnames are fine
salp audit -f sites.txt -c 20               # one URL per line, 20 at a time
salp audit example.com --lighthouse         # add the lab audit (~90s/site)
salp doctor                                 # which backends are available
salp batches                                # what has been run
salp runs -b <batch-id>                     # runs in a batch
salp show 42 -v                             # findings, with fixes
salp show 42 -o                             # plus raw observations
salp rules                                  # validate and list the rules

salp report 42 --open                       # HTML + PDF for one site
salp report -b <batch-id> --merge           # every site, plus one combined PDF
salp report --check                         # is the PDF backend installed?
```

Or run the desktop app:

```bash
salp-gui            # or: python -m salp_gui
```

## Shipping it to someone

```bash
python packaging/build.py --zip
```

Produces `dist/SALP/` (~1.1GB, ~410MB zipped) containing the Python runtime,
the app, Node, Lighthouse and Chromium. A teammate unzips it and runs it;
they install nothing.

PyInstaller is not a cross-compiler, so build on the platform you are
shipping to. To get all three without owning all three machines, run the
**Build distributables** workflow on GitHub: it builds Windows, macOS
(Apple Silicon) and Linux natively, and each job runs the bundle it just
built before uploading it.

See `docs/packaging.md` for the size breakdown, Windows SmartScreen, and
macOS Gatekeeper.

Reports land in `report_dir` (per-user, under `%LOCALAPPDATA%\salp` on
Windows) unless you pass `-o`. The HTML is the artifact of record and the
PDF is a rendering of it, so if the PDF backend is missing you still get
the report and a message saying what to install.

Ctrl+C cancels cooperatively: in-flight sites finish and every run row
lands in a terminal state, so history is never left half-written.

## Layout

```
src/salp/
  schema.py              Phase 0: the frozen observation contract
  bundle.py              finds Node, Chromium and the worker when frozen
  db.py                  SQLite, WAL, thread-local connections
  events.py              progress events; the front-end seam
  core.py                THE API. CLI and GUI both call only this
  config.py              settings from defaults / TOML / environment
  collectors/
    base.py              Collector protocol, shared fetch context
    http_probe.py        headers, compression, caching, cookies, redirects
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
src/salp_gui/            desktop front-end. Depends on salp.core, never back
  bridge.py              the asyncio-to-Qt seam; every threading bug lives here
  models.py              table models; per-row dataChanged, no SQL
  pages/                 composer, monitor, history, settings
packaging/               build script and PyInstaller spec
docs/gui-architecture.md PySide6 threading model and screen map
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
5. **Nothing under `src/salp/` imports a GUI toolkit.** Front-ends are
   clients of `salp.core`. If a front-end needs to reach past it, the core
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
11. **The GUI is a client, not a layer.** `salp_gui` calls `salp.core` and
   nothing below it; no widget opens a database, builds a pipeline, or
   renders a template. A test walks the AST of every module under `salp/`
   and fails if any of them imports Qt.

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
pytest -q          # 207 tests, no network and no display required
```

The suite runs local HTTP servers for the end-to-end paths, so the whole
thing is offline-safe. Lighthouse extraction is tested against a recorded
LHR from a deliberately awful fixture page (`tests/fixtures/slowsite/`),
because a clean page yields zero savings everywhere and cannot tell a
working extractor from a broken one. GUI tests run under
`QT_QPA_PLATFORM=offscreen`. Tests needing a real browser, or PySide6, skip
cleanly when it is absent.
