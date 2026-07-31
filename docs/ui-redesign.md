# SLAP: UI redesign

*Decided 2026-07-31. Supersedes §11 and §13 of the roadmap, which chose PySide6.*

Two decisions, both made deliberately:

1. **The site is the primary object**, not the batch.
2. **A local web UI**, not a Qt desktop app.

---

## 1. Why the batch was the wrong centre

The existing GUI has four screens: Composer, Progress, History, Settings. That is
the shape of *a tool that runs jobs*. History goes batches → runs → findings,
which is the storage layout wearing a UI.

Nobody opens this app thinking "show me batch b6aeaeb157b4". They think "how is
example.com doing" or "did the fix we shipped last month work". The batch is a
scheduling detail. Making it the organising principle costs three things:

- **Trends are unreachable.** Runs are immutable and a report is a pure function
  of a run id, so before/after comparison is a query over two run ids rather than
  new collection. The architecture has supported this since Phase 0 and the UI has
  nowhere to put it.
- **Repeat work is re-entered.** You audit the same client sites over and over and
  paste the URLs in every time.
- **Findings cannot be seen across sites.** "Which of my 24 sites have no HSTS" is
  one SQL query against data already stored, and it is invisible.

## 2. The screens

| Screen | What it is for | New? |
|---|---|---|
| **Sites** (home) | Every site, current verdict, 90-day sparkline, open findings, last audit. Select rows → audit. | Replaces Composer |
| **Site detail** | One site over time: score trend, findings split **open / fixed since last run**, run history, CWV tiles. | **Entirely new** |
| **Run / report preview** | The exact HTML the client receives, in place, with control over included findings and branding. | New |
| **Findings across sites** | Grouped by rule, with affected-site counts. | **Entirely new** |
| **Activity dock** | Persistent strip. Queue, per-site stage, live log. | Replaces Progress |
| **Settings** | Backends, measurement, storage, branding. | Mostly unchanged |

### Three principles the screens encode

**Progress is a state, not a place.** A 24-site batch with Lighthouse on is
roughly 40 minutes at concurrency 3. Making that a destination means the operator
sits and watches or navigates away and loses the thread. It is a dock: the app
stays fully usable and the detail is there when wanted.

**The report is the product.** Today the only way to see what the client gets is
to export and open it externally. Preview belongs in the app, and so does deciding
what goes in it. `Settings.branding` is already a plain dict with no UI on it.

**Site detail is the screen that earns money.** "We fixed it, here is proof" is
the deliverable a client pays for twice. Everything needed for it is already in
the database.

## 3. Why a local web UI

The original PySide6 decision recorded its own cost: *the presentation layer
exists twice*. A complete redesign is the honest moment to re-ask it, and the
answer changed:

- The report is **already Jinja2 HTML**, and `report/model.py` is already a pure
  view model that "computes everything so the templates compute nothing" (rule 7).
  A web UI consumes that model directly. The duplication collapses from two
  presentation layers to one.
- **`EventBus` → SSE is a far simpler seam than `EventBus` → QueueSink → QTimer.**
  Every threading bug in this project lives in `salp_gui/bridge.py`: signals
  garbage-collected mid-emit, tasks outliving the window, `QThreadPool.waitForDone`
  on close. Server-sent events delete that file's entire problem class.
- **Charts stop being a size decision.** `QtCharts` is excluded from the
  PyInstaller spec to save ~150MB, so trends in Qt mean hand-painted `QPainter`
  widgets. In HTML a sparkline is nine lines of SVG.

### Proposed stack

**FastAPI + Jinja2 + HTMX.** No build step, no bundler, no `node_modules` for the
front end, server-rendered. HTMX covers the interactivity this app actually needs
(swap a panel, poll a queue, submit a form) and SSE covers live progress. A React
front end would add a build toolchain to a PyInstaller bundle for no benefit here.

### What this costs

- **`src/slap_gui/` is retired.** ~2,100 lines, plus the Qt-specific tests.
- **PySide6 leaves the bundle.** That is ~117MB back, and the `QtWebEngine`
  exclusion list in the spec becomes moot.
- **The distributable still works the same way.** The PyInstaller bundle starts a
  local server on a loopback port and opens the default browser. A teammate still
  double-clicks one thing and installs nothing. Chromium is already in the bundle
  for PDF export, so there is no new dependency.
- **The architecture rule survives unchanged.** Nothing under `src/slap/` imports
  a web framework. `src/slap_web/` is a client of `slap.core` exactly as
  `slap_gui` was, and the AST test that fails on any Qt import under `slap/` just
  extends to FastAPI.

## 4. Design system

The UI uses the **report's** palette and vocabulary, imported rather than
redeclared, so the operator view and the client PDF cannot drift on what "High"
means. `SEVERITY_STATUS` and `STATUS_WORDS` already live in `report/model.py`.

Running the palette validator on the four status colours as a *categorical* set
FAILs, exactly as `report.css` documents: `serious` (#ec835a) and `warning`
(#fab219) sit ΔE 13.6 apart in normal vision, below the 15 floor, and both are
sub-3:1 on the light surface. They are not a categorical set. They are a **status**
palette, and the mitigation is mandatory: **every badge prints its status word.**

That is why the mockup never shows a bare coloured dot anywhere. It is not a
style choice and it must not be tidied up.

Other rules carried over: one series means no legend (the title names it); direct
labels on the first and last point only, never every point; text always wears text
tokens, never a status colour; dark mode is a selected set of steps against the
dark surface, not an automatic flip.

## 5. Built, 2026-07-31

All seven steps are done and verified against real audits, not fixtures.

| | |
|---|---|
| `src/slap_web/` skeleton | FastAPI + Jinja2, no build step |
| Sites, Site detail | trend, open/fixed split, CWV tiles |
| Activity dock over SSE | `bridge.py` retired |
| Report preview and branding | the client's HTML, inline |
| Findings across sites | grouped by rule id |
| Packaging | server + browser launch; **933MB → 702MB** |
| `src/slap_gui/` | deleted |

241 tests pass. The bundle was built and run in an environment with no Node,
no Playwright and no PATH beyond `/usr/bin`: it served every route, ran a
Lighthouse audit driven from its own UI, and exported a PDF.

### What building it taught

**`uvicorn` resolves its own internals by string.** Event loop, HTTP protocol
and lifespan implementations are imported by name at runtime, so PyInstaller
sees none of them. `collect_submodules("uvicorn")` is in the spec because
without it the bundle starts cleanly and dies on the first request.

**`doctor` was lying about CrUX.** It checked that a key was *set*. A key can
be present, well-formed and rejected on every request, which is exactly what
happened: valid key, API not enabled on its Google Cloud project. Every audit
would have recorded `crux.available: false` while `doctor` said ok. It now
makes a real request against a high-traffic origin, so "no data for this
origin" cannot be confused with "the key does not work". Same lesson as the
PDF check that stat-ed a file instead of launching the browser.

**Two view-model bugs only visible by looking.** Five runs seeded in one
afternoon made every chart axis label read "today", because `humanise` is
right for a table cell and wrong for a chart. And with no CrUX key all three
vitals tiles read "No data", which is honest and useless; they now fall back
to the lab number behind a `LAB` chip. INP deliberately does not: its lab
proxy is total blocking time, and printing that under an "Interaction to Next
Paint" heading would be a lie.

**The dock offers a refresh rather than taking one.** It reloaded on batch
completion at first, and promptly interrupted a navigation mid-flight. It
would do the same to an operator mid-click.

### What is deliberately not done

- **Branding is session-only.** Persisting it means round-tripping the user's
  `config.toml` without eating their comments, and `tomllib` is read-only.
  That is a decision, not an oversight.
- **One live batch at a time.** Two batches means two sets of Lighthouse
  workers and the concurrency cap that keeps scores reproducible stops
  meaning anything.
- **`list_sites` reads history per site.** Fine at tens of sites. If it ever
  hurts it becomes one grouped query in the core, not a cache in the route.
