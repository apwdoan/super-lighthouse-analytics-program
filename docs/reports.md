# Reports: HTML and PDF

*Phase 3. Built 2026-07-31.*

## The pipeline

```
core.get_run_detail(run_id)
    │
    ▼
report/model.py      pure transform → ReportModel   (unit tested, no HTML)
    │
    ▼
report/render.py     Jinja2 → self-contained HTML   (the artifact of record)
    │
    ▼
report/pdf.py        Chromium print-to-PDF          (a rendering of that file)
```

**HTML is the deliverable; the PDF is a rendering of it.** That ordering is
load-bearing, not stylistic:

- The PDF can never contain something the HTML does not.
- A failure in the PDF backend costs the user nothing. `export_report`
  writes the HTML first and returns `pdf_error` set, so a teammate who
  skipped `playwright install chromium` still gets a usable report and a
  message naming the exact command.
- A client who would rather have a link than an attachment is already
  served.

The HTML is fully self-contained: CSS inlined, no `<link>`, no external
fonts, logos as data URIs. It survives being emailed.

## The engine, and why not the alternatives

**Playwright's pinned Chromium.**

| Rejected | Why |
|---|---|
| WeasyPrint | Excellent paged-media CSS, but on Windows it needs GTK/Pango DLLs installed out of band. The audience is teammates on Windows; that is a support burden per machine. |
| System Chrome `--headless --print-to-pdf` | Zero install, but no running header/footer and no page numbers, and output shifts between teammates on different Chrome versions. A client-facing document must not do that. |
| ReportLab / direct PDF | Would mean maintaining a second layout engine that shares nothing with the HTML. |

Cost of the choice: one setup step per machine.

```bash
pip install "salp[report]"
playwright install chromium
```

`core.pdf_backend_status()` probes for this without launching a browser and
returns a `BackendStatus` that renders directly in a settings screen. Call
it from the GUI's preferences panel rather than discovering the problem
when a user clicks Export.

## Two Chromium settings that are not optional

```python
await page.emulate_media(media="print")   # or @media print rules never apply
await page.pdf(print_background=True)     # or every badge prints white-on-white
```

`print_background=False` is Chromium's default and silently strips every
background colour. The severity badges, verdict panel, and status dots all
disappear, and the PDF looks *fine* at a glance because the text is still
there. Do not remove `print-color-adjust: exact` from `report.css` either;
it is the same defence.

## Structure

Page one is the verdict, not the data.

1. **Verdict.** A plain-language headline, then a KPI row of three stat
   tiles (LCP, INP, CLS) with threshold meters, then a lab strip (TTFB,
   HTML size, compression, redirects) and one sentence explaining why lab
   and field figures disagree.
2. **What to fix first.** Every critical and high finding in full: what is
   wrong, evidence chips, the specific fix, and the WP Rocket setting where
   one applies. Everything else collapses to a one-line list.
3. **Security.** TLS and certificate, the six recommended response headers,
   cookie hygiene.
4. **Appendix.** Methodology, run provenance, detected technology, and
   every measurement collected.

### The finding split, and a bug worth remembering

`split_findings()` gives the detailed treatment to **every** critical and
high finding, with no cap.

The first version took the top 5. On a site with six critical-or-high
findings that meant an alphabetical rule-id tiebreak decided which one got
demoted to a one-liner, and in the first real test it demoted
`wprocket-cache-cold` — the single most actionable thing SALP produces.
**Never cap by count what you have ranked by severity.** The test
`test_every_high_and_critical_finding_gets_the_detailed_treatment` guards
this.

## Colour and accessibility

Colours are the reference data-viz palette, used verbatim. The status roles
carry all severity meaning: `good` `#0ca30c`, `warning` `#fab219`,
`serious` `#ec835a`, `critical` `#d03b3b`.

Running the palette validator against the report surface surfaced two
constraints that shape the markup:

```
[FAIL] Normal-vision floor  #ec835a ↔ #fab219  ΔE 13.6 — below the 15 floor
[WARN] Contrast vs surface  #fab219 1.79, #ec835a 2.57 — below 3:1
```

`serious` is the "high" badge and `warning` is the "medium" badge, and they
sit adjacent in the findings list. So:

- **Every badge, tile, and status cell prints its status WORD.** Never
  reduce one to a bare coloured dot. This is the documented mitigation for
  both findings above, and it is the reason the report is readable in
  greyscale, which is how a lot of clients will actually print it.
- **Status colours are used as fills, rules, and dots beside dark ink,
  never as text colour.** Text always wears the ink tokens.

Form choices follow the same reference: three current values is a KPI row
of stat tiles, not a chart. A value against thresholds is a meter. Tile
values use proportional figures; `tabular-nums` is reserved for the table
columns that must align vertically.

The meter's track is neutral with hairline ticks at 33% and 66%, where the
good and needs-improvement thresholds land on **every** tile, so the three
can be compared by eye without re-reading each axis. `meter_fraction()` is
non-linear to make that true, and
`test_meter_thresholds_land_at_the_same_place_on_every_tile` keeps the
maths and the hard-coded tick positions in agreement.

## Formatting lives in the schema

`schema.format_value()` renders a value using the metric registry's
declared unit, and both the findings engine and the report model call it.
That single source of truth exists because rule text substitutes metric
values:

```yaml
detail: "The document came back at {http.content_bytes}."   # → "402 KB"
```

Two consequences:

- **Rule text must not append its own unit.** Write `{http.ttfb}`, never
  `{http.ttfb}ms`, or you ship "412msms".
  `test_no_shipped_rule_appends_a_unit_after_a_placeholder` scans the whole
  rules file for this.
- **A metric's declared unit is a formatting decision, not just metadata.**
  `crux.cls.p75` was declared `RATIO`, which rendered 0.06 as "6%" in a
  client-facing document. It is `SCORE`. Check the unit when registering a
  metric.

## Branding

Neutral by default. `Settings.branding` is a plain dict so a Qt preferences
dialog and a TOML file can both populate it without a schema change:

```toml
[branding]
company_name = "Your Company"
accent = "#2a78d6"
logo_data_uri = "data:image/png;base64,..."
```

A logo replaces the wordmark in the masthead. Keep it a data URI so the
HTML stays self-contained.

## Wiring it into the GUI

`core.export_report()` is synchronous and must not be called from a thread
with a running event loop; it raises a clear `PdfError` if you try. In the
GUI, run it from a `QRunnable` on `QThreadPool`:

```python
class ExportTask(QRunnable):
    def run(self):
        result = core.export_report(self.settings, self.run_id, pdf=True)
        # emit result back to the main thread via a QObject signal
```

To export automatically at the end of a batch, from inside the
`BatchWorker` thread's loop, await `core.export_report_async()` instead.

For viewing, open the PDF or HTML with the system handler rather than
embedding it:

```python
QDesktopServices.openUrl(QUrl.fromLocalFile(str(result.pdf_path)))
```

That keeps `QWebEngineView` (~150MB, and a real PyInstaller complication)
out of the build until someone actually asks for an embedded preview.

## Batch output

```
reports/batch-<id>/
  index.html / index.pdf          summary, ranked worst-first
  <hostname>-<run>.html / .pdf    one per site
  batch-<id>.pdf                  everything concatenated (--merge)
```

The index ranks by highest severity present, not by a score: a site with
one critical finding sorts above a site with twenty low ones, which is
usually the right order to work in. Sites with no findings read as
"Clean" and sort last.

Merging uses `pypdf`. Filenames go through `safe_filename()`, which strips
path-hostile characters and prefixes the Windows reserved device names
(`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) — those fail to open on
Windows even with an extension appended.
