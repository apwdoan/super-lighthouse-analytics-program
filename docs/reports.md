# Reports: HTML and PDF

*Phase 3. Built 2026-07-31.*

## The pipeline

```
build_model(conn, run_id)     pure transform → report model (unit tested, no HTML)
    │
    ▼
render_html()                minijinja + report.css → self-contained HTML (the artifact of record)
    │
    ▼
report_pdf()                 headless Chromium print-to-PDF of that HTML (a rendering of that file)
```

**HTML is the deliverable; the PDF is a rendering of it.** That ordering is
load-bearing, not stylistic:

- The PDF can never contain something the HTML does not.
- A failure in the PDF backend costs the user nothing. `report_pdf` renders
  the HTML first and only then drives Chromium, so a machine without the
  pinned browser still gets a usable HTML report and a clear error naming
  what is missing.
- A client who would rather have a link than an attachment is already
  served: the HTML export button writes the same document.

The HTML is fully self-contained: CSS inlined, no `<link>`, no external
fonts, logos as data URIs. It survives being emailed.

## The browser, and why not the alternatives

**The pinned Chrome for Testing** the app already downloads for Lighthouse —
the same binary serves PDF export, fetched on first use if absent.

| Rejected | Why |
|---|---|
| WeasyPrint-style pure-Rust paged media | Excellent paged-media CSS, but on Windows it needs GTK/Pango DLLs installed out of band. The audience is teammates on Windows; that is a support burden per machine. |
| System Chrome `--headless --print-to-pdf` | Zero install, but no running header/footer and no page numbers, and output shifts between teammates on different Chrome versions. A client-facing document must not do that. |
| A second layout engine that shares nothing with the HTML | Would mean maintaining a layout that the HTML is not built from. |

Cost of the choice: one pinned browser per machine, shared with Lighthouse.

`report_pdf` asks for the destination **before** it renders anything:
cancelling costs nothing, and the PDF path is heavy (a Chromium print, and
possibly a first-run fetch). The print runs as a blocking subprocess on a
blocking task so it cannot stall the async runtime, and the temp HTML it
writes is cleaned up on the same task.

## Two Chromium settings that are not optional

The print invocation must carry `--no-pdf-header-footer` and keep backgrounds
on. Chromium's default header/footer prints a URL line and page numbers on
top of the report's own masthead, and its default `print_background=false`
silently strips every background colour. So the badges, verdict panel, and
status dots all disappear, and the PDF looks *fine* at a glance because the
text is still there. `report.css` carries `print-color-adjust: exact` as the
same defence — do not remove it.

## Structure

*Restyled 2026-10-05 in Lighthouse's visual language.* A client has seen the
Lighthouse report in PageSpeed Insights or DevTools, so the report borrows its
grammar wholesale rather than inventing a second one: gauges, metric rows,
audit lists, runtime settings. What stays SLAP's own is the order (verdict
first) and everything Lighthouse does not do (findings across pages, security,
software).

Page one is the verdict, not the data.

1. **Gauges.** The home page's four Lighthouse categories, as Lighthouse draws
   them, with the site median under each when several pages were measured,
   and Lighthouse's score-scale legend.
2. **Verdict.** "Core Web Vitals assessment: Passed / Failed / No real-user
   data", a plain-language headline, and the three field metrics in the
   PageSpeed Insights layout: the p75, and a marker on the good /
   needs-improvement / poor scale.
3. **What to fix first.** Every critical, high and medium finding in full:
   what is wrong, the pages it affects (or "Site-wide" when its evidence is
   all origin-scoped), the specific fix, and the WP Rocket setting where one
   applies. Everything else collapses to a one-line list.
4. **Lighthouse: the home page.** The full Lighthouse view: the performance
   gauge, the metrics grid, Insights and Diagnostics, then each other
   category's failing audits by Lighthouse group, with the passed, manual and
   not-applicable counts.
5. **Lighthouse across N pages.** Per category, the median and a stacked bar
   of how many pages fail, are average, or pass; then the Lighthouse audits
   that fail on the most pages, with their reach ("38 of 40 pages") and
   typical saving.
6. **Pages audited.** Every page with all four scores, LCP, TBT and CLS.
7. **Pages worth a closer look.** A compact Lighthouse section (gauges,
   metrics, failing audits capped per category) for each page that is an
   outlier (15+ points under the site's median performance, or failing a
   category the site passes) or carries a finding fewer than half the pages
   have. Capped at 25 with the remainder counted; with six or fewer pages
   measured, every page gets one.
8. **Software, Security, Appendix.** Methodology, run provenance, Lighthouse's
   runtime settings (device, network, CPU, browser, benchmark), coverage, and
   every measurement collected.

**The audit lists come from a stored summary, not a re-parsed LHR.** When a
page is measured, the median run's LHR is reduced to a few KB (failing and
informative audits per Lighthouse group, counts, metric ratings, runtime
settings) and written beside the database as an `lh-summary` artifact. The
report never parses a raw LHR, and works whether or not raw LHRs are kept.
Scores and metric values come from the observations (per-metric medians);
the audit list comes from the run with the median performance score. A page
whose summary is missing still renders, with its gauges and metrics.

### The finding split, and a bug worth remembering

The model splits findings into **significant** (critical, high, medium —
full cards) and **minor** (the one-line list), with no cap on the detailed
treatment.

The first version took the top 5. On a site with six critical-or-high
findings that meant an alphabetical rule-id tiebreak decided which one got
demoted to a one-liner, and in the first real test it demoted
`wprocket-cache-cold` — the single most actionable thing SLAP produces.
**Never cap by count what you have ranked by severity.** A test renders the
report and asserts the detailed treatment appears for the seeded
critical/high findings.

## Colour and accessibility

*Replaced 2026-10-05.* The report uses Lighthouse's own palette:

| Role | Fill (shapes, arcs, bars) | Text |
|---|---|---|
| Pass (90-100) | `#0c6` | `#080` |
| Average (50-89) | `#fa3` | `#c33300` |
| Fail (0-49) | `#f33` | `#c00` |
| Informative | `#757575` outline | ink |

Two rules carry over from the earlier palette, because they are about
accessibility rather than taste:

- **A rating never relies on colour alone.** Lighthouse's answer is shape: a
  red triangle fails, an orange square is average, a green circle passes, a
  grey ring is informative. Every gauge band, metric, audit, score chip and
  security status here carries one. Finding badges also print their severity
  WORD, because high and medium sit adjacent in the findings list and their
  fills are too close to separate. The report stays readable in greyscale.
- **Light fills are never text.** `#0c6`, `#fa3` and `#f33` are below 3:1 on
  white, so they are used for shapes, arcs and bars. Numbers wear the dark
  steps (`#080`, `#c33300`, `#c00`, all above 4.5:1), exactly as Lighthouse
  colours the number inside a gauge.

The metric ratings use Lighthouse's own scoring control points (for mobile
LCP: 2.5s and 4s), which are its pass and average boundaries, so a metric is
green here exactly when it would be green in Lighthouse.

## Formatting lives in the schema

`schema::format_value` renders a value using the metric registry's declared
unit, and both the findings engine and the report model call it. That single
source of truth exists because rule text substitutes metric values:

```yaml
detail: "The document came back at {http.content_bytes}."   # → "402 KB"
```

Two consequences:

- **Rule text must not append its own unit.** Write `{http.ttfb}`, never
  `{http.ttfb}ms`, or you ship "412msms". A test scans the whole rules
  file for this.
- **A metric's declared unit is a formatting decision, not just metadata.**
  `crux.cls.p75` was declared `RATIO`, which rendered 0.06 as "6%" in a
  client-facing document. It is `SCORE`. Check the unit when registering a
  metric.

## Branding

Neutral by default. `Settings.branding` is a plain map so the app's
settings screen and a TOML file can both populate it without a schema
change:

```toml
[branding]
company_name = "Your Company"
logo_data_uri = "data:image/png;base64,..."
```

A logo replaces the wordmark in the masthead. Keep it a data URI so the
HTML stays self-contained. `the_masthead_renders_the_configured_brand_name_and_logo`
pins both the set and the unset cases.

## Exporting

Exporting is two Tauri commands, both per-run:

- `report_html` renders `render_html` and hands the file to the user's
  system handler for a Save dialog.
- `report_pdf` does the same through headless Chromium, as described above.

Both ask for the destination before doing any work, so cancelling costs
nothing. Viewing uses the OS handler rather than an embedded viewer — that
keeps a heavyweight webview component out of the install until someone
actually asks for an in-app preview.

## Per-run output, not per-batch

Each run exports its own report: one site, one HTML, one PDF. A multi-site
audit is just several runs under one `batch-<id>`, and the app's report
screen picks the run. There is deliberately no concatenated "batch
report": it would need a second layout (one page per site) and a second
source of truth for what a run contains.

Filenames go through `report_filename`, which strips path-hostile characters
and prefixes the Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`,
`COM1-9`, `LPT1-9`) — those fail to open on Windows even with an extension
appended.