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
  greyscale, which is how a lot of clients will actually print it. The model
  carries `status_word` on every tile and card for exactly this.
- **Status colours are used as fills, rules, and dots beside dark ink,
  never as text colour.** Text always wears the ink tokens.

Form choices follow the same reference: three current values is a KPI row
of stat tiles, not a chart. A value against thresholds is a meter. Tile
values use proportional figures; `tabular-nums` is reserved for the table
columns that must align vertically.

The meter's track is neutral with hairline ticks at 33% and 66%, where the
good and needs-improvement thresholds land on **every** tile, so the three
can be compared by eye without re-reading each axis. `meter_pct` is
non-linear to make that true, and
`meter_pins_thresholds_at_a_third_and_two_thirds` keeps the maths and the
hard-coded tick positions in agreement.

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