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

**Everything the template prints is escaped as HTML text.** A Server
header, a redirect chain, a component name or a TLS error is the audited
site's own text, and the report must print it, not obey it: before this was
set, a Server header containing `<title>` swallowed everything after it and
cut a 7-page PDF to 3. The template is escaped by its own formatter
(`html_text_formatter`), which is minijinja's HTML escaping without `&#x2f;`
for `/`, so paths and URLs stay readable in the source; the stylesheet is
included unescaped. A test renders markup in a finding title and checks it
arrives as text.

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

*Restyled 2026-10-05 in Lighthouse's visual language, then reworded for the
client the same day.* A client may have seen the Lighthouse report in
PageSpeed Insights, so the report borrows its look rather than inventing a
second one: gauges, metric rows, audit lists, the three rating shapes. What
stays SLAP's own is the order (verdict first), everything Lighthouse does not
do (findings across pages, security, software), and the words, which are
written for the site's owner rather than its developer (see *Plain language*
below).

Page one is the verdict, not the data.

1. **Gauges.** The home page's four Lighthouse categories, as Lighthouse draws
   them, with "Typical page: N" under each (the median of every page tested)
   when several pages were tested, and a legend that names the bands: poor,
   needs work, good.
2. **Verdict.** "Google's Core Web Vitals for real visitors: Passed / Failed /
   Not enough data", a plain headline, and the three field metrics (main
   content, responsiveness, layout shift) in the PageSpeed Insights layout:
   the p75, and a marker on the good / needs-work / poor scale. A field-data
   improvement shows here as good news.
3. **What to fix first.** Every critical, high and medium finding in full:
   what is wrong, the pages it affects ("The whole site" when its evidence is
   all origin-scoped), the effort in words (quick fix, some work, bigger job),
   how to fix it, and the WP Rocket setting where one applies. Low findings
   are one line each under "Smaller improvements".
4. **Home page in detail.** The performance gauge beside the five metrics,
   each with its plain name, Lighthouse's short name, and one line on what it
   means; "Ways to make it faster", the failing and needs-work audits as one
   list with their savings; then the other three categories side by side,
   each with a sentence on what it measures, its problems, and how many
   checks passed.
5. **Across the site.** The coverage sentence; per category, the typical
   score and a stacked bar of how many pages are poor, need work, or are
   good; the most common problems with their reach ("38 of 40 pages") and
   typical saving; then every page with its four scores, main content time
   (LCP) and issue count. A page's issues are its own: a problem with the
   whole site is stored on the home page, and counting it there would make
   the home page look worse than any other. When Lighthouse tried and failed
   on every page, the score columns stay and say so, rather than vanishing
   as if it had not run.
6. **Pages worth a closer look.** A compact section (gauges, metrics,
   problems capped per category) for pages that stand out. When every page
   was tested, that is a page 15+ points under the typical performance score,
   failing a category the site passes, or with problems most pages do not
   have, which the section names. "Most" means fewer than half the pages the
   problem could be on: a Lighthouse finding can only be on a page
   Lighthouse tested, so in a sampled run it is judged against the tested
   pages, not the whole site. Pages of one type with the same problems are
   one section that lists the others ("The same problems on 9 other pages"),
   so forty product pages from one template do not become forty sections.
   When one page of each type was tested, every one gets a section: it
   speaks for its type. Capped at 25 sections, the remainder counted.
7. **Security.** The secure connection (certificate, issuer, expiry, TLS
   version, the http-to-https redirect), cookies, and the six headers the
   HTTP collector expects as a Set / Missing checklist, each named by what it
   protects with the header's own name beneath it.
8. **Software and technology.** Platform, builder, CDN, server, caching and
   WP Rocket; the software found; known security flaws in a sentence; and the
   vulnerability database's date, with the NVD's required attribution. The
   check ran when the database's date is recorded; the flaw counts are only
   stored when they are not zero, so their absence after a check means none
   were found, not that nothing was checked.
9. **About this report.** How the audit tested, in plain bullets; the test
   details (date, pages tested, device, connection, tool, browser, tests per
   page, reference); notes on the results; and a dozen other measurements in
   plain words. Metric keys, sources, schema versions, batch ids, the
   benchmark index and the throttling profile are no longer printed: the
   full record stays in the app, and the report says it is available on
   request.

**Density.** *Condensed 2026-10-05; a 6-page site went from 18 PDF pages to
9, a 40-page one from 33 to 14. The rewording took them to 7 and 8.* No font
size was changed to get there; only space, layout and words. Sections run on
with no forced page breaks, and headings (section heads, group heads,
page-section heads) are kept with what follows them, so no sheet is left half
empty and no heading is stranded at the foot of a page. The space goes where
it does the most good: the performance gauge sits beside its metrics, the
other categories sit three abreast, a page section puts its gauges beside a
two-column metric list and flows its problems across two columns, a
finding's scope and effort share one line with its pages listed inline, the
connection and cookie tables sit beside the header checklist, and the other
measurements run two to a row. Print margins are 9mm by 10mm (`@page`). If a
change needs more room, take it from padding before touching a font size.

**The audit lists come from a stored summary, not a re-parsed LHR.** When a
page is measured, the median run's LHR is reduced to a few KB (failing and
informative audits per Lighthouse group, counts, metric ratings, runtime
settings) and written beside the database as an `lh-summary` artifact. The
report never parses a raw LHR, and works whether or not raw LHRs are kept.
Scores and metric values come from the observations (per-metric medians);
the audit list comes from the run with the median performance score. A page
whose summary is missing still renders, with its gauges and metrics.
Informative audits are stored but not printed: Lighthouse does not score
them, and a client cannot act on them.

### Plain language

The reader owns the site and may never have opened a developer tool, so
nothing the report prints should need one to understand.

- **Lighthouse audits are retitled by audit id** (`plain_audit_title`) as the
  problem they describe: "Images are bigger than they need to be", not
  "Improve image delivery"; "The main content is not marked for screen
  readers", not "Document does not have a main landmark." An id without an
  entry keeps Lighthouse's own title. Audits that mean the same thing to a
  reader (the eleven ARIA attribute checks, say) share a title and are listed
  once. Lighthouse's descriptions are not printed.
- **Savings are time when there is a meaningful amount** (a tenth of a
  second or more), otherwise download size in decimal KB or MB: "could save
  about 2.4 s", "could save about 234 KB". Other display strings ("2 failure
  reasons") are dropped.
- **Metrics keep Lighthouse's short name beside a plain one**: "Main content"
  with LCP, "Unresponsive time" with TBT, "Page fills in" with Speed Index.
  A client who knows the acronyms can still find them; one who does not is
  not asked to.
- **Templates read as page types** (`page_kind`): "Blog post", "Top-level
  page"; dates read as "6 October 2026".
- **Finding text comes from the current rules.** The report renders each
  finding's title, detail and fix from today's `rules.yaml`, filled in from
  the stored observations of the page it fired on, which are the same values
  the engine read when the run was finalised. A run audited before a rule was
  reworded reads in the current words; its rules, severities and pages are
  the run's own. A rule that no longer exists falls back to the stored text.
  Rule titles and details are written for the client; remediation is for
  whoever makes the fix and may stay technical (see the header of
  `rules.yaml`).

### The finding split, and a bug worth remembering

The model splits findings into **significant** (critical, high, medium —
full cards), **minor** (the one-line list) and **notes**, with no cap on the
detailed treatment. Info findings describe the audit rather than the site (a
busy or drifting test machine, results that varied, software the database
could not check, an inconclusive or blocked probe), so they are listed under
"Notes on these results" in About this report, not as things to fix, and
the per-page issue counts leave them out. `no-field-data` is not repeated
there because the verdict says it, and `crux-history-improvement` is good
news, so it shows in the verdict.

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