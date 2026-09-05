# SLAP: per-page analysis

*Designed and built 2026-08-02. Extends the roadmap; supersedes nothing.*

A report covers **every page of a site**, not the home page, and carries
per-page security alongside performance. This is what was built, and what
building it taught.

**Status: phases 5a and 5b are done.** Discovery, multi-page persistence, the
aggregation fixes, two-dimensional concurrency, template sampling, the page
inventory, rule-grouped findings, metric scope, and the per-page subresource
collector. The core and engine test suites pass with no network. 5c (CVE
matching) and 5d (endpoint probing) are not started.

---

## 1. The GUI did not change

A Rust core in a Tauri shell, a Node sidecar for Lighthouse, the system
webview as the window. Decided when the desktop app was scoped, re-examined
against per-page, unchanged.

Per-page strengthened it: the new UI surface is a page inventory table with
drill-down and per-page status, which is a `<table>` in the static frontend —
no bundler, no paint framework, nothing new in the bundle.

---

## 2. What the storage layer already supported

Almost everything. `observation.page_id`, `finding.page_id` and
`artifact.page_id` were foreign keys to `page` from Phase 0, every read query
already joined through it, and `idx_page_run` was already there.

Only the **cardinality** was pinned to one, and only in a handful of places.
Four columns were added to `page` (`role`, `discovered_via`, `audit_depth`,
`template_class`) through `storage::migrate()`, guarded on `PRAGMA table_info`,
because `CREATE TABLE IF NOT EXISTS` never reaches a table that already
exists — the same trap as the SALP → SLAP column rename.

`audit_depth` is **stored, not derived from artifact presence**. Deriving it
conflates "Lighthouse was never asked to run here" with "Lighthouse ran and
failed", and the report needs a different sentence for each. The migration
back-fills `full` for historical pages that have an LHR artifact, or every
pre-existing run would claim its browser audit never happened.

Existing rows default to `role = 'home'`. That default is load-bearing: the
queries below select the home page, and a NULL would silently drop all of
history off every site's trend line.

---

## 3. Every aggregation bug in this area is silent

This is the part worth remembering. None of these raise, none look wrong in a
screenshot, and all of them are wrong.

| Query | Naive result on a 20-page run |
|---|---|
| `list_sites.finding_count` | 240 open findings for 12 real problems |
| `site_metric_history` | 20 rows per run; the chart plots whichever page sorted last |
| `findings_across_sites` | counts finding rows, not sites or pages |
| `get_site_detail.observations` | `LIMIT 1` with no `ORDER BY`: an arbitrary page's score becomes the site's headline |

The fixes: `COUNT(DISTINCT f.rule_id)` for problems and
`COUNT(DISTINCT p.id)` for pages, both kept alongside the raw
`finding_instances`; and every "one representative row" lookup goes through
`home_page_id()`, which falls back to the lowest page id so a run with no
home page still reports something rather than blanking a report that has good
data in it.

**The trend follows the home page and only the home page.** A trend line has
to track a stable subject or it is noise rendered as a line, and the home page
is the one page every run of every site is guaranteed to have.

The per-page tests in the engine suite write each of these as a number, and
each was checked against the pre-per-page SQL before the fix: the site list
read 8 where it should read 2, and the trend read 10.0 (the worst page) where
the home page scored 70.0.

---

## 4. Discovery

`slap-engine`'s `discovery` module. **Not a collector**: a collector takes a
`PageContext` and returns observations for one URL, and discovery runs before
any context exists. Bending the protocol to fit would have been the first
crack in the thing that has kept the pipeline clean.

`robots.txt` → conventional locations (`/sitemap.xml`, `/sitemap_index.xml`
for Yoast, `/wp-sitemap.xml` for WordPress 5.5+) → shallow same-origin crawl.

Three failure modes, all silent, all covered by the offline fixture:

1. **A `<sitemapindex>` is not a page list.** Its children are `<sitemap>`
   elements pointing at more sitemaps. A parser that reads `<loc>` without
   checking the root element audits zero real pages and reports success.
2. **`.xml.gz` is served as `Content-Type: application/gzip`**, where the gzip
   is the *payload*, not the transfer encoding, so the HTTP client does not
   decode it. `decode_body()` sniffs the magic bytes instead of trusting the
   header.
3. **A cap applied and not stated reads as full coverage.** `DiscoveryResult`
   carries `found` and `dropped`, and both the report and the UI print them.

`canonical_url()` is shared by discovery, the crawler and the report, because
two implementations produce `/about` and `/about/` as separate pages and the
report then prints every finding twice with nothing to explain why.

---

## 5. Two passes, because the second needs what the first learns

A page's template class is read from its fetched HTML. The decision about
which pages are worth ninety seconds of browser time is made from the template
classes. So:

1. **Light pass** — the no-browser collectors on every discovered page.
2. **Classify** — WordPress body classes first (`.woocommerce-checkout`,
   `.single-product`, `.single-post`), URL shape as fallback.
3. **Heavy pass** — Lighthouse on one representative per template.

`split_pipeline()` separates them by asking each collector for
`needs_browser`, rather than assuming Lighthouse is the last stage: the
pipeline is a caller-supplied list and a test that appends a stage would
otherwise silently turn its collector into the Lighthouse pass.

### Sampling by coverage, not alphabetically

The obvious ordering is by template name, and it is wrong in a way that is
easy to miss. On the ten-page fixture — home, page, contact, checkout, post×3,
product×3 — an alphabetical pass at `--lh-pages 4` picks checkout, contact,
home and page, and **drops `post` and `product` entirely**. That measures four
pages representing four pages and says nothing about the six that are the
actual site.

Ordering by how many pages a template covers picks home, post, product and
checkout. Ties break on class name then URL, so the choice stays
deterministic: two runs of a site must measure the same pages or every run's
"product page score" is a different product page, which reads as a regression
and is not one.

Measured against the fixture with a real browser: 10 pages, 4 measured, 33
seconds.

---

## 6. Concurrency is two-dimensional now

`http_concurrency` used to bound sites and pages at once, because a site was
one page. At twenty pages per site the naive version is 20 × 20 = 400
concurrent requests. The connection pool would cap that at
`http_concurrency * 2` and the batch would not fall over — it would serialise
unpredictably behind the pool, which is worse than failing because it looks
like it works.

Two semaphores now, and the pool is sized for the real ceiling
(`http_concurrency × page_concurrency`) rather than for sites alone.

**The Lighthouse cap was verified, not reasoned about.** Counting processes
matching the browser flag reports 16, which looks like a five-fold breach of
the cap of 3; Chrome forks a renderer, gpu, zygote and utility process per
instance. Counting **distinct `--remote-debugging-port` values** — one per
Lighthouse instance — reports 3. The cap holds per page. Worth writing down
because the wrong measurement here would have sent someone rewriting a
semaphore that was already correct.

`benchmarkIndex` is a per-page observation, not run provenance: engine
versions are a property of the machine and session and agree across pages,
but the CPU benchmark does not.

---

## 7. The report

**Findings are grouped by rule, with the pages they affect.** The ungrouped
version of the fixture audit is 105 finding rows describing 15 problems, which
is a two-hundred-page PDF that gets skimmed and binned, and which buries the
three findings that only affect `/checkout`.

Grouping happens in the engine's `report` module, not in SQL and not in the
findings engine. The engine evaluates one page's flat `{metric_key: value}`
dict and cannot express "3 of 12 pages"; teaching it to would turn a small
declarative interpreter into code, which is what rule 3 exists to prevent.
Rules fire per page, stay dumb, and aggregation lives with every other
presentation decision.

Three things the first render got wrong:

1. **"1 of 10 page".** The noun has to agree with the total, not the count.
2. **An invalid TLS certificate reported as "1 of 10 pages".** Its
   observations live on the home page because storage is page-keyed, not
   because the problem stops there. A finding whose evidence keys are *all*
   origin-scoped now prints "Site-wide". Understating a critical finding by a
   factor of ten is worse than not scoping it at all.
3. **The frontend reimplemented the grouping** and immediately drifted from
   the model on exactly that point. It renders the engine's grouped findings
   now.

The verdict, the TLS section and the technology fingerprint read
`home_values`, the home page's observations alone. Flattening every page into
one dict renders perfectly and reports whichever page was written last, so a
site's headline score would change depending on which product page sorted
highest.

Pages with no score print **"Not measured"**, never a blank cell: a blank
reads as a zero to some people and as a pass to others, and the honest answer
is neither.

Verified end to end: a 15-page PDF from a real browser audit, containing the
page inventory, the coverage sentence, "Site-wide", "All 10 pages" and "Not
measured".

---

## 8. Metric scope

`Metric.scope` (`page` | `origin`) is declared in the registry, which already
gates every key at collection time. `Metric` is a plain struct built
positionally through `M()`, so `scope` defaults to `page` — a required field
would have broken all ~90 existing entries at load.

TLS and CrUX are origin-scoped: one certificate serves every page, and the
CrUX collector queries the origin, so per-page collection is N identical
results, N handshakes and N times the API quota. Collectors declare it too, so
the filtering happens before the work rather than after it. An end-to-end test
asserts no origin-scoped observation lands on a non-home page.

---

## 9. The bug the old test suite caught

Discovery metadata (`discovery.method`, `discovery.found`, …) is written as
observations, because that is the only per-page store there is. The first
version attached it before the persistence step computed whether the run had
learned anything, so `n_obs` was non-zero for an unreachable host, the run
reported `completed`, the findings engine ran against an empty value set, and
the report told a client that a host nobody reached has no HSTS header.

That is precisely the failure this project's oldest guard exists to prevent,
and it walked around it through the back door. The engine's run test caught it
on the first run. The metadata is now written *after* the check, and the
unreachable-host test guards the ordering explicitly.

---

## 10. One pre-existing bug found on the way in

The report's `stamp` was written so several runs on the same afternoon get
distinct chart labels. It appended the time only when a run was less than 24
hours old and fell back to a date-only form after that, so the five runs
seeded on 2026-07-31 read distinctly that afternoon and collapsed to five
identical "31 Jul" ticks the next morning.

Its own test passed on the day it was written and failed from the following
day onwards. That is the tell: **a test whose result depends on how long ago
the fixture date was is asserting against the clock, not the behaviour.** The
date now always carries its time, only "today" drops it, and the regression
test pins a date in 2020 so no clock can rescue it.

---

## 11. What is deliberately not done

- **CVE matching (5c) and endpoint probing (5d).** These are the two that can
  damage a client relationship rather than merely annoy you, and they should
  land after the plumbing under them is boring. The guardrails live in
  `docs/vulnerabilities.md`.
- **Mixed content from the LHR network log.** The current collector parses the
  markup, which finds declared subresources and misses script-injected ones. A
  browser sees both. The method is recorded as `mixed.method` precisely so the
  report can make the right claim, and so switching to the archived LHR later
  is a change in one place.
- **Per-URL CrUX.** The API accepts a `url` parameter, but most individual
  pages lack the traffic to have a record, so origin-scoped is the honest
  default. `Metric.scope` is where that decision would be revisited.
- **Cross-page rules in the engine.** Rules fire per page; grouping is
  presentation. Keeping the interpreter unable to aggregate is the point.