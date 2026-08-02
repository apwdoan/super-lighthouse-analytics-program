# SLAP: per-page analysis and vulnerability scanning

*Designed 2026-08-02. Extends the roadmap; supersedes nothing. This is a plan,
not a post-build record: everything below is grounded in the current code, but
none of it is built yet, and the sections marked **unverified** are the ones
most likely to change on contact.*

The pivot: a report covers **every page of a site**, not the homepage, and
carries **security vulnerabilities** alongside performance. Both halves export
to the same PDF.

---

## 0. The GUI question, re-answered

**No change. FastAPI + Jinja2 + HTMX on a loopback port, PyInstaller one-dir
bundle, the user's own browser as the window.** Decided 2026-07-31 in
`docs/ui-redesign.md`, built, and still correct.

Per-page strengthens it rather than reopening it:

- A per-page report is a navigable document: a page inventory table, filters by
  template class, drill-down per URL, one sparkline per page. In HTML that is a
  `<table>` and nine lines of SVG. In Qt it is hand-painted `QPainter` widgets,
  because `QtCharts` was excluded from the spec to save ~150MB.
- The volume of rows goes up by an order of magnitude. HTMX partial swaps and
  server-side pagination handle that with no widget code and no virtualised
  list-view work.
- The report preview screen already renders the client's actual HTML. Per-page
  makes that screen more valuable, not less.

Self-contained is already satisfied in the sense the pivot needs: the bundle
carries Python, Node, Lighthouse and Chromium, ~700MB unzipped and ~300MB
zipped, and a teammate installs nothing. Chromium is in there for PDF export
regardless, so using the browser as the window costs zero additional bytes.
PySide6 was built (~2,100 lines, four screens) and retired; that took the bundle
from 933MB to 702MB. Do not re-litigate it.

The stack also already satisfies "Python and JavaScript" without adding
anything: Node's entire footprint is `worker.js` at ~250 lines, and the
front-end JavaScript is HTMX. No bundler, no `node_modules` in the front end,
no build step in the PyInstaller pipeline.

---

## 1. The unit of analysis moves from site to page

### What already works

The storage layer was built page-keyed and does not need a rewrite.
`observation.page_id`, `finding.page_id` and `artifact.page_id` are all foreign
keys to `page`, every read query already joins through it, and `get_findings`
and `get_observations` already select `p.url` alongside. `idx_page_run` is
already there, which is the one index multi-page reads actually need. Whoever
wrote Phase 0 left the door open.

### What breaks

The *cardinality* is hardcoded to one, in a handful of specific places:

| Location | Assumption |
|---|---|
| `core._persist` (core.py:169) | calls `db.create_page` exactly once per run |
| `core.py:517` | `SELECT id FROM page WHERE run_id = ? LIMIT 1` |
| `db.site_metric_history` (db.py:446) | joins observations through page; N pages yields N rows per run and the trend chart doubles up |
| `db.list_sites` (db.py:416) | finding counts multiply by page count |
| `db.findings_across_sites` (db.py:503) | counts findings, not affected sites |
| `report/model.py` | builds one report from one run's single page |

None of these is hard. All of them are silent when wrong: a trend chart with
duplicated points and a site list showing 240 open findings instead of 12 both
render perfectly and look plausible. **Write the aggregation tests before the
discovery code**, because this class of bug is invisible in a screenshot.

### The decision: page is a child of run, not a run of its own

A site audit stays one run. Pages become N rows under it. The tempting
alternative, one run per page, breaks three things:

1. **Provenance is per-session, not per-page.** `lh_version`, `chrome_version`,
   throttling profile and git sha are properties of the machine and the moment.
   Duplicating them across 20 rows invites them to drift and doubles the
   appendix.
2. **Rule 2 dies.** "A report is a pure function of a run id" becomes "a pure
   function of a set of run ids," and every caller has to reconstruct the set.
3. **Trends become a join over an unstable set.** Page counts change between
   audits when a site adds pages. Comparing run to run is arithmetic; comparing
   run-set to run-set is a research project.

### Schema additions

```sql
ALTER TABLE page ADD COLUMN role TEXT;            -- home | template | discovered
ALTER TABLE page ADD COLUMN discovered_via TEXT;  -- sitemap | crawl | manual
ALTER TABLE page ADD COLUMN audit_depth TEXT;     -- full | light
ALTER TABLE page ADD COLUMN template_class TEXT;  -- home, post, product, ...
```

`audit_depth` is stored rather than derived from artifact presence, deliberately.
Deriving it conflates **"Lighthouse was not asked to run on this page"** with
**"Lighthouse ran and failed"**, and those need different sentences in the
report. Storing what was attempted is not redundancy.

Same migration discipline as the SALP → SLAP rename: the DDL is
`CREATE TABLE IF NOT EXISTS`, so these must go in `db.migrate()` guarded on
`PRAGMA table_info`, not into the `CREATE TABLE` body where an existing database
will never see them.

---

## 2. Discovery: sitemap first, crawl fallback

### Where it lives

**Not a collector.** A collector takes a `PageContext` and returns observations
for one URL. Discovery runs before any `PageContext` exists and produces the URL
list itself. It belongs in a new `src/slap/discovery.py` called by `core` as a
pre-stage, not bolted onto the `Collector` protocol. Bending the protocol to fit
would be the first crack in the thing that has kept this codebase clean.

### The sequence

1. `robots.txt` → every `Sitemap:` directive.
2. Failing that, try the conventional locations: `/sitemap.xml`,
   `/sitemap_index.xml` (Yoast), `/wp-sitemap.xml` (WordPress core since 5.5).
3. Failing that, a same-origin breadth-first crawl from the homepage, depth 2,
   honouring `robots.txt` `Disallow`.

### Traps to build against from the start

- **Sitemap index files nest.** A `<sitemapindex>` contains `<sitemap>` entries
  pointing at more sitemaps, not `<url>` entries. A parser that reads the index
  as a page list audits zero real pages and reports success.
- **`.xml.gz` is common** and `httpx` will not transparently decode a body
  served as `application/gzip`. Same failure shape as the `h2` bug: everything
  works, the data is silently empty.
- **Sitemaps routinely list thousands of URLs.** A cap is mandatory, and per the
  no-silent-caps rule, the report must state that it was applied and how many
  URLs were dropped. "12 of 3,400 pages audited" is honest; "12 pages audited"
  against a 3,400-page site is a lie by omission.
- **Reuse `normalize_url`.** Discovery that does its own trailing-slash and
  scheme handling will create `example.com/about` and `example.com/about/` as
  two pages, and the report will print the same findings twice with no
  indication why.
- **Crawl politeness.** Same-origin only, respect `Disallow`, and note skipped
  paths rather than silently omitting them.

---

## 3. The Lighthouse budget

### The arithmetic that forces the decision

Lighthouse is ~90s per page at median-of-3, and concurrency is capped at 3
across the whole batch (rule 9, non-negotiable: contended CPU inflates TBT and
yields plausible irreproducible scores).

| Strategy | 24 sites × 10 discovered pages | Wall clock |
|---|---|---|
| Lighthouse on every page | 240 pages × 90s ÷ 3 | **~2 hours** |
| Lighthouse on ~4 templates per site | 96 pages × 90s ÷ 3 | **~48 min** |
| Homepage only (today) | 24 pages × 90s ÷ 3 | ~12 min |

The middle row is roughly what a full 24-site batch costs today, which is the
argument: template sampling buys per-page coverage for free in wall-clock terms.

### Template classification

Every discovered page gets the cheap collectors, so `HttpCollector` has already
fetched the HTML. Classify from that document, with no additional requests:

- WordPress body classes are the strongest signal: `.home`, `.single-post`,
  `.archive`, `.page`, `.woocommerce-checkout`, `.product`.
- URL shape as a fallback: path depth, `/product/`, `/category/`, `/blog/`.
- Group by class, pick one representative per class, always include the
  homepage, cap at `lighthouse_pages_per_site` (default 5).

### The honest-reporting constraint

Template sampling means **most pages have no performance number.** The report
must not imply otherwise. A page with `audit_depth='light'` shows its security
and header findings and says *"performance not measured on this page"* where the
score would be. An empty cell reads as a zero or as a pass; neither is true.

---

## 4. The four security layers

### 4a. Per-page hygiene

`HttpCollector` and the header/cookie checks already take a `PageContext`, so
running them on every discovered page is mostly wiring. This is also where
per-page earns its keep immediately: an admin or checkout page routinely has
weaker cookie flags than the homepage, and today SLAP never looks.

**But some observations are origin-scoped, not page-scoped.** Running
`TlsCollector` against 20 pages of one host is 20 identical certificate results
and 20 wasted handshakes, and the report would print "certificate expires in 40
days" twenty times.

**Fix: add a `scope` attribute to `schema.METRIC_REGISTRY`** (`origin` vs
`page`). The registry already gates every metric key at collection time
(rule 4), so it is the natural home, and the report can then print origin-scoped
facts once in the site header rather than in every page section. Origin-scoped
collectors run once per run and their observations attach to the homepage row.

`Metric` is `@dataclass(frozen=True, slots=True)` with five fields, all built
through the `_m()` helper, so `scope` needs a default of `page` or every
existing registry entry breaks at import. Default it and annotate only the
handful that are origin-scoped.

**CrUX is the interesting case.** The CrUX API accepts a `url` parameter as well
as `origin`, so per-page field data genuinely exists — for pages with enough
traffic, which most individual pages do not have. Query the origin once, then
query per-URL opportunistically and fall back to origin data with a chip saying
so. At 2/s, 480 page queries across a 24-site batch is about four minutes and
stays well inside the 150/min quota.

### 4b. Mixed content and third-party resources

Mostly **extraction, not collection**: the network records are already in the
gzipped LHR on disk, and re-deriving from archived artifacts is exactly what the
immutable-run design was for.

The catch is that this only covers pages where Lighthouse ran. For `light`
pages, parse the HTML for `http://` subresources. That catches passive mixed
content and misses anything injected by script. **Say which method produced the
finding**, because "no mixed content found" means two different things depending
on the answer.

### 4c. Known-CVE version matching

**The binding constraint is version detection, not the vulnerability database.**
The database is a solved problem. Knowing that a site runs Contact Form 7
*5.8.1* rather than *5.9.x*, from outside, is not.

What is actually detectable from the front end, ranked by trustworthiness:

| Signal | Confidence | Notes |
|---|---|---|
| Lighthouse `js-libraries` audit | **observed** | Runs in a real browser, detects library + version. Already in every LHR you archive. Best source you have, and it is free. |
| `wprocket.version` from the generator meta | **observed** | Already collected |
| WordPress core generator meta | **observed** when present | Frequently stripped |
| `?ver=` on `/wp-content/plugins/<slug>/…` assets | **inferred** | The standard technique and the dangerous one |
| Plugin presence with no version | **none** | Do not guess |

The `?ver=` query string is where false CVEs come from. It is often the plugin's
version. It is also often the WordPress core version, a cache-buster hash, or
absent entirely, because optimisers (including WP Rocket, which SLAP
specifically targets) strip or rewrite it. **A wrong version produces a
confident, specific, wrong CVE in a client-facing PDF**, which is the single
worst thing this project can print.

#### Data sources, researched 2026-08-02

- **OSV.dev** — covers npm, so every JS library with an npm name, including
  jQuery. Bulk `all.zip` per ecosystem on GCS, no auth, no key. **Ships offline
  in the bundle**, which fits the self-contained requirement exactly. Does *not*
  cover WordPress plugins, themes or core.
- **NVD API 2.0** — 5 requests per rolling 30s without a key, 50 with one, and
  NIST's own guidance is to mirror locally via `lastModStartDate` rather than
  query per lookup. Treat it as a feed, not a service.
- **WPScan** — has the WordPress coverage, and its terms are a dealbreaker:
  *"Permanent storage of our vulnerability data is not permitted,"* *"API
  vulnerability data caching is not permitted,"* and commercial integration
  requires an Enterprise account. An offline bundled database is precisely what
  it forbids. **Recording this so it is not re-litigated.**
- **Wordfence Intelligence** — advertises a free WordPress vulnerability feed
  and is the most promising remaining candidate for the WordPress half.
  **Unverified:** its terms and licence pages returned empty to automated
  fetches, so read them by hand before designing against it.

#### Guardrails, non-negotiable

- **Confidence travels with the finding.** Observed versions may state a CVE.
  Inferred versions produce a MEDIUM *possible* finding that names how the
  version was determined and asks the client to confirm. Never a CRITICAL
  assertion from a `?ver=` string.
- **No version, no finding.** Silence is correct.
- **Absence of findings is not a clean bill of health.** The report must never
  print "no known vulnerabilities" when it means "could not determine versions."
  Those are different sentences and the second one is the honest one.
- **The vulnerability database has a date, and it goes in the appendix** with
  the rest of the provenance (rule 6). A bundle built once and run for a year
  carries a year-old database; a report that does not say so is wrong in a way
  nobody can detect.

### 4d. Exposed endpoint probing

Different in kind from everything else here. Every other collector requests
pages the site publishes. This requests things it hopes are not there:
`/.git/config`, `/.env`, `/wp-admin`, `/xmlrpc.php`, backup files.

- **Off by default, per-site opt-in, with the authorization recorded.** A
  `site.probe_authorized_at` and by whom. Not a global config flag: a global flag
  gets switched on once and then silently applies to a client who never agreed.
- **A dozen paths, not a wordlist.** This is a hygiene check, not a pentest.
  Rate-limited, and it should look like it in the target's logs.
- **Never fetch the body.** Record status code and `Content-Length` only. Pulling
  a client's `.env` into your SQLite and your gzipped artifact directory creates
  a custody liability you did not previously have, in a file that gets zipped up
  and emailed around. Status and size are sufficient to raise the finding.
- **403 vs 404 matters.** A 403 on `/.git/config` usually means it is there.
- **WAFs return 200 with a block page.** Check the content shape, not just the
  status, or the first client behind Cloudflare gets a page of false criticals.

---

## 5. What per-page does to the report

**The biggest single decision: group findings by rule, list the affected pages,
do not repeat the finding per page.** Twelve pages missing HSTS is one finding
with twelve pages attached. The naive rendering produces a 200-page PDF that
says the same thing twelve times and gets skimmed and discarded. This is the
same lesson as the top-5 cap that buried `wprocket-cache-cold`, in the other
direction: never let the report's structure obscure the ranking.

Structure:

1. **Verdict** — still site-level. Worst-of across pages, plus coverage: *"3 of
   12 pages have no Content-Security-Policy."*
2. **Page inventory** — a table: URL, template class, audit depth, score where
   measured, open finding count. This is the new section and it is what makes
   the report visibly per-page.
3. **What to fix first** — grouped by rule, affected pages listed per finding.
4. **Security** — origin-scoped facts (TLS, certificate) once; page-scoped facts
   (headers, cookies, mixed content) in the grouped list.
5. **Per-page detail** — only for pages with Lighthouse data or page-specific
   findings. Not one section per page unconditionally.
6. **Appendix** — existing provenance, plus discovery method, the cap applied
   and how many URLs were dropped, and the vulnerability database date.

### The findings engine stays dumb

`rules.yaml` conditions evaluate against a flat `{metric_key: value}` dict for
one page (core.py:208). Cross-page rules ("3 of 12 pages lack CSP") **cannot** be
expressed in that interpreter, and should not be added to it. Rule 3 says the
engine is data; teaching it to aggregate across pages makes it code, with an
`eval`-shaped hole where the small declarative interpreter used to be.

**Fire rules per page and group in `report/model.py`**, where every other
threshold comparison and plain-language sentence already lives (rule 7), and
where it is unit-testable without rendering HTML.

---

## 6. Concurrency becomes two-dimensional

Today `http_concurrency = 20` bounds *sites in flight*, and each site is one
page, so sites and pages are the same number. After the pivot they are not, and
the fan-out multiplies: 20 sites × 20 pages is 400 concurrent requests. The
`httpx.Limits(max_connections=http_concurrency * 2)` pool would throttle that to
40, which means it does not fall over — it just serialises unpredictably, which
is worse than failing, because it looks like it works.

**Bound both levels explicitly.** A site-level semaphore and a page-level one,
separately configured, the same way `LighthouseConfig.concurrency` is already
separate from `CollectorConfig.http_concurrency`.

Two related checks:

- **Verify the Lighthouse semaphore still gates pages.** It is acquired inside
  the runner per invocation (lighthouse.py:539), so it should stay correct
  per-page rather than per-site — but confirm it by counting concurrent Chrome
  processes during a real multi-page run, not by reading the code. Getting this
  wrong produces plausible, irreproducible scores, which is the exact failure
  rule 9 exists to prevent and the hardest to notice after the fact.
- **`benchmarkIndex` becomes per-page.** Provenance is currently set on the run
  from the single page's Lighthouse metadata. With N Lighthouse runs the CPU
  benchmark will differ across them. Record the range, and let
  `lh-contended-measurement` fire on the worst of it rather than on whichever
  page happened to be written last.

---

## 7. Sequencing

**Phase 5a — plumbing.** Discovery, multi-page persistence, the aggregation
query fixes, two-dimensional concurrency, the page inventory section. No new
security surface at all. This alone changes the product, and it is the phase
where the silent-wrong-number bugs live.

**Phase 5b — per-page hygiene.** Registry `scope`, origin-scoped collectors run
once, per-URL CrUX, mixed content extracted from archived LHRs.

**Phase 5c — CVE matching.** npm/OSV first: `js-libraries` gives observed
versions, OSV ships offline, and the confidence story is clean end to end.
WordPress second, and only behind a licence-clean source.

**Phase 5d — endpoint probing.** With the authorization record built first, not
retrofitted.

5c and 5d are the two that can damage a client relationship rather than merely
annoy you. They should land after the plumbing underneath them is boring.

---

## 8. Things that will bite

- Aggregation counts multiplying by page count, silently, in `list_sites`,
  `site_metric_history` and `findings_across_sites`.
- The metric registry rejects unregistered keys at collection time (rule 4).
  This pivot adds a lot of keys. Register first or every new collector raises on
  its first real run.
- `page` columns added to the DDL body instead of `db.migrate()` will never
  reach an existing database.
- Sitemap index nesting and `.xml.gz`, both of which fail by producing an empty
  list rather than an error.
- Discovery that does not reuse `normalize_url`, producing duplicate pages.
- A report that prints a blank performance cell for `light` pages instead of
  saying they were not measured.
- A `?ver=` string treated as a version, producing a confident wrong CVE.

Every significant bug in this project so far was found by building the thing and
running it, not by reading code: the `h2` HTTP/2 misreport, the backend check
that stat-ed a file, the CrUX key that was set and rejected, the disabled
checkbox that looked enabled. Assume the same here, and get to a real
multi-page audit against a real site early.

## Sources

- [NVD API: getting started and rate limits](https://nvd.nist.gov/developers/start-here)
- [OSV.dev data sources and bulk downloads](https://google.github.io/osv.dev/data/)
- [WPScan vulnerability database API terms](https://wpscan.com/api/)
- [Wordfence Intelligence vulnerability data feed](https://www.wordfence.com/help/wordfence-intelligence/v2-accessing-and-consuming-the-vulnerability-data-feed/) *(terms unverified — page did not return content)*
- [CrUX API](https://developer.chrome.com/docs/crux/api)
- [WordPress plugin readme.txt and version exposure](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/)
