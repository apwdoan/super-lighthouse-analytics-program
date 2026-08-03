# SLAP: known vulnerabilities and endpoint probing

*Built 2026-08-02. Phases 5c and 5d of `per-page-and-vulnerabilities.md`.*

The two features that can damage a client relationship rather than merely
annoy the operator. Almost everything below is a guardrail, and each one was
measured against a fixture built to defeat it rather than assumed to work.

---

## 1. Version detection is the binding constraint

The database is a solved problem. Knowing from outside that a site runs
Contact Form 7 *5.8.1* rather than *5.9.x* is not, and **a wrong version
produces a confident, specific, wrong CVE in a client PDF**, which is the
worst thing this project can print.

So confidence is a property of every component and it travels to the report:

| | Source | May print |
|---|---|---|
| **observed** | Lighthouse read the version off the *running* library; or the software announced itself in a generator tag | the CVE at its real severity |
| **inferred** | a `?ver=` query string on an asset URL | a *possible* finding, capped at medium, naming how the version was determined |

### The find that made this buildable

Lighthouse 13's `js-libraries` audit returns

```json
{"name": "jQuery", "version": "3.4.1", "npm": "jquery"}
```

The **npm coordinate** is the part that matters. It maps straight onto OSV's
npm ecosystem with no name guessing, so the highest-confidence version source
is also the one with the cleanest database behind it. A row without an `npm`
key is dropped rather than name-matched: guessing that "Kendo UI" is npm's
`kendo-ui-core` is how a version gets matched against another package's
advisories.

The audit reads `jQuery.fn.jquery` off the live `window`, which is worth
knowing when writing a fixture — the first version of ours served a file
containing only `/*! jQuery v3.4.1 */` and detected nothing, correctly.

### What `?ver=` actually contains

Three of the four asset versions on the test fixture are *not* the
component's version, which is the normal case on a real WordPress site:

```html
<script src="/wp-content/plugins/contact-form-7/…?ver=5.8.1">   <!-- real -->
<script src="/wp-content/plugins/akismet/…?ver=6.5.2">          <!-- WP core -->
<script src="/wp-content/plugins/wp-rocket/…?ver=1699887600">   <!-- timestamp -->
<link  href="/wp-content/themes/astra/style.css?ver=a3f9c2e1">  <!-- hash -->
```

Three guards, in `parse_version` and `wordpress_assets`:

- a value that does not parse as a version yields no component;
- **a single integer above 1000 is a timestamp, not a version**;
- a `?ver=` equal to the WordPress core version on the same page is discarded,
  because WordPress substitutes core's version for any asset that does not set
  its own, and treating that as the plugin's version matches every plugin on
  the site against core's number.

`INFERRED_SEVERITY_CEILING` is `medium` and applies whatever the advisory
says. A CVSS-critical matched against a number scraped from a query string is
still a guess, and printing CRITICAL next to a guess spends credibility that
is hard to earn back.

---

## 2. The database: local, dated, curated

**Local.** Matching runs against a file on disk, never a live API call during
an audit. A per-audit lookup sends a client's component inventory to a third
party, which is not a thing to do quietly on a client's behalf, and a
rate-limited dependency mid-batch turns a network hiccup into a report that
silently finds nothing.

**Dated.** `generated_at` is printed in the report appendix beside the
Lighthouse and Chrome versions, and the Settings page's Backends card
marks it stale past 30
days. A bundle built once and run for a year carries a year-old database, and
a report that does not say so is wrong in a way nobody can detect.

**Curated.** A full vulnerability corpus is hundreds of megabytes and SLAP
can only name the components its detectors recognise. The database holds
exactly those: **616 advisories in ~460KB** from the NVD build on
2026-08-02, which ships in the bundle. A database wider than the detection
is dead weight; narrower would be a silent gap.

### Sources (revised 2026-08-02: NVD is primary)

| Source | Status |
|---|---|
| **NIST NVD** | **Primary.** The [CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), queried by CPE per tracked product. Keyless at 5 req/30s (a full refresh is ~5 minutes), or 50 req/30s with a free key via `NVD_API_KEY` (~40 seconds). CVSS severity comes from NIST's own analysis, permanent storage is permitted, and it covers what no free WordPress-specific source could: **WordPress core (350 usable CVEs) plus the most common plugins**. Fair use requires the notice in `NVD_NOTICE`; the report appendix prints it. |
| **OSV.dev** (npm) | Retained as an alternative, and selectable beside the update button on the Settings page. No key, no CPE map to maintain, npm only. |
| **WPScan** | **Ruled out on licence.** "Permanent storage of our vulnerability data is not permitted", "API vulnerability data caching is not permitted", and commercial integration requires an Enterprise account. An offline bundled database is precisely what it forbids. |
| **Wordfence** | Was free and unauthenticated when this was designed. As of 2026-08-02 the v2 endpoints return **410 Gone** and v3 returns **401**. NVD made the question moot. |

**The CPE map is verified, not guessed.** NVD answers a wrong CPE with zero
results, and zero results is exactly what a clean product returns, so an
unverified guess ships a coverage gap disguised as good news. Every entry
in `NVD_PRODUCTS` was probed live before being added, with the CVE count at
verification recorded beside it; candidates that returned zero
(`vuejs:vue`, `backbone.js_project:backbone.js`, `wp_media:wp_rocket`) were
dropped, not kept on faith. The flip side is that coverage is **per
package, not per ecosystem**: `covered_packages` records exactly which
packages were queried, `covers(ecosystem, package)` answers at that level,
and a detected plugin outside the map is reported as *not checked*.

Two NVD records shapes worth remembering: old CVEs recorded against version
`-` ("unknown") with no bounds are **dropped** rather than matched against
every version forever (jQuery's CVE-2007-2379 would otherwise flag jQuery
3.7 on every audit), and v2-only records top out at HIGH because CVSS v2
never defined CRITICAL.

Unmapped WordPress plugins and themes remain **inventoried and not
matched**, and `vuln.unchecked_count` exists so the report can say that.
*"No vulnerabilities
found in your plugins"* and *"your plugins were not checked"* are different
sentences, and only the second is true. `VulnDatabase.covers()` is what forces
the caller to pick the right one rather than defaulting to silence.

### Two bugs the real data caught

**Severity read as `info`.** OSV puts the severity word in
`database_specific.severity` at the **top level**. The first implementation
read `affected[].ecosystem_specific.severity`, which is `null` on every GitHub
advisory, so a prototype-pollution CVE came out rated `info` and would have
been filed under "also worth addressing" in a client report. When a feed has
three plausible places for a field, check which one it actually populates
against a real record rather than taking the first the schema allows.

**Aliased advisories double-counted.** GHSA re-issues advisories and aliases
the old id to the new one; lodash carries `GHSA-f23m-r3pf-42rh` and
`GHSA-xxjr-mmjv-4gpg`, both aliased to CVE-2025-13465, describing one bug.
Keying on the record id reported it twice and inflated every count a client
reads. `deduplicate()` keys on the CVE, keeping the most severe record, and
runs on query rather than on build so an older database also reports honestly.

*(An aside worth keeping: lodash 4.17.21 really does carry open advisories in
2026. The first expectation written for it was wrong, not the matcher.)*

---

## 3. Endpoint probing

Different in kind from everything else in the pipeline. Every other collector
requests pages the site publishes; this one requests things it hopes are not
there.

**Authorised per site, never globally.** A global flag gets switched on once
for a client who agreed and then silently applies to the next one.
Authorisation lives on the `site` row with a timestamp and a name, the
approver is required, and the report prints it. `probe_enabled` *and*
per-host authorisation are both required, so a config left switched on
probes nothing.

**Both switches live on the Settings page** (2026-08-03), alongside `slap
probe allow/revoke` and `audit --probe`. The card states what the pair of
them will actually do, because that is where the two-key design can
mislead: a screen showing only the global switch reads as "on" while every
audit quietly probes nothing. "Probing is on, but no host is authorised, so
no audit will probe anything" is the sentence that stops someone believing
a check ran.

Adding the UI turned up why nobody had used the feature: **`Settings.load`
never read `probe_enabled` from `config.toml`.** The field existed, the
audit pipeline honoured it, `slap probe allow` closed by telling people to
set it in `config.toml`, and that instruction did nothing whatsoever. The
only working route was `audit --probe`. The loader reads it now, and a
round-trip test covers the setting the tool had been recommending for
months. One TOML trap is worth knowing if this is extended: a bare key
written after `[collector]` belongs to *collector*, so a top-level setting
cannot be appended to the end of the file.

**Origin-scoped**, so it runs once per site however many pages are audited.
Probing sixteen paths twenty times is twenty times the noise in the client's
access log for the same answer.

**Nothing from a probed path is stored.** A 512-byte prefix is read to
classify the response and dropped; only status, length and the verdict
survive. Pulling a client's `.env` into a SQLite file that later gets zipped
up and emailed creates a custody problem the audit did not start with. A test
asserts the fixture's literal secrets never reach the database.

### The three guards, measured

A WAF returns 200 with a block page. Plenty of sites return 200 with their
homepage for every unknown path. Status codes alone would hand the first
client behind Cloudflare a page of false criticals.

1. **Control calibration** — two requests for random paths that cannot exist,
   learning this origin's "not found". Two rather than one, because a 404 page
   that echoes the path back varies per request, and comparing them is how you
   tell a templated 404 from a static one.
2. **Block-page detection** — if a firewall answers the control, the probe
   *stops* rather than continuing and reporting sixteen identical criticals.
3. **Content signature** — the body must actually be the thing the path
   implies. `[core]` and `repositoryformatversion` for a git config, not
   merely a 200.

Measured against the fixtures with each guard disabled in turn:

| Fixture | No guards | Calibration only | Signature only | Shipped |
|---|---|---|---|---|
| Genuinely exposes 3 files | 3 | 3 | 3 | **3** |
| 200-with-homepage for everything | 16 | 1 | 0 | **0** |
| Cloudflare block page | 16 | — | — | **0**, probe halted |

The guards are independent and each catches what the others do not:
calibration handles the bulk soft-404 case, the signature catches paths whose
response merely *differs* from the homepage (`/wp-content/debug.log` returning
an asset stub was the one that slipped through calibration), and the block
check stops the run entirely.

A `403` where the control is `404` is recorded but never `confirmed`: it
usually means the file is there, and the content that would confirm it is
exactly what is being withheld.

---

## 4. Reporting

Both features are surfaced as **statements about scope**, before any result:

> Components were checked against npm (OSV.dev), last updated 0 day(s) ago.
> Components in wordpress, wordpress-plugin have no configured source and were
> NOT checked, which is not the same as finding nothing wrong with them.
> Endpoint probing was not run against this site, so nothing here speaks to
> whether files such as .env or .git are publicly readable.

`probe_note` returns that last sentence **even when probing was never switched
on**. The first version returned `""` in that case, which is the exact failure
the section exists to prevent: a reader looking at a page headed "Security"
reasonably assumes exposed files were among the things checked, and silence
lets them keep assuming.

Two reporting bugs found by reading the rendered PDF rather than the code:

**The CVE numbers never reached the page.** A medium-severity finding lands in
the compact "also worth addressing" list, which prints the title only. "2
known vulnerabilities" is not something a client can act on. The identifiers
now go in the **title**, because the title is the one string that survives
every rendering path — the compact list, the CLI's default output and the web
UI's rows all drop the detail.

**Every exposure rule recited every finding.** One shared `exposure.paths`
meant the version-control rule told the client that `/.env` and `/backup.sql`
are git metadata. Each category has its own path list now.

---

## 5. What building and running the bundle taught

The design was verified against fixtures; the bundle was verified by running
it. Three bugs only the second found, and one measurement.

**`vulndb update` wrote inside the bundle.** `_internal/slap/data/vulndb.json`
is inside the application: read-only in Program Files or /Applications,
signature-breaking in a macOS `.app`, and silently discarded by the next
upgrade even where the write succeeds. A teammate would have no way to tell
why their data kept aging. Refreshes go to the per-user data directory now,
and `default_vulndb_path()` picks **whichever copy is newer by the date it
carries** — not "the user's copy wins", because a teammate who refreshed in
January and installs a June bundle should get June's data.

**A rebuild silently produced a smaller database.** Forty minutes after a good
build, `angular` came back with zero advisories instead of fifteen. No
exception, no failed request, nothing in the output to distinguish it from a
package that genuinely has none — OSV rate-limits bursts by answering rather
than refusing. A quietly smaller database is the same failure as a stale one:
every audit afterwards reports less and looks clean doing it. `build_from_osv`
now takes the previous database as a baseline, retries a package that returns
empty when it previously had entries, and records anything still failing in
`failures`; both the CLI and the build script refuse to write a degraded
result. The retry alone recovered the missing fifteen.

**Path resolution cost 5ms per `Settings()`.** It loaded and parsed up to two
108KB JSON files to compare two dates, on every CLI invocation and every test.
`read_stamp` does a bounded read for the field, falling back to a real parse
on an unexpected layout because a wrong answer silently picks the older
database. 5.1ms → 0.17ms.

**The component pass never ran in the default configuration.** Driving the
bundled *web server* rather than its CLI, an audit came back with no
`component.*` observations at all. `collect_site` returned early when the
browser pipeline was empty, and that early return skipped the final pass along
with it. Lighthouse is opt-in, so that is the DEFAULT: every audit without
`--lighthouse`, including every audit the web UI starts, did no component
detection and no CVE matching. Nothing raised, the run completed, and the
report printed *"components were checked against npm (OSV.dev)"* having
checked nothing.

Every test missed it for one reason: the ones that exercised components
through `run_batch` all enabled Lighthouse, and the ones that ran with it off
called the collector directly. Neither shape covered the configuration almost
every real run uses. Three regression tests now do, each verified to fail
against the old code.

The two passes are independent — the browser pass needs pages to *measure*,
the final pass needs pages to *read* — and only the first is conditional now.

The build itself: 919MB, of which 719MB is runtime (Chromium, Node,
`node_modules`) and the vulnerability database is 108KB. It runs under
`env -i` with no PATH beyond `/usr/bin`, resolves every backend inside itself,
and produces the report in §4 from a real browser audit. The bundled **web
server** was driven too, not just the CLI: it is what a teammate gets when
they double-click, and it is the path that surfaced the bug above.

### The CI gate

`--require-vulndb` makes a network failure fail the job rather than fall back
to the committed copy: a developer building on a train should still get a
bundle, a release must never ship data older than the tag it is named after.
The verify step asserts `[ok ] Vulnerability database` alongside the existing
Lighthouse and PDF assertions, and separately asserts the path the bundle
resolves is **inside the bundle** — a database picked up from the build
machine's home directory would pass the first check and ship nothing.

`MAX_VULNDB_AGE_DAYS = 14` fails the build outright. The report would still
print its own date, which is the design working, but nobody reads an appendix
before trusting a headline.

---

## 6. What is deliberately not done

- **A WordPress vulnerability source.** The adapter shape is there and the
  ecosystem strings are wired through; what is missing is a feed that permits
  offline use. If Wordfence credentials become available, it is a source entry
  and a parser, not a redesign.
- **Active exploitation checks.** SLAP reports that a version is affected by a
  published advisory. Whether the vulnerable code path is reachable on a
  particular site is a different question and not one a remote audit can
  answer honestly.
- **CVSS base-score computation.** The severity word GHSA publishes is used;
  the vector is banded only as a fallback. A score that is subtly wrong is
  worse here than an honest band.
- **A wordlist.** Sixteen paths is a hygiene check. Anything longer is a
  penetration test, which needs a different conversation with the client than
  the one the Settings page records.
