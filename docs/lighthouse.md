# Phase 2: the Lighthouse runner

*Built 2026-07-31, verified against Lighthouse 13.4.1 and Chromium 141.*

## The worker's answer is its first envelope

A Windows build reported `worker_crashed` on a probe that had already
succeeded. The stdout said so plainly once it was printed:

```
{"ok":true,"meta":{"lighthouseVersion":"13.4.1",...}}{"ok":false,"code":"worker_crashed","error":"Error: EPERM, Permission denied: ...\Temp\lighthouse.60430772"}
```

A complete, correct result, immediately followed by a crash. `chrome-launcher`
deletes its temp profile inside `kill()`, and on Windows that races Chrome's
own shutdown and throws `EPERM`. The rejection escaped the `finally` block,
reached `main().catch()`, and emitted a second envelope. **A finished audit
was reported as a crash because a temp folder could not be deleted.**

Three things were wrong, and all three are worth keeping fixed:

1. **Cleanup could fail a run.** `chrome.kill()` now goes through
   `killQuietly()`, which retries briefly, because across a 100-site batch
   each leaked profile is tens of megabytes, and then gives up to stderr.
   Cleanup is not the job.
2. **The worker could contradict itself.** `emit()` is write-once. A late
   failure after a delivered result goes to stderr and exits with the status
   the result earned. Envelopes are also newline-terminated now, so two can
   never be concatenated into one unparseable line.
3. **The Python side preferred the crash.** It took the *last* JSON object it
   could find. It now decodes objects one at a time with `raw_decode` and
   takes the *first* envelope. Line splitting could not have separated these
   two anyway, since there was no separator between them.

The worker being well-behaved is what makes 1 and 2 sufficient. 3 exists
because trusting that is how this went unnoticed in the first place.

## Setup

```bash
cd src/slap/node_worker && npm install       # Lighthouse + chrome-launcher
cd -
playwright install chromium                  # the pinned browser (shared with PDF export)
slap doctor                                  # confirm every backend
```

Run npm from *inside* the worker directory. `npm install --prefix <dir>`
looks correct and works on macOS and Linux, but on Windows npm ignores the
prefix and reads the current directory's package.json, failing at the repo
root with `ENOENT ... package.json`. That is [npm/cli#7722], open since
2015. It cost a Windows CI build, and the platform-specific nature is the
whole problem: it passes everywhere you are likely to test it.

[npm/cli#7722]: https://github.com/npm/cli/issues/7722

Node **>= 22.19** is required; Lighthouse 13 declares it in `engines` and
fails on older LTS in ways that do not obviously point at the Node version.

Then:

```bash
slap audit example.com --lighthouse
slap audit -f sites.txt --lighthouse --lh-runs 3 --lh-concurrency 3
```

Off by default. Phase 1 alone takes seconds per site; enabling Lighthouse
takes it to roughly 90 seconds per site, so it is an explicit choice rather
than a surprise.

## The thing that would have silently broken this

**Lighthouse 13 replaced the classic opportunity audits with "insights" and
moved the savings API.** Every audit ID the industry still quotes is gone:

| Pre-13 audit ID | Lighthouse 13 |
|---|---|
| `render-blocking-resources` | `render-blocking-insight` |
| `uses-long-cache-ttl` | `cache-insight` |
| `modern-image-formats`, `uses-optimized-images`, `offscreen-images`, `uses-responsive-images` | `image-delivery-insight` (all four merged) |
| `font-display` | `font-display-insight` |
| `legacy-javascript` | `legacy-javascript-insight` |
| `third-party-summary` | `third-parties-insight` |
| `dom-size` | `dom-size-insight` |

And savings moved from `details.overallSavingsMs` to
`metricSavings: {FCP, LCP, INP}`.

Writing the extractor from memory produces rules that never fire and an
audit that reports nothing wrong, which is far worse than an error. The
mapping lives in `schema.LIGHTHOUSE_OPPORTUNITIES`, and
`test_opportunity_ids_are_lighthouse_13_names` fails if any pre-13 ID
creeps back in.

A related trap: `_audit_savings()` must **not** fall back to `numericValue`
for insight audits. `dom-size-insight`'s `numericValue` is an element
count, so a naive fallback reports "3604ms of saving" in a client report.

**A clean test page cannot catch any of this** — every saving is zero and a
broken extractor looks fine. `tests/fixtures/slowsite/` is a deliberately
awful page (3.6MB unoptimised PNG, 1500 unused CSS rules, render-blocking
head, 3600-element DOM) served with no compression and no caching, offline.
Against it the extractor produces real savings: image delivery 17.2s,
render-blocking 3.0s, unused CSS 2.2s.

## Architecture

```
slap.core (Python)
    │  asyncio.create_subprocess_exec
    ▼
src/slap/node_worker/worker.js         one job on stdin, one LHR on stdout
    │  chrome-launcher
    ▼
Chromium (pinned, via Playwright)
```

**The Node worker is deliberately dumb.** No business logic, no thresholds,
no storage, no formatting. It launches Chrome, runs Lighthouse, writes the
raw LHR, exits. Everything downstream of "what did Chrome measure" is
Python's job. If you want to add a condition to `worker.js`, it belongs in
`collectors/lighthouse.py` or `findings/rules.yaml` instead.

`asyncio.create_subprocess_exec`, **not** Qt's `QProcess`, even though
`QProcess` is the nicer API: the subprocess belongs to the core and the core
does not import Qt.

## Concurrency

**`LighthouseConfig.concurrency` is a separate setting from
`CollectorConfig.http_concurrency`, and this is the single most important
thing in Phase 2.** Defaults are 3 and 20 respectively.

Contended CPU inflates Total Blocking Time and Time to Interactive, so a
wide fan-out produces a batch of plausible, irreproducible, pessimistic
scores. They look fine. A client who re-tests on web.dev and sees a better
number stops trusting the whole report.

The runner holds its own semaphore, and Lighthouse is its own pipeline
stage, so 20 sites can be in flight on the network collectors while only 3
are inside Chrome. The CLI keeps the flags separate (`-c` vs
`--lh-concurrency`) and the GUI must not offer a single "concurrency"
control that moves both.

Budget for 100 sites, mobile median-of-3, concurrency 3: roughly 50 minutes.

*Not done:* pinning workers to dedicated cores, which the roadmap floats as
an option. Worth measuring on the 7950X before adding the complexity.

## Median and spread

Three runs per site per form factor; the **median** is reported, because a
single Lighthouse run is noise. `statistics.median`, not the mean: one
outlier run should not move the number.

The **spread** (max − min) is recorded beside it for LCP, TBT, the
performance score, and the CPU benchmark. This is what the roadmap means by
"if the spread is wide, say so on the report rather than hiding it" — the
`lh-unstable-measurement` rule fires when the performance score moved more
than 10 points or LCP more than 1.5s across runs, and the report says so in
plain language.

A metric present in only some runs is aggregated over the runs that have
it, never treated as zero.

## benchmarkIndex, the contention canary

Lighthouse measures the CPU of the machine taking the measurement and
reports it as `environment.benchmarkIndex`. It is captured on every run as
`lh.benchmark_index`, with its spread.

This is direct evidence for the concurrency warning above: a low or
unstable benchmark index means the lab numbers are pessimistic for reasons
that have nothing to do with the site. `lh-contended-measurement` fires
below 1000, or when the spread exceeds 500, and says so on the report.

It fires on this project's own CI sandbox, which is the correct answer.

## Provenance

Every run records `lh_version`, `chrome_version`, and `throttling_profile`
(`mobile/simulate/lh13-default`), and the report prints all three plus the
run count and benchmark index in its appendix.

One subtlety: Chrome's user-agent string reports a **reduced** version
(`141.0.0.0`), so the LHR-derived value loses the build number. The worker's
`--probe` asks Chrome directly and gets `141.0.7390.37`, and the runner
prefers that. Precision is the entire point of recording it.

## Artifacts

Each raw LHR is gzipped to
`artifact_dir/<batch_id>/<hostname>-<form_factor>-<n>.lhr.json.gz`
(~600KB each, from ~4MB of JSON) with a SHA-256, and referenced from the
`artifact` table.

Never parse an LHR twice: extract once into `observation`, keep the blob for
forensics and for re-deriving findings when a rule changes. That last part
is what makes the rules-are-data design pay off — a threshold change can be
replayed against archived runs without re-auditing anything.

## Chrome selection

Playwright's pinned Chromium, resolved by `default_chrome_path()` and passed
to the worker as `CHROME_PATH`. Every teammate measures on the identical
build, which is what makes run-to-run and person-to-person comparison
meaningful, and it reuses the browser already installed for PDF export.

**`default_chrome_path()` must not be called from inside a running event
loop** in its Playwright-API path, which is why the runner resolves it
through `asyncio.to_thread`. It tries `CHROME_PATH`, then a filesystem scan
of the Playwright browsers directory (cheap, no loop constraint), then the
sync API. This is the same trap as the sync PDF wrapper, and it surfaces as
a confusing "CHROME_PATH must be set" error that does not point back here.

## Failure behaviour

Every failure degrades rather than aborts, and says so:

- **Worker not installed / Node missing / probe fails** → the batch logs a
  warning, drops the Lighthouse stage, and runs Phase 1 only. The report's
  appendix says no lab audit was run.
- **A single run fails or times out** → recorded in the run's errors; the
  median is taken over the runs that succeeded. Timeout kills the process so
  a wedged Chrome does not become a contention source for the rest of the
  batch.
- **Lighthouse `runtimeError`** (the page never loaded) is treated as a
  failed run rather than stored, so a run full of zeroes never reaches the
  report looking like real measurements.

`slap doctor` reports on all of it in one place, which exists precisely
because every one of these degrades quietly by design.

## Rules and the WP Rocket mapping

`findings/rules.yaml` gained 17 `lh-*` rules keyed off `lh.opp.*` and
`lh.score.*`. This is where the roadmap's WP Rocket remediation mapping
landed, attached to each rule's `wp_rocket_setting` field rather than kept
in a separate file, so a rule and its fix cannot drift apart:

| Finding | WP Rocket setting |
|---|---|
| `lh-render-blocking` | File Optimization > Optimize CSS delivery; Load JavaScript deferred |
| `lh-unused-css` | File Optimization > Remove Unused CSS |
| `lh-unused-js`, `lh-third-parties`, `lh-heavy-main-thread` | File Optimization > Delay JavaScript execution |
| `lh-unminified-assets` | File Optimization > Minify CSS / JavaScript files |
| `lh-image-delivery` | Media > LazyLoad, Add missing image dimensions |
| `lh-lcp-discovery` | Media > Excluded images or iframes |
| `lh-font-display` | Preload > Fonts preloading |
| `lh-document-latency` | Preload > Preload Cache; Advanced Rules > Never Cache URL(s) |

## What Phase 2 does not do

- Desktop form factor is available (`--lh-desktop`) but off by default.
  Google ranks mobile-first and CrUX field data is phone-only, so the
  default matches the verdict page.
- No trend or before/after comparison yet; that is Phase 4, and the
  immutable-run design already makes it cheap.
- No core pinning, no `throttlingMethod: provided` for real-device
  measurement.
