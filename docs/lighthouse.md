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
3. **The engine side preferred the crash.** It took the *last* JSON object it
   could find. It now decodes objects one at a time with a streaming
   decoder and takes the *first* envelope. Line splitting could not have
   separated these two anyway, since there was no separator between them.

4. **The throw did not come from the call we were guarding.** `killQuietly`
   wraps the `kill()` the worker awaits, but chrome-launcher *also* calls
   `destroyTmp()` from a `chromeProcess.on('close')` listener, so the error
   arrives as an uncaught exception in an event handler that no try/catch
   around `kill()` can reach:

   ```
   at Launcher.destroyTmp (chrome-launcher.js:353)
   at ChildProcess.<anonymous> (chrome-launcher.js:328)
   ```

   Node's default there is to print the stack and die on the spot. The
   envelope had already been written, but a pipe write is not synchronous,
   so whether the engine saw a complete result or a truncated one was down
   to flush timing. `process.on("uncaughtException")` and
   `("unhandledRejection")` now let the process unwind normally when a
   result has already been delivered.

The worker being well-behaved is what makes 1, 2 and 4 sufficient. 3 exists
because trusting that is how this went unnoticed in the first place.

**How this was verified.** A throw was injected into chrome-launcher's
`destroyTmp()` so cleanup fails on every call, reproducing the CI stdout
byte-for-byte: two concatenated envelopes, exit 1. With the fixes, the same
injection yields one clean envelope, exit 0, the failure on stderr, and a
completed audit. A deliberately broken `CHROME_PATH` still produces a
failure envelope and exit 1, so the fix does not swallow real errors.

## Setup

```bash
cd desktop/worker && npm install   # Lighthouse + chrome-launcher
# the pinned Chrome for Testing is fetched on first use (shared with PDF export)
./target/debug/slap-desktop --self-check     # confirm every backend
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

Lighthouse is a per-run option in New audit, and it starts ticked: the
report's gauges and speed figures come from it, so an audit without it is
the exception. New audit shows what it will cost before anything starts
(about 30 seconds a page at the default concurrency), and unticking it
gives a server-and-security pass in seconds. `[lighthouse] enabled = false`
in `config.toml` makes the box start unticked instead.

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
mapping lives in `schema::LIGHTHOUSE_OPPORTUNITIES`, and
`every_lighthouse_opportunity_registered` fails if any entry drifts from the
Lighthouse 13 names the extractor reads.

A related trap: `audit_savings()` must **not** fall back to `numericValue`
for insight audits. `dom-size-insight`'s `numericValue` is an element
count, so a naive fallback reports "3604ms of saving" in a client report.

**A clean test page cannot catch any of this** — every saving is zero and a
broken extractor looks fine. `desktop/fixtures/slowsite/` is a deliberately
awful page (3.6MB unoptimised PNG, 1500 unused CSS rules, render-blocking
head, 3600-element DOM) served with no compression and no caching, offline.
Against it the extractor produces real savings: image delivery 17.2s,
render-blocking 3.0s, unused CSS 2.2s.

## Architecture

```
slap-engine (Rust)
    │  spawns the Node worker as a subprocess
    ▼
worker/worker.js                      one job on stdin, one LHR on stdout
    │  chrome-launcher
    ▼
Chromium (pinned Chrome for Testing, fetched on first use)
```

**The Node worker is deliberately dumb.** No business logic, no thresholds,
no storage, no formatting. It launches Chrome, runs Lighthouse, writes the
raw LHR, exits. Everything downstream of "what did Chrome measure" is the
engine's job. If you want to add a condition to `worker.js`, it belongs in
the engine's Lighthouse collector or in `rules/rules.yaml` instead.

The worker runs as a plain subprocess, owned by the engine, which keeps it
out of the core: `slap-core` still imports no browser, no Node, and no UI
framework, exactly as the core's own tests enforce.

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
are inside Chrome. The app keeps the two settings separate in its UI; a
single "concurrency" control that moves both would reintroduce exactly this
failure.

Budget for 100 sites, mobile median-of-3, concurrency 3: roughly 50 minutes.

*Not done:* pinning workers to dedicated cores, which the roadmap floats as
an option. Worth measuring on the 7950X before adding the complexity.

## Median and spread

Three runs per site per form factor; the **median** is reported, because a
single Lighthouse run is noise. The median, not the mean: one
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
(`mobile/simulate/lh13-default`). The report's About this report section
prints the Lighthouse version, the Chrome version, the emulated device and
connection, and the number of tests per page; the throttling profile and
benchmark index stay in the app, where the full record is.

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

A pinned **Chrome for Testing**, resolved by `resolve_or_fetch_chrome()` and
passed to the worker as `CHROME_PATH`. Every teammate measures on the
identical build, which is what makes run-to-run and person-to-person
comparison meaningful, and it reuses the same browser the PDF export path
fetches.

The resolution order is `CHROME_PATH`, then the known install location
(a cheap filesystem check), then a first-run download from the Chrome for
Testing CDN — unless the egress policy blocks it, in which case
`CHROME_PATH` is the escape hatch and the runner surfaces a clear
"CHROME_PATH must be set" error rather than a confusing network failure.

## Failure behaviour

Every failure degrades rather than aborts, and says so:

- **Worker not installed / Node missing / probe fails** → the batch logs a
  warning, drops the Lighthouse stage, and runs Phase 1 only. The report's
  About this report section says the audit did not include browser tests.
- **A single run fails or times out** → recorded in the run's errors; the
  median is taken over the runs that succeeded. Timeout kills the process so
  a wedged Chrome does not become a contention source for the rest of the
  batch.
- **Lighthouse `runtimeError`** (the page never loaded) is treated as a
  failed run rather than stored, so a run full of zeroes never reaches the
  report looking like real measurements.

The app's self-check reports on all of it in one place, which exists
precisely because every one of these degrades quietly by design.

## Rules and the WP Rocket mapping

`rules/rules.yaml` carries the `lh-*` rules keyed off `lh.opp.*` and
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

- Desktop form factor is wired through (the worker takes a `formFactor`
  per run) but the app ships mobile-only. Google ranks mobile-first and
  CrUX field data is phone-only, so the default matches the verdict page.
- No trend or before/after comparison yet; that is Phase 4, and the
  immutable-run design already makes it cheap.
- No core pinning, no `throttlingMethod: provided` for real-device
  measurement.
