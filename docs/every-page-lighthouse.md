# Lighthouse on every page

*Built 2026-10-05. Extends per-page analysis (`per-page.md`).*

SLAP has always run full, self-hosted Lighthouse; what it did not do was run
it on every page. Discovery finds every page, but the browser audit measured
one representative per template, capped at five a site. This adds a coverage
mode, and the machinery a many-hour batch needs to finish.

## The setting

`[lighthouse] scope` in `config.toml`: `"sampled"` (the default) or
`"every_page"`. It lives in `[lighthouse]` because that section ignores
unknown keys, so an older build reading the same file is unaffected. A typo
falls back to `sampled` rather than refusing to load. New audit and
Settings → Lighthouse both set it.

The mode is recorded on the run (`run.lh_scope`, added by migration) and
printed by the report: "All 20 pages found on the site were tested" and "5 of
20 pages were tested: one of each type of page" are different claims, and the
reader must not have to infer which one they are reading.

## Cost

Median of 3 runs, ~30 seconds a run, 3 at a time: every page costs about 30
seconds of wall clock.

| Batch | Sampled | Every page |
|---|---|---|
| 24 sites × 10 pages | ~48 min | ~2 h |
| 100 sites × 20 pages | ~4.2 h | ~16.7 h |

The concurrency cap does not rise to compensate. Contended CPU inflates TBT
and produces plausible, irreproducible scores, and that does not change because
there are more pages.

Before an every-page batch starts, New audit runs discovery alone
(`estimate_audit`, nothing measured, nothing written) and shows the page count,
the duration and the disk it will take.

## Queue order

`run::lighthouse_order`: home first, then one page of each template, the
templates covering the most pages first, then every remaining page in the same
coverage order. Sampled mode is exactly the first `lighthouse_pages_per_site`
of this order, so the two modes agree on what matters most. A batch stopped at
hour six has measured the representative pages, not an alphabetical prefix.
The order is a pure function of the stored pages and their templates, so a
resumed run continues in the same order.

## Surviving the night

Nothing is held in memory until the end any more.

- **Every run of a batch is written as `pending` before work starts**, with
  the URL it was asked to audit (`run.requested_url`). A batch interrupted at
  site 40 of 100 still knows about sites 41 to 100.
- **The light pass is one transaction.** A run with page rows has a complete
  light pass; pages queued for Lighthouse are marked `audit_depth = full`
  at that point, because depth records what was attempted.
- **Each Lighthouse page is one transaction**, written the moment its median
  is known: its observations, its artifacts, and (on the run's first success)
  the run's provenance. `lh.runs` is written for success and failure alike, so
  "queued and no `lh.runs`" is the exact definition of "still to do".
- **Findings are evaluated once, at finalisation**, from the stored
  observations. They are a pure function of observations, and a resumed run's
  pages gained observations after any earlier evaluation would have run.
  Finalisation is one transaction: a run is finished or resumable, never half.

**Stop** stops new work. Pages already inside Chrome finish and are written;
killing Node would orphan Chrome, since chrome-launcher cleans up in exit
handlers that a hard kill skips. Stopped runs stay `pending`/`running`, which
the UI shows as Interrupted when no audit is live.

**Resume** (`run::resume_runs`) continues a run in place, unless the engine
changed. A run's Lighthouse and Chrome versions come from the worker's
`--probe`, which asks the browser directly (`141.0.7390.37`; an LHR's user
agent says `141.0.0.0` and cannot tell two builds apart). If either version,
or SLAP's, differs from the one recorded, the old run is closed as cancelled
with the reason and the site is audited afresh as a new run in the same batch.
Mixing engines inside one run would make its pages incomparable under a single
provenance line. Probing is never resumed: authorization is given per batch.

## The concurrency cap, which was not enforced

The Python app held a Lighthouse semaphore separate from `http_concurrency`.
The Rust port ran each site's Lighthouse pages one at a time but ran up to
`http_concurrency` (20) sites at once, so a 20-site batch could have 20
Chromes in flight. There is now one `tokio::sync::Semaphore` per session with
`[lighthouse] concurrency` permits (3, clamped to 1..=4), shared by every
site, and a single large site may use all of them. The end-to-end test counts
pages between `page_started` and `page_finished` and asserts the peak.

## Machine stability

Over hours, a laptop warms up, throttles, or goes onto battery, and its speed
changes between the first page and the last. Each page's own `benchmarkIndex`
can look fine while pages measured hours apart are not comparable. On
finalisation the home page gets run-level, origin-scoped observations
(`lh.run.pages_*`, `lh.run.benchmark_min/max/drift`), and a new rule,
`lh-benchmark-drift`, fires above 20% drift. Its evidence is all
origin-scoped, so it describes the run rather than one page, as the TLS
findings that used to read "/ (home)" now describe the whole site. It is an
info rule about the test machine, not the site, so the report lists it under
"Notes on these results" rather than with the things to fix.

The shell holds a keep-awake assertion for the length of a batch
(`SetThreadExecutionState` on Windows, `caffeinate -i -w` on macOS,
`systemd-inhibit` on Linux), and New audit warns before a long batch starts
on battery.

## Artifacts and disk

Per measured page, under `artifact_dir/<batch>/<host>/`:

- `page-<id>.lh-summary.json.gz`, always: a few KB. Failing and informative
  audits per Lighthouse group, passed/manual/not-applicable counts, metric
  ratings and runtime settings. The report is drawn from these.
- `page-<id>.lhr.json.gz`, when `[lighthouse] keep_artifacts` (default on):
  the median run's full LHR, about 600 KB. One of the three runs, not all
  three.

2,000 pages is about 1.2 GB with full reports, about 12 MB without. Both are
rows in the `artifact` table, so deleting a site removes them.

## The window no longer freezes

`start_audit` was a synchronous Tauri command, and Tauri runs those on the
main thread: the window stopped repainting for the length of an audit, and the
progress events could not be delivered. It is async now and awaits the audit
thread. That made the activity dock possible: pages in Chrome, pages measured
of planned, failures, an ETA (the configured pace until the batch has two
minutes of its own throughput), and Stop.

Progress has two phases, and both show which page they are on. **Scanning**
(the no-browser fetch of every discovered page, a few at a time) reports
`pages_discovered` once discovery knows a site's page count, then
`page_scan_started` and `page_scanned` for each page; **Lighthouse** reports
`pages_planned`, then `page_started` and `page_finished`. New audit shows both
as progress bars under the Run button, with the pages being scanned and the
pages in Chrome right now; the dock shows the same state on every other
screen, and steps aside while that panel is on screen. It listens to `slap://progress` for
as long as the app is open, so it survives navigation.

## Tests

- `crates/slap-engine/tests/every_page.rs`: two sites, every page, through
  the real runner, the real database and a real subprocess (a stand-in Node
  worker that answers with the recorded LHR). Asserts the global cap, per-page
  artifacts, provenance from the probe, run-level drift and its finding; Stop
  after three pages then resume, with nothing measured twice; a resume refused
  under a different Chrome; and sampled mode unchanged. Skipped where Node is
  absent.
- Unit tests for the queue order, the estimate arithmetic, the resume
  blocker, the LHR summary (against the slowsite fixture), Lighthouse's
  metric display and rating bands, and Site-wide scoping.
- Verified by hand against real Lighthouse 13.5.0 and Chromium 141 on the
  slowsite fixture served as a six-page site: 6 of 6 measured, provenance from
  the probe, the drift rule firing on a two-core machine running three Chromes.

## Not done

- **A single-run speed lever.** Three times faster, but it loses the spread
  that lets a report defend its numbers. `lh.runs` is stored per page, so the
  report could print the run count beside a score if it is ever added.
- **Killing pages in Chrome on Stop.** See above; the cost is up to one
  Lighthouse timeout before a Stop completes.
- **Resuming a batch's probe authorization.** Deliberately not: it is given
  for one batch, in the composer.
