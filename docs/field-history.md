# SLAP: real-user history

*Built 2026-08-02. The first slice of Phase 4, and the one that does not
depend on anything the per-page work still has to prove against a real site.*

Twenty-five weekly periods of Core Web Vitals from the CrUX History API,
per origin.

The trend SLAP already had is built from its own runs: it shows nothing until
you have been auditing a site for months, and it plots lab numbers taken on
your machine. This one arrives complete on the first audit, is measured on the
client's actual visitors, and is unaffected by page-set churn because it is
origin-scoped. For "did the fix work", it is better evidence by a distance.

---

## 1. The disclosure that has to travel with the chart

Each period is a **28-day rolling average**, and the periods advance weekly.
Consecutive points therefore overlap by three weeks and are not independent
observations: a change that happened in one week appears smeared across four,
and the line lags reality by up to a month.

A reader who takes a week-over-week step as "what happened that week" is
reading it wrong, so both the report and the site page print the caveat under
the chart. Same class of disclosure as the lab-versus-field sentence on the
verdict page, and it is not decoration.

## 2. Crossings, not deltas

Both history rules fire on a **threshold crossing**, never on a raw change.

A site whose LCP went from 1.2s to 2.4s doubled and still passes. One that
went from 2.4s to 2.6s barely moved and now fails. Only the second is worth a
client's attention, and only a threshold comparison tells them apart. A
`crux-history-improvement` finding is the other half, and it is the one that
gets a report paid for twice: a vital that was failing and now passes is "we
fixed it, here is proof", backed by real users rather than by a lab number
taken on our own machine.

## 3. Storage: the first table that is not a property of a run

Every other table in this schema hangs off `run`. `crux_history` does not, and
that is the point. The CrUX record for an origin in a given week is the same
fact whoever fetched it and whenever, so two audits a week apart share 24 of
their 25 periods. Keying it to runs would duplicate ~96% of it and force every
trend query into a dedup pass to avoid plotting the same week five times.

Immutability still holds. A run is immutable history of what SLAP *did*; this
is a cache of an external series keyed by its own identity. Re-fetching a
period overwrites it with the same values, and `fetched_at` records when we
last saw it. The upsert is REPLACE rather than IGNORE because Google revises
recent periods as late data lands, and the newer answer is the better one.

## 4. What the response shape does to a parser

The payload is **transposed**: one `collectionPeriods` list on the record, and
every metric carries parallel arrays indexed against it. Three things follow,
and each is a test:

- **A short metric array must truncate, not zip past the end.** Real responses
  carry short arrays for thin metrics — the fixture gives INP three values
  against eight periods. Zipping by position past the end attributes one
  week's number to a different week.
- **A null period is skipped, not stored as zero.** A zero LCP plots as a
  perfect score.
- **Dates are zero-padded.** They are ordered as text by the storage layer,
  and `2026-2-1` sorts after `2026-11-01`.

Quota is shared with the point-in-time endpoint — 150/minute across both — so
the collector takes the same `TokenBucket` instance rather than its own. Two
independent limiters would let a wide batch burst straight through the limit.

## 5. Two bugs found by looking at the render

Neither was visible in the model, the tests, or the HTML source.

**The verdict announced "No real-user data is available for this site"**
directly above a paragraph explaining how to read its eight-week real-user
chart, with the tiles suppressed in between. `crux.available` answers "did the
point-in-time endpoint return a record", which is a question about one API
call, not about whether this report has real-user data to show. The two came
apart the moment a second source of the same data existed.

**A tile read "No data" above its own trend line.** A contradiction the reader
resolves by trusting neither. The latest history period *is* the current
figure — both endpoints report the p75 of the most recent 28-day window — so
the tile falls back to it. That is the same measurement by another route, not
a substitute for it.

A third, caught by a test only because the fixture runs on a non-standard
port: the site page rebuilt the origin from the hostname, which **drops the
port**, so a site on anything but 80 or 443 stored under `http://host:8080`
and was looked up under `http://host`. It returned nothing and rendered as
"this site has no field data". `origin_for()` is now shared by the run detail
and the site detail rather than written twice. On a real client site this
would never have fired, which is exactly why the fixture is worth having.

## 6. Wording

`TREND_WORDS` is per metric, because "Faster" under a Cumulative Layout Shift
heading is a category error and the sort a client notices, since it reads as
though we do not know what the metric is. LCP moves Slower/Faster, INP moves
Less/More responsive, CLS moves Less/More stable.

The chart's y scale always includes the threshold even when every point sits
well clear of it. Auto-scaling to the data alone would put a series that never
approaches the limit right next to one about to cross it, and the two would
look identical.

## 7. Not done

- **No CrUX key exists in this environment**, so every test runs against a
  response built to the documented shape. The collector's request has never
  been sent. First real audit with a key should confirm the field names before
  anything is promised to a client from it.
- **PHONE only.** Desktop is a second query and a second row set for a
  segment most of these clients care less about. The schema keys on form
  factor already, so adding it is a config flag, not a migration.
- **The site page charts LCP alone.** INP and CLS are stored and are on the
  report's tiles; a three-line chart on the site page is a layout question
  worth answering with real data in front of it.
- **No alerting.** "Tell me when a site regresses" is the obvious next step
  and needs a scheduler, which is its own decision.
