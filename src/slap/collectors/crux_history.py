"""Twenty-five weeks of real-user field data, from the CrUX History API.

The trend SLAP already had is built from its own runs, which means it shows
nothing until you have been auditing a site for months, and it plots lab
numbers. This one arrives complete on the first audit, is real-user data, and
is unaffected by page-set churn because it is origin-scoped. For "did the fix
work", it is the better evidence by a distance.

**The caveat that has to reach the report.** Each period is a *28-day rolling
average*, and periods advance weekly. Consecutive points therefore overlap by
three weeks and are not independent observations: a change that happened in
one week appears smeared across four, and the line lags reality by up to a
month. A reader who takes a week-over-week step as "what happened that week"
is reading it wrong, and the chart has to say so. This is the same class of
disclosure as the lab-versus-field sentence on the verdict page.

Quota is shared with the point-in-time API — 150 queries/minute across both —
so this uses the same :class:`TokenBucket` instance rather than its own.
"""

from __future__ import annotations

from typing import Any

from ..schema import CWV_GOOD_THRESHOLDS, Observation, Scope, obs
from .base import PageContext
from .crux import METRIC_MAP, TokenBucket, _as_float

HISTORY_ENDPOINT = (
    "https://chromeuxreport.googleapis.com/v1/records:queryHistoryRecord"
)

#: The API accepts 1-40. Twenty-five is the default and about six months,
#: which is the horizon a client conversation actually spans: "since we did
#: the work in the spring".
DEFAULT_PERIODS = 25

#: Metrics worth the quota. TTFB is deliberately absent: it is diagnostic
#: rather than something a client is assessed on, and each extra metric is
#: more response to parse for a line nobody puts in front of a client.
HISTORY_METRICS = (
    "largest_contentful_paint",
    "interaction_to_next_paint",
    "cumulative_layout_shift",
)


def _iso(date: dict[str, Any] | None) -> str | None:
    """``{"year": 2026, "month": 2, "day": 1}`` to ``"2026-02-01"``.

    Zero-padded, because these strings are compared and ordered as text by
    the storage layer and "2026-2-1" sorts after "2026-11-01".
    """
    if not isinstance(date, dict):
        return None
    try:
        return (f"{int(date['year']):04d}-{int(date['month']):02d}"
                f"-{int(date['day']):02d}")
    except (KeyError, TypeError, ValueError):
        return None


def parse_history(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """A ``queryHistoryRecord`` response to flat weekly points.

    Returns one dict per (period, metric). The response is transposed: the
    collection periods are a single list on the record, and every metric
    carries parallel arrays indexed against it. A metric whose arrays are
    shorter than the period list is truncated rather than misaligned, because
    zipping them by position after a short array would attribute one week's
    number to a different week.
    """
    record = payload.get("record") or {}
    periods = record.get("collectionPeriods") or []
    metrics = record.get("metrics") or {}

    bounds: list[tuple[str, str]] = []
    for period in periods:
        start, end = _iso(period.get("firstDate")), _iso(period.get("lastDate"))
        if start and end:
            bounds.append((start, end))

    points: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for crux_name, (metric_key, _good_key) in METRIC_MAP.items():
        metric = metrics.get(crux_name)
        if not metric or crux_name not in HISTORY_METRICS:
            continue

        p75s = ((metric.get("percentilesTimeseries") or {}).get("p75s")) or []
        histogram = metric.get("histogramTimeseries") or []
        # densities[i] is the share in that bin for period i. Bin 0 is good,
        # 1 needs improvement, 2 poor, matching the point-in-time histogram.
        densities = [(bin_.get("densities") or []) for bin_ in histogram[:3]]

        for index, (start, end) in enumerate(bounds):
            key = (metric_key, end)
            if key in seen:
                continue
            p75 = _as_float(p75s[index]) if index < len(p75s) else None
            shares = [
                _as_float(band[index]) if index < len(band) else None
                for band in densities
            ]
            while len(shares) < 3:
                shares.append(None)
            if p75 is None and all(s is None for s in shares):
                # A period with no data for this metric. Skipped rather than
                # stored as zero: a zero LCP would plot as a perfect score.
                continue
            seen.add(key)
            points.append({
                "period_start": start, "period_end": end,
                "metric_key": metric_key, "p75": p75,
                "good": shares[0], "needs_improvement": shares[1],
                "poor": shares[2],
            })
    return points


def series_for(points: list[dict[str, Any]], metric_key: str) -> list[dict[str, Any]]:
    return sorted((p for p in points if p["metric_key"] == metric_key),
                  key=lambda p: p["period_end"])


def crossed_threshold(points: list[dict[str, Any]],
                      metric_key: str) -> str | None:
    """``"regressed"``, ``"improved"``, or None if it stayed on one side.

    Compares the FIRST and LAST periods against the Core Web Vitals
    threshold, not the raw delta. A site whose LCP went from 1.2s to 2.4s got
    twice as slow and is still passing; a site that went from 2.4s to 2.6s
    barely moved and now fails. The second is the one a client needs to hear
    about, and only a threshold comparison distinguishes them.
    """
    threshold = CWV_GOOD_THRESHOLDS.get(metric_key)
    series = [p for p in series_for(points, metric_key) if p["p75"] is not None]
    if threshold is None or len(series) < 2:
        return None
    was_good = series[0]["p75"] <= threshold
    is_good = series[-1]["p75"] <= threshold
    if was_good and not is_good:
        return "regressed"
    if is_good and not was_good:
        return "improved"
    return None


def summarise(points: list[dict[str, Any]]) -> list[Observation]:
    """Run-level observations. The series itself goes to its own table."""
    if not points:
        return [obs("crux.history.available", False)]

    weeks = len({p["period_end"] for p in points})
    out: list[Observation] = [
        obs("crux.history.available", True),
        obs("crux.history.weeks", weeks),
    ]

    regressed: list[str] = []
    improved: list[str] = []
    for metric_key, short in (("crux.lcp.p75", "lcp"),
                              ("crux.inp.p75", "inp"),
                              ("crux.cls.p75", "cls")):
        series = [p for p in series_for(points, metric_key)
                  if p["p75"] is not None]
        if len(series) < 2:
            continue
        first, last = series[0]["p75"], series[-1]["p75"]
        out.append(obs(f"crux.history.{short}.delta", round(last - first, 4)))
        out.append(obs(f"crux.history.{short}.first", first))
        verdict = crossed_threshold(points, metric_key)
        if verdict == "regressed":
            regressed.append(short.upper())
        elif verdict == "improved":
            improved.append(short.upper())

    out.append(obs("crux.history.regressed", bool(regressed)))
    if regressed:
        out.append(obs("crux.history.regressed_metrics", ", ".join(regressed)))
    # The other half, and the one that gets a report paid for twice: a vital
    # that was failing and now passes is "we fixed it, here is proof" backed
    # by real users rather than by a lab number taken on our own machine.
    out.append(obs("crux.history.improved", bool(improved)))
    if improved:
        out.append(obs("crux.history.improved_metrics", ", ".join(improved)))
    if points:
        span = sorted({p["period_end"] for p in points})
        out.append(obs("crux.history.first_period", span[0]))
        out.append(obs("crux.history.last_period", span[-1]))
    return out


class CruxHistoryCollector:
    """Fetches the weekly series and hands it to the persistence layer.

    Returns summary observations and stashes the series in ``ctx.extras``,
    the same shape :class:`LighthouseCollector` uses for its artifacts: a
    collector emits observations, and anything that does not fit that shape
    travels in extras for ``core._persist`` to write.
    """

    name = "crux-history"
    #: Origin-scoped, and more emphatically than the point-in-time collector:
    #: the History API has no url form at all.
    scope = Scope.ORIGIN

    def __init__(self, bucket: TokenBucket | None = None, *,
                 periods: int = DEFAULT_PERIODS,
                 form_factor: str = "PHONE",
                 enabled: bool = True) -> None:
        self._bucket = bucket
        self.periods = max(1, min(40, periods))
        self.form_factor = form_factor
        self.enabled = enabled

    async def collect(self, ctx: PageContext) -> list[Observation]:
        if not self.enabled:
            return []
        api_key = ctx.config.crux_api_key
        if not api_key:
            # Explicit, not silent. Without this the report cannot tell "no
            # history exists for this origin" from "we never asked".
            return [obs("crux.history.available", False)]

        bucket = self._bucket or TokenBucket(ctx.config.crux_rate_per_second)
        await bucket.acquire()

        body = {
            "origin": ctx.origin,
            "formFactor": self.form_factor,
            "metrics": list(HISTORY_METRICS),
            "collectionPeriodCount": self.periods,
        }
        try:
            response = await ctx.client.post(
                HISTORY_ENDPOINT, params={"key": api_key}, json=body,
                timeout=ctx.config.timeout,
            )
        except Exception as exc:                       # noqa: BLE001
            ctx.errors.append(f"crux-history: {type(exc).__name__}: {exc}")
            return [obs("crux.history.available", False)]

        if response.status_code == 404:
            # Not an error: the origin has too little traffic for a record.
            # The commonest outcome on a small-business site.
            return [obs("crux.history.available", False)]
        if response.status_code != 200:
            ctx.errors.append(
                f"crux-history: HTTP {response.status_code} "
                f"{response.text[:120]}")
            return [obs("crux.history.available", False)]

        try:
            points = parse_history(response.json())
        except ValueError as exc:
            ctx.errors.append(f"crux-history: bad JSON: {exc}")
            return [obs("crux.history.available", False)]

        if points:
            ctx.extras["crux_history"] = {
                "origin": ctx.origin,
                "form_factor": self.form_factor,
                "points": points,
            }
        return summarise(points)
