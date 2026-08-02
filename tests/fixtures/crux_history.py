"""A CrUX History API response, built to the documented shape.

Hand-built rather than recorded, because no CrUX key is available in this
environment and a fixture nobody can regenerate is worse than one whose
construction is explicit. Every structural feature below is taken from the
API reference: the transposed layout (one `collectionPeriods` list on the
record, parallel arrays per metric), `percentilesTimeseries.p75s`,
`histogramTimeseries[].densities`, and `{year, month, day}` dates.

The values are chosen to exercise the cases that matter rather than to look
plausible:

* **LCP crosses the 2500ms threshold upward.** Starts good, ends failing.
  This is the regression a client needs to hear about.
* **CLS improves across the same window** but never crosses its threshold,
  so it must NOT be reported as an improvement worth mentioning.
* **INP has a short array**, three entries against eight periods. Real
  responses do this when a metric has thin coverage, and zipping by position
  past the end is how one week's number gets attributed to another week.
* **One LCP period is null**, which is what a period with insufficient data
  looks like. Stored as zero it would plot as a perfect score.
"""

from __future__ import annotations

#: Eight consecutive weekly periods, each a 28-day window advancing by 7 days.
_PERIODS = [
    ("2025-12-07", "2026-01-03"),
    ("2025-12-14", "2026-01-10"),
    ("2025-12-21", "2026-01-17"),
    ("2025-12-28", "2026-01-24"),
    ("2026-01-04", "2026-01-31"),
    ("2026-01-11", "2026-02-07"),
    ("2026-01-18", "2026-02-14"),
    ("2026-01-25", "2026-02-21"),
]

#: Good at 2100ms, drifting past the 2500ms threshold. Index 4 is null.
LCP_P75 = [2100, 2180, 2260, 2340, None, 2560, 2680, 2790]
#: Improves, but 0.16 -> 0.12 never reaches the 0.1 threshold.
CLS_P75 = [0.16, 0.155, 0.15, 0.14, 0.135, 0.13, 0.125, 0.12]
#: Deliberately short: three values for eight periods.
INP_P75 = [180, 190, 195]


def _date(iso: str) -> dict[str, int]:
    year, month, day = iso.split("-")
    return {"year": int(year), "month": int(month), "day": int(day)}


def _histogram(p75s, good_max, poor_min):
    """Three density bands, derived from the p75 series so they stay coherent."""
    good, needs, poor = [], [], []
    for value in p75s:
        if value is None:
            good.append(None), needs.append(None), poor.append(None)
            continue
        share = 0.9 if value <= good_max else (0.6 if value <= poor_min else 0.4)
        good.append(round(share, 4))
        needs.append(round((1 - share) * 0.7, 4))
        poor.append(round((1 - share) * 0.3, 4))
    return [{"start": 0, "end": good_max, "densities": good},
            {"start": good_max, "end": poor_min, "densities": needs},
            {"start": poor_min, "densities": poor}]


def response(*, include_inp: bool = True) -> dict:
    record = {
        "key": {"origin": "https://fixture.test", "formFactor": "PHONE"},
        "metrics": {
            "largest_contentful_paint": {
                "histogramTimeseries": _histogram(LCP_P75, 2500, 4000),
                "percentilesTimeseries": {"p75s": LCP_P75},
            },
            "cumulative_layout_shift": {
                "histogramTimeseries": _histogram(CLS_P75, 0.1, 0.25),
                "percentilesTimeseries": {"p75s": CLS_P75},
            },
        },
        "collectionPeriods": [
            {"firstDate": _date(start), "lastDate": _date(end)}
            for start, end in _PERIODS
        ],
    }
    if include_inp:
        record["metrics"]["interaction_to_next_paint"] = {
            "histogramTimeseries": _histogram(INP_P75, 200, 500),
            "percentilesTimeseries": {"p75s": INP_P75},
        }
    return {"record": record}


#: What an origin with too little traffic returns. Not an error.
NOT_FOUND = {
    "error": {"code": 404, "message": "chrome ux report data not found",
              "status": "NOT_FOUND"}
}

PERIOD_COUNT = len(_PERIODS)
