"""Shaping core output for the templates.

Rule 7 of the project, unchanged from the report pipeline: **the templates
compute nothing.** Every threshold comparison, formatted number, plain
sentence and SVG path is decided here, where it is unit tested without
rendering HTML.

Status vocabulary is IMPORTED from :mod:`slap.report.model`, never
redeclared, so the operator's screen and the client's PDF cannot drift on
what "High" means. That was already the rule for the Qt theme and it
survives the rewrite.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from slap.report.model import (
    CWV_BANDS, CWV_TILES, SEVERITY_ORDER, SEVERITY_STATUS, STATUS_WORDS,
    cwv_status, meter_fraction,
)
from slap.schema import format_value

#: Severity -> the word printed beside the swatch. A status colour never
#: carries meaning alone: `serious` and `warning` are only ΔE 13.6 apart in
#: normal vision and both sit below 3:1 contrast on this surface, so hue
#: cannot distinguish two findings that sit adjacent in a list.
SEVERITY_WORDS = {
    "critical": "Critical", "high": "Serious", "medium": "Warning",
    "low": "Low", "info": "Info",
}


#: Lab stand-ins for the field metrics, used only when CrUX has nothing.
#: INP has no lab equivalent at all (the lab proxy is total blocking time,
#: which is a different measurement), so it is deliberately absent: showing
#: TBT under an "Interaction to Next Paint" heading would be a lie.
LAB_FALLBACK = {"crux.lcp.p75": "lh.lcp", "crux.cls.p75": "lh.cls"}


@dataclass(slots=True)
class Tile:
    label: str
    value: str
    status: str          # good | needs-improvement | poor | unknown
    word: str            # the printed word. Never omit it.
    fraction: float
    good_at: str
    poor_above: str
    source: str          # "field" | "lab" | "none". Never leave it implied.


@dataclass(slots=True)
class SiteRow:
    id: int
    hostname: str
    client: str | None
    audited: str
    audited_iso: str | None
    never: bool
    score: int | None
    score_word: str
    score_status: str
    delta: int | None
    lcp: str
    open_count: int
    urgent_count: int
    spark: str           # an SVG path, precomputed. Templates draw, not compute.
    spark_last: tuple[float, float] | None


def _num(values: dict[str, Any], key: str) -> float | None:
    value = values.get(key)
    return float(value) if isinstance(value, (int, float)) else None


def score_status(score: float | None) -> tuple[str, str]:
    """Lighthouse's own banding: >=90 good, >=50 needs work, else poor."""
    if score is None:
        return "unknown", STATUS_WORDS["unknown"]
    if score >= 90:
        return "good", STATUS_WORDS["good"]
    if score >= 50:
        return "needs-improvement", STATUS_WORDS["needs-improvement"]
    return "poor", STATUS_WORDS["poor"]


def humanise(iso: str | None) -> str:
    """'today' / '3 days ago' / a date. Never a raw ISO string in the UI."""
    if not iso:
        return "never"
    try:
        when = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    days = (datetime.now(timezone.utc) - when).days
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 14:
        return f"{days} days ago"
    return when.strftime("%-d %b")


def stamp(iso: str | None) -> str:
    """A label that stays distinct when several runs land on the same day.

    `humanise` is right for a table cell ("3 days ago") and wrong for a chart
    axis: seed five runs in an afternoon and every tick reads "today", which
    is how the first render of this screen came out.
    """
    if not iso:
        return ""
    try:
        when = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone()
    days = (datetime.now(timezone.utc) - when.astimezone(timezone.utc)).days
    return when.strftime("%H:%M") if days < 1 else when.strftime("%-d %b")


def sparkline(values: Sequence[float | None], width: float = 88,
              height: float = 22) -> tuple[str, tuple[float, float] | None]:
    """An SVG path plus the last point, or ('', None) with too little data.

    Returns a path rather than a list of points because a template that
    builds a path from coordinates is a template doing computation.
    """
    points = [v for v in values if v is not None]
    if len(points) < 2:
        return "", None
    low, high = min(points), max(points)
    span = (high - low) or 1.0
    step = (width - 4) / (len(points) - 1)
    coords = [
        (2 + i * step, height - 2 - ((v - low) / span) * (height - 6))
        for i, v in enumerate(points)
    ]
    path = " ".join(
        f"{'M' if i == 0 else 'L'}{x:.1f} {y:.1f}" for i, (x, y) in enumerate(coords)
    )
    return path, coords[-1]


def build_site_rows(sites: list[dict[str, Any]],
                    histories: dict[int, list[dict[str, Any]]]) -> list[SiteRow]:
    rows: list[SiteRow] = []
    for site in sites:
        history = histories.get(site["id"], [])
        scores = [h.get("lh.score.performance") for h in history]
        latest = next((s for s in reversed(scores) if s is not None), None)
        first = next((s for s in scores if s is not None), None)
        path, last = sparkline(scores)
        status, word = score_status(latest)
        lcp = next(
            (h.get("crux.lcp.p75") or h.get("lh.lcp") for h in reversed(history)
             if h.get("crux.lcp.p75") is not None or h.get("lh.lcp") is not None),
            None,
        )
        rows.append(SiteRow(
            id=site["id"],
            hostname=site["hostname"],
            client=site.get("client") or site.get("label"),
            audited=humanise(site.get("last_audited")),
            audited_iso=site.get("last_audited"),
            never=site.get("latest_run_id") is None,
            score=int(round(latest)) if latest is not None else None,
            score_word=word,
            score_status=status,
            delta=(int(round(latest - first))
                   if latest is not None and first is not None and len(scores) > 1
                   else None),
            lcp=format_value("crux.lcp.p75", lcp) if lcp is not None else "--",
            open_count=site.get("finding_count") or 0,
            urgent_count=site.get("urgent_count") or 0,
            spark=path,
            spark_last=last,
        ))
    return rows


def build_tiles(values: dict[str, Any]) -> list[Tile]:
    tiles: list[Tile] = []
    for key, label, _blurb in CWV_TILES:
        value, source = _num(values, key), "field"
        if value is None and key in LAB_FALLBACK:
            value = _num(values, LAB_FALLBACK[key])
            source = "lab" if value is not None else "none"
        elif value is None:
            source = "none"
        status = cwv_status(key, value)
        good_at, poor_above = CWV_BANDS[key]
        tiles.append(Tile(
            label=label,
            value=format_value(key, value) if value is not None else "No data",
            status=status,
            word=STATUS_WORDS[status],
            fraction=meter_fraction(key, value),
            good_at=format_value(key, good_at),
            poor_above=format_value(key, poor_above),
            source=source,
        ))
    return tiles


def build_trend(history: list[dict[str, Any]], metric: str = "lh.score.performance",
                width: float = 640, height: float = 200) -> dict[str, Any]:
    """Everything the trend chart needs, geometry included.

    One series, so no legend: the chart's title names it. Only the first and
    last points get a direct label, never every point.
    """
    points = [(h, h.get(metric)) for h in history]
    points = [(h, v) for h, v in points if v is not None]
    if len(points) < 2:
        return {"empty": True, "count": len(points)}

    left, right, top, bottom = 34.0, 14.0, 16.0, 28.0
    inner_w, inner_h = width - left - right, height - top - bottom
    ceiling = 100.0

    def x(i: int) -> float:
        return left + (i / (len(points) - 1)) * inner_w

    def y(v: float) -> float:
        return top + inner_h - (min(v, ceiling) / ceiling) * inner_h

    marks = [
        {"x": round(x(i), 1), "y": round(y(v), 1), "value": int(round(v)),
         "when": stamp(h["started_at"]), "run_id": h["run_id"],
         "last": i == len(points) - 1}
        for i, (h, v) in enumerate(points)
    ]
    line = " ".join(f"{'M' if i == 0 else 'L'}{m['x']} {m['y']}"
                    for i, m in enumerate(marks))
    area = (f"M{marks[0]['x']} {y(0):.1f} "
            + " ".join(f"L{m['x']} {m['y']}" for m in marks)
            + f" L{marks[-1]['x']} {y(0):.1f} Z")
    gridlines = [{"y": round(y(v), 1), "label": int(v)} for v in (0, 25, 50, 75, 100)]
    return {
        "empty": False, "width": width, "height": height,
        "line": line, "area": area, "marks": marks, "gridlines": gridlines,
        "first": marks[0], "last": marks[-1],
        "delta": marks[-1]["value"] - marks[0]["value"],
    }


def decorate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach the swatch class and the mandatory word to each finding."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out = []
    for f in findings:
        severity = f.get("severity", "info")
        out.append({
            **f,
            "status": SEVERITY_STATUS.get(severity, "muted"),
            "word": SEVERITY_WORDS.get(severity, severity.title()),
            "rank": order.get(severity, 99),
        })
    return sorted(out, key=lambda f: (f["rank"], f.get("title", "")))
