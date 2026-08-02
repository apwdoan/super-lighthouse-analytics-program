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
    #: Pages in the latest run. `open_count` counts DISTINCT rules, so the two
    #: numbers answer different questions and both belong in the row: "12
    #: problems across 20 pages" is the honest summary, and the version that
    #: multiplied them read "240 open findings".
    page_count: int = 1

    @property
    def pages_text(self) -> str:
        return "1 page" if self.page_count <= 1 else f"{self.page_count} pages"


def day_month(when: datetime) -> str:
    """``"4 Mar"``, without a leading zero, on every platform.

    ``strftime("%-d")`` is a glibc extension. Windows' C runtime rejects the
    ``-`` flag outright with ``ValueError: Invalid format string``, and macOS
    accepts it only by accident of BSD libc. Formatting the day as an integer
    and letting strftime handle only the month name is portable and says what
    it means.

    This is not a hypothetical. `humanise` has carried ``"%-d %b"`` since it
    was written and raises on Windows for any site last audited more than a
    fortnight ago — the site list, on the machine this project is developed
    on. It never fired because every test seeds fresh data and lands in the
    "today" / "N days ago" branches above it.
    """
    return f"{when.day} {when:%b}"


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
    return day_month(when)


def stamp(iso: str | None) -> str:
    """A label that stays distinct when several runs land on the same day.

    `humanise` is right for a table cell ("3 days ago") and wrong for a chart
    axis: seed five runs in an afternoon and every tick reads "today", which
    is how the first render of this screen came out.

    The first fix only held for a day. It appended the time when the run was
    less than 24 hours old and fell back to a bare date after that, so the five
    runs seeded in one afternoon read distinctly that afternoon and collapsed
    to five identical "31 Jul" ticks the next morning. Its own test passed on
    the day it was written and failed from the following day onwards, which is
    the tell: a test whose result depends on how long ago the fixture date was
    is asserting against the clock, not against the behaviour.

    So the date always carries its time. Only the label for *today* drops the
    date, because "today" is the one case where the reader already has it.
    Chart axes label the first and last point only, so the extra five
    characters cost nothing.
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
    if when.date() == datetime.now(when.tzinfo).date():
        return when.strftime("%H:%M")
    return f"{day_month(when)} {when:%H:%M}"


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
        # No lab score does not mean no verdict. The first real-data run had
        # this column reading "No data" for a site whose OWN ROW showed a
        # 2.7s LCP from real visitors, because the verdict keyed on the
        # Lighthouse score alone. The report leads with field data when it
        # has it; the site list follows the same rule.
        if latest is None:
            cwv = next((h.get("crux.cwv_pass") for h in reversed(history)
                        if h.get("crux.cwv_pass") is not None), None)
            if cwv is not None:
                status = "good" if cwv else "poor"
                word = "Passing CWV" if cwv else "Failing CWV"
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
            page_count=site.get("page_count") or 1,
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


def build_field_trend(history: dict[str, list[dict[str, Any]]],
                      metric: str = "crux.lcp.p75") -> dict[str, Any]:
    """Real-user weekly series for the site page.

    Separate from `build_trend`, which plots SLAP's own runs. They answer
    different questions and must not be merged into one line: one is what we
    measured on our machine, the other is what visitors experienced, and a
    chart that silently splices them would be indefensible the first time
    they disagreed.
    """
    from slap.report.model import CWV_BANDS, field_sparkline

    series = history.get(metric) or []
    measured = [p for p in series if p.get("p75") is not None]
    if len(measured) < 2:
        return {"empty": True}

    threshold = CWV_BANDS.get(metric, (None, None))[0]
    path, threshold_y = field_sparkline(measured, threshold, width=560, height=90)
    first, last = measured[0], measured[-1]
    return {
        "empty": False, "path": path, "threshold_y": threshold_y,
        "width": 560, "height": 90,
        "weeks": len(measured),
        "first_label": first["period_end"], "last_label": last["period_end"],
        "first_value": format_value(metric, first["p75"]),
        "last_value": format_value(metric, last["p75"]),
        "threshold_text": format_value(metric, threshold) if threshold else "",
        "status": ("good" if threshold and last["p75"] <= threshold else "poor"),
        "status_word": ("Good" if threshold and last["p75"] <= threshold
                        else "Outside target"),
    }


def decorate_findings(findings: list[dict[str, Any]], *,
                      pages_total: int = 1) -> list[dict[str, Any]]:
    """Group by rule, attach the swatch class and the mandatory word.

    Grouped for the same reason the client report groups: a run over twenty
    pages produces a few hundred finding rows describing a dozen problems, and
    an operator list that shows all of them is unreadable in exactly the way
    the report would be. The rule id is the identity; the pages ride along.
    """
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    grouped: dict[str, dict[str, Any]] = {}
    for f in findings:
        rule_id = f.get("rule_id") or f.get("title", "")
        url = f.get("url")
        if rule_id in grouped:
            if url and url not in grouped[rule_id]["pages"]:
                grouped[rule_id]["pages"].append(url)
            continue
        severity = f.get("severity", "info")
        grouped[rule_id] = {
            **f,
            "status": SEVERITY_STATUS.get(severity, "muted"),
            "word": SEVERITY_WORDS.get(severity, severity.title()),
            "rank": order.get(severity, 99),
            "pages": [url] if url else [],
        }
    out = []
    for entry in grouped.values():
        count = len(entry["pages"])
        # Only claim a page count when we actually counted pages. Rows from
        # `findings_across_sites` are aggregated in SQL and carry no `url`, so
        # unconditionally writing len(pages) would overwrite a real
        # COUNT(DISTINCT p.id) with 0 — and the template that reads it would
        # simply render nothing, which is the failure mode this whole change
        # exists to stamp out.
        if count:
            entry["page_count"] = count
        entry["scope"] = (
            "" if pages_total <= 1 or not count
            else f"All {pages_total} pages" if count >= pages_total
            else f"{count} of {pages_total} pages"
        )
        out.append(entry)
    return sorted(out, key=lambda f: (f["rank"], f.get("title", "")))


def build_page_rows(pages: list[dict[str, Any]],
                    scores: dict[int, float | None] | None = None) -> list[dict[str, Any]]:
    """The operator's page inventory for a run.

    Mirrors `report.model.build_page_rows` in what it decides and stays in the
    web layer for what it looks like. A page with no score prints why: a blank
    cell reads as a zero to some people and as a pass to others.
    """
    from urllib.parse import urlsplit

    scores = scores or {}
    rows = []
    for page in pages:
        score = scores.get(page["id"])
        status, word = score_status(score)
        parts = urlsplit(page["url"])
        rows.append({
            "id": page["id"],
            "url": page["url"],
            "path": (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
            "template": (page.get("template_class") or "page").replace("-", " "),
            "role": page.get("role") or "discovered",
            "depth": page.get("audit_depth") or "light",
            "measured": score is not None,
            "score": int(round(score)) if score is not None else None,
            "score_word": word if score is not None else "Not measured",
            "score_status": status if score is not None else "muted",
            "findings": page.get("finding_count") or 0,
            "urgent": page.get("urgent_count") or 0,
        })
    return rows
