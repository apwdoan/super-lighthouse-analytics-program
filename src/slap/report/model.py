"""The report view model.

A pure transform from what :func:`slap.core.get_run_detail` returns into the
shape the templates render. The templates compute nothing: every threshold
comparison, every plain-language sentence, and every formatted number is
decided here, where it can be unit tested without rendering HTML.

That split is what keeps the Qt operator view and the client-facing report
from drifting, since both read this same model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from ..schema import (
    EXPECTED_SECURITY_HEADERS,
    METRIC_REGISTRY,
    Severity,
    format_value,
    origin_scoped_keys,
)

# --------------------------------------------------------------------------
# Status vocabulary
#
# Mapped onto the reference status palette (good / warning / serious /
# critical). Two constraints from that palette drive the template, and
# removing either one breaks accessibility:
#
#   1. `serious` (#ec835a) and `warning` (#fab219) sit ΔE 13.6 apart in
#      normal vision, below the 15 floor. High and medium findings sit
#      adjacent in the list, so hue alone cannot distinguish them.
#   2. Both are below 3:1 contrast on a light surface.
#
# The mitigation for both is the same and is mandatory: every badge carries
# the severity word. Never reduce a badge to a bare coloured dot.
# --------------------------------------------------------------------------

SEVERITY_STATUS: dict[str, str] = {
    "critical": "critical",
    "high": "serious",
    "medium": "warning",
    "low": "muted",
    "info": "muted",
}

SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

#: Core Web Vitals bands: (good_at_or_below, poor_above).
CWV_BANDS: dict[str, tuple[float, float]] = {
    "crux.lcp.p75": (2500.0, 4000.0),
    "crux.inp.p75": (200.0, 500.0),
    "crux.cls.p75": (0.1, 0.25),
}

CWV_TILES: list[tuple[str, str, str]] = [
    ("crux.lcp.p75", "Largest Contentful Paint", "How long until the main content appears"),
    ("crux.inp.p75", "Interaction to Next Paint", "How quickly the page responds to a tap or click"),
    ("crux.cls.p75", "Cumulative Layout Shift", "How much the page jumps around while loading"),
]

#: (word when the value rose, word when it fell). Rising is worse for all
#: three, but "slower" only means something for the two that measure time.
TREND_WORDS: dict[str, tuple[str, str]] = {
    "crux.lcp.p75": ("Slower", "Faster"),
    "crux.inp.p75": ("Less responsive", "More responsive"),
    "crux.cls.p75": ("Less stable", "More stable"),
}

EFFORT_LABELS = {
    "low": "Low effort", "medium": "Medium effort", "high": "High effort",
    "varies": "Effort varies", "none": "No action needed",
}


# --------------------------------------------------------------------------
# Formatting helpers. Pure, and tested.
# --------------------------------------------------------------------------

def format_ms(value: float | None) -> str:
    """Milliseconds, switching to seconds once that reads better."""
    if value is None:
        return "n/a"
    if value >= 1000:
        return f"{value / 1000:.1f}s"
    return f"{round(value):g}ms"


def format_bytes(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value >= 1_048_576:
        return f"{value / 1_048_576:.1f} MB"
    if value >= 1024:
        return f"{value / 1024:.0f} KB"
    return f"{value:.0f} B"


def format_seconds_as_duration(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value >= 86400:
        return f"{value / 86400:.0f} days"
    if value >= 3600:
        return f"{value / 3600:.0f} hours"
    if value >= 60:
        return f"{value / 60:.0f} minutes"
    return f"{value:.0f} seconds"


def cwv_status(metric_key: str, value: float | None) -> str:
    """`good`, `needs-improvement`, `poor`, or `unknown`."""
    if value is None or metric_key not in CWV_BANDS:
        return "unknown"
    good_max, poor_min = CWV_BANDS[metric_key]
    if value <= good_max:
        return "good"
    if value <= poor_min:
        return "needs-improvement"
    return "poor"


STATUS_WORDS = {
    "good": "Good", "needs-improvement": "Needs work",
    "poor": "Poor", "unknown": "No data",
}


def score_status(score: float | None) -> str:
    """Lighthouse's own 0-100 banding.

    Named and shared rather than inlined, so the page inventory and the
    category tiles cannot drift: a page shown amber in the inventory and green
    in the summary is the kind of contradiction a client notices first.
    """
    if score is None:
        return "unknown"
    if score >= 90:
        return "good"
    if score >= 50:
        return "needs-improvement"
    return "poor"


def meter_fraction(metric_key: str, value: float | None) -> float:
    """Where the value sits on a 0..1 track whose 'poor' edge is at 0.66.

    Deliberately non-linear: the good and needs-improvement bands each take a
    third of the track so the two thresholds land at fixed positions across
    all three metrics. A reader can then compare tile to tile by eye without
    re-reading the axis every time.
    """
    if value is None or metric_key not in CWV_BANDS:
        return 0.0
    good_max, poor_min = CWV_BANDS[metric_key]
    if value <= good_max:
        return max(0.02, (value / good_max) * 0.33)
    if value <= poor_min:
        return 0.33 + ((value - good_max) / (poor_min - good_max)) * 0.33
    # Everything past the poor threshold compresses into the last third.
    overshoot = min((value - poor_min) / poor_min, 1.0)
    return min(0.66 + overshoot * 0.34, 1.0)


# --------------------------------------------------------------------------
# View model
# --------------------------------------------------------------------------

@dataclass(slots=True)
class MetricTile:
    key: str
    label: str
    caption: str
    value_text: str
    status: str
    status_word: str
    meter_fraction: float
    threshold_text: str
    #: Real-user history: an SVG path, plus the threshold's y position so the
    #: chart can draw the line the value is judged against. Empty when the
    #: origin has no CrUX history, which is most small sites.
    spark_path: str = ""
    spark_threshold_y: float | None = None
    spark_weeks: int = 0
    spark_first: str = ""
    spark_last: str = ""
    #: Which way it moved across the window, in words. A colour alone cannot
    #: carry this: the palette's two middle steps are ΔE 13.6 apart.
    trend_word: str = ""


def field_sparkline(series: list[dict[str, Any]], threshold: float | None,
                    *, width: float = 150.0, height: float = 34.0
                    ) -> tuple[str, float | None]:
    """An SVG path for a weekly p75 series, plus the threshold's y position.

    The y scale always includes the threshold, even when every point sits
    well clear of it. Auto-scaling to the data alone would put a line that
    never approaches the limit right next to one that is about to cross it,
    and the two would look identical.
    """
    points = [p["p75"] for p in series if p.get("p75") is not None]
    if len(points) < 2:
        return "", None

    low, high = min(points), max(points)
    if threshold is not None:
        low, high = min(low, threshold), max(high, threshold)
    # A flat series would divide by zero; give it a band so it draws level.
    span = (high - low) or max(abs(high) * 0.1, 1.0)
    pad = span * 0.12
    low, high = low - pad, high + pad
    span = high - low

    step = (width - 4) / (len(points) - 1)
    coords = [
        (2 + i * step, height - 2 - ((value - low) / span) * (height - 4))
        for i, value in enumerate(points)
    ]
    path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f} {y:.1f}"
                    for i, (x, y) in enumerate(coords))
    threshold_y = (height - 2 - ((threshold - low) / span) * (height - 4)
                   if threshold is not None else None)
    return path, threshold_y


@dataclass(slots=True)
class LabStat:
    label: str
    value_text: str
    note: str = ""


@dataclass(slots=True)
class CategoryScore:
    label: str
    value: int
    status: str
    status_word: str


@dataclass(slots=True)
class Verdict:
    has_field_data: bool
    passes: bool | None
    headline: str
    explanation: str
    tiles: list[MetricTile] = field(default_factory=list)
    lab_stats: list[LabStat] = field(default_factory=list)
    categories: list[CategoryScore] = field(default_factory=list)
    has_lab_data: bool = False
    lab_note: str = ""


@dataclass(slots=True)
class EvidenceItem:
    label: str
    value_text: str


@dataclass(slots=True)
class FindingView:
    rule_id: str
    severity: str
    severity_word: str
    status: str
    title: str
    detail: str
    remediation: str | None
    wp_rocket_setting: str | None
    effort_label: str | None
    impact_text: str | None
    evidence: list[EvidenceItem] = field(default_factory=list)
    #: Every page this rule fired on, shortest path first. One finding with
    #: twelve pages, never twelve findings: a report that repeats "no HSTS
    #: header" once per page is a two-hundred-page PDF that gets skimmed and
    #: binned, and it buries the three findings that only affect checkout.
    pages: list[str] = field(default_factory=list)
    #: Total pages in the run, so the template can say "9 of 12" without
    #: computing anything.
    pages_total: int = 0
    #: True when every metric this rule read describes the ORIGIN rather than
    #: a page: the certificate, the negotiated TLS version, the field data.
    #: Those observations are collected once and stored on the home page, so
    #: a naive page count reports "1 of 10 pages" for an expired certificate
    #: that takes down all ten. Understating a critical finding by a factor of
    #: ten is worse than not scoping it at all.
    origin_scoped: bool = False

    @property
    def page_count(self) -> int:
        return len(self.pages)

    @property
    def is_sitewide(self) -> bool:
        if self.origin_scoped:
            return True
        return self.pages_total > 1 and self.page_count >= self.pages_total

    @property
    def scope_text(self) -> str:
        """Where this fired, in words. Never a bare number.

        "1 of 12 pages" is the sentence that makes a per-page report worth
        reading: it is the difference between a site-wide misconfiguration
        and a single broken template.
        """
        if self.origin_scoped:
            return "Site-wide"
        if self.pages_total <= 1 or not self.pages:
            return ""
        if self.is_sitewide:
            return f"All {self.pages_total} pages"
        # The noun agrees with the total, not the count: "1 of 10 pages".
        return f"{self.page_count} of {self.pages_total} pages"


@dataclass(slots=True)
class PageRow:
    """One line of the page inventory."""

    url: str
    path: str
    template: str
    role: str
    depth: str
    #: The performance score, or None when the page was never measured. The
    #: template must print `depth_note` rather than an empty cell: a blank
    #: reads as a zero or as a pass, and neither is true.
    score: float | None
    score_text: str
    status: str
    status_word: str
    findings: int
    urgent: int
    measured: bool
    depth_note: str


@dataclass(slots=True)
class SecurityRow:
    label: str
    value_text: str
    status: str
    status_word: str


@dataclass(slots=True)
class SecuritySection:
    tls: list[SecurityRow] = field(default_factory=list)
    headers: list[SecurityRow] = field(default_factory=list)
    cookies: list[SecurityRow] = field(default_factory=list)
    headers_present: int = 0
    headers_expected: int = len(EXPECTED_SECURITY_HEADERS)


@dataclass(slots=True)
class AppendixRow:
    metric_key: str
    label: str
    value_text: str
    source: str


@dataclass(slots=True)
class Coverage:
    """What the audit actually covered, stated rather than implied.

    Exists because every number on the rest of the page is read against it. A
    report that says "12 pages audited" on a 3,400-page site is not wrong in
    any individual figure and is still misleading, and a client who notices
    stops trusting the parts that were right.
    """

    pages_audited: int = 1
    pages_found: int = 1
    pages_dropped: int = 0
    pages_measured: int = 0
    method: str = "manual"
    method_text: str = "the URL supplied"
    sitemaps: str | None = None
    #: Vulnerability database provenance. Printed beside the Lighthouse and
    #: Chrome versions, because a bundle built once and run for a year
    #: carries a year-old database and a report that does not say so is
    #: wrong in a way nobody can detect.
    vuln_db_generated: str | None = None
    vuln_db_age_days: int | None = None
    vuln_db_sources: str | None = None
    unchecked_ecosystems: str | None = None
    probe_authorised: bool | None = None

    @property
    def capped(self) -> bool:
        return self.pages_dropped > 0

    @property
    def summary(self) -> str:
        if self.pages_audited <= 1:
            return "One page audited."
        if self.capped:
            return (f"{self.pages_audited} of {self.pages_found} pages audited, "
                    f"found via {self.method_text}.")
        return (f"{self.pages_audited} pages audited, "
                f"found via {self.method_text}.")

    @property
    def vulnerability_note(self) -> str:
        """What the vulnerability check did and did not cover.

        Never silent. A report that simply omits this reads as "checked, all
        clear", which is the one thing it must not say when no source is
        configured for half the components on the page.
        """
        if not self.vuln_db_sources or self.vuln_db_sources == "none configured":
            return ("No vulnerability database was available, so no component "
                    "was checked against known vulnerabilities. This is not a "
                    "clean result; it is an absent check.")
        parts = [f"Components were checked against {self.vuln_db_sources}"]
        if self.vuln_db_generated:
            age = (f", last updated {self.vuln_db_age_days} day(s) ago"
                   if self.vuln_db_age_days is not None else "")
            parts.append(f"{age}")
        parts.append(".")
        note = "".join(parts)
        if self.unchecked_ecosystems:
            note += (f" Components in {self.unchecked_ecosystems} have no "
                     "configured source and were NOT checked, which is not "
                     "the same as finding nothing wrong with them.")
        return note

    @property
    def probe_note(self) -> str:
        """Whether the site was probed for exposed endpoints.

        Stated even when probing was never switched on. The first version
        returned "" in that case, which is the failure this whole section
        exists to prevent one level up: a reader looking at a page headed
        "Security" reasonably assumes exposed files were among the things
        checked, and silence lets them keep assuming it. One sentence is a
        cheap price for not implying a check that never happened.
        """
        if self.probe_authorised:
            return ("This site was probed for a short list of files that "
                    "should never be publicly readable, with prior "
                    "authorisation.")
        return ("Endpoint probing was not run against this site, so nothing "
                "here speaks to whether files such as .env or .git are "
                "publicly readable.")

    @property
    def measurement_note(self) -> str:
        """Why most pages have no performance score."""
        if self.pages_audited <= 1 or self.pages_measured >= self.pages_audited:
            return ""
        if self.pages_measured == 0:
            return ("No page received the browser performance audit, so this "
                    "report covers security and delivery only.")
        return (f"{self.pages_measured} of {self.pages_audited} pages received "
                "the full browser performance audit, one per page template. "
                "The rest were checked for security and delivery only.")


@dataclass(slots=True)
class ReportModel:
    hostname: str
    url: str
    final_url: str | None
    run_id: int
    generated_at: str
    audited_at: str
    verdict: Verdict
    top_findings: list[FindingView]
    other_findings: list[FindingView]
    security: SecuritySection
    appendix: list[AppendixRow]
    provenance: dict[str, Any]
    tech: dict[str, Any]
    severity_counts: dict[str, int]
    branding: dict[str, Any] = field(default_factory=dict)
    pages: list[PageRow] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)

    @property
    def total_findings(self) -> int:
        return len(self.top_findings) + len(self.other_findings)

    @property
    def is_multipage(self) -> bool:
        return len(self.pages) > 1


# --------------------------------------------------------------------------

def flatten_observations(observations: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """`{metric_key: value}`, decoding the bool convention as db.py does."""
    out: dict[str, Any] = {}
    for row in observations:
        if row["numeric_value"] is not None:
            out[row["metric_key"]] = (
                bool(row["numeric_value"]) if row["unit"] == "bool"
                else row["numeric_value"]
            )
        else:
            out[row["metric_key"]] = row["text_value"]
    return out


def _format_metric(metric_key: str, value: Any) -> str:
    """Delegates to the schema so report text and rule text never diverge."""
    return format_value(metric_key, value)


def build_verdict(values: dict[str, Any],
                  history: dict[str, list[dict[str, Any]]] | None = None) -> Verdict:
    # History counts as field data, and forgetting that produced a page that
    # announced "No real-user data is available for this site" directly above
    # a paragraph explaining how to read its eight-week real-user chart, with
    # the tiles suppressed in between.
    #
    # `crux.available` answers "did the point-in-time endpoint return a
    # record", which is a question about one API call, not about whether this
    # report has real-user data to show. The two came apart the moment a
    # second source of the same data existed.
    has_history = any(
        any(p.get("p75") is not None for p in series)
        for series in (history or {}).values()
    )
    has_field = bool(values.get("crux.available")) or has_history

    tiles: list[MetricTile] = []
    failing: list[str] = []
    for key, label, caption in CWV_TILES:
        value = values.get(key)
        series = (history or {}).get(key) or []
        measured_points = [p for p in series if p.get("p75") is not None]

        # A tile reading "No data" above its own eight-week trend line is a
        # contradiction the reader has to resolve, and they will resolve it
        # by trusting neither. The latest history period IS the current
        # figure: both endpoints report the p75 of the most recent 28-day
        # window, so falling back to it is the same measurement by another
        # route, not a substitute for it.
        if value is None and measured_points:
            value = measured_points[-1]["p75"]

        status = cwv_status(key, value)
        good_max, poor_min = CWV_BANDS[key]
        if key == "crux.cls.p75":
            value_text = f"{value:.2f}" if value is not None else "n/a"
            threshold = f"Good is {good_max:g} or less"
        else:
            value_text = format_ms(value)
            threshold = f"Good is {format_ms(good_max)} or less"
        if status in ("needs-improvement", "poor"):
            failing.append(label)
        spark_path, threshold_y = field_sparkline(series, good_max)
        measured = measured_points
        trend_word = ""
        if len(measured) >= 2:
            first, last = measured[0]["p75"], measured[-1]["p75"]
            was_good, is_good = first <= good_max, last <= good_max
            if was_good and not is_good:
                trend_word = "Crossed into failing"
            elif is_good and not was_good:
                trend_word = "Improved into good"
            elif abs(last - first) < good_max * 0.05:
                trend_word = "Broadly flat"
            else:
                # CLS is not a speed. "Faster" under a Cumulative Layout
                # Shift heading is a category error, and the sort a client
                # notices because it reads as though we do not know what the
                # metric is.
                worse, better = TREND_WORDS.get(key, ("Worse", "Better"))
                trend_word = worse if last > first else better

        tiles.append(MetricTile(
            key=key, label=label, caption=caption, value_text=value_text,
            status=status, status_word=STATUS_WORDS[status],
            meter_fraction=meter_fraction(key, value),
            threshold_text=threshold,
            spark_path=spark_path, spark_threshold_y=threshold_y,
            spark_weeks=len(measured),
            spark_first=measured[0]["period_end"] if measured else "",
            spark_last=measured[-1]["period_end"] if measured else "",
            trend_word=trend_word,
        ))

    passes = values.get("crux.cwv_pass")
    performance = values.get("lh.score.performance")

    if has_field and passes:
        headline = "Real visitors are having a good experience."
        explanation = (
            "All three of Google's Core Web Vitals are within target for the "
            "75th percentile of real visits over the last 28 days. The "
            "findings below are improvements, not emergencies."
        )
    elif has_field:
        count = len(failing)
        subject = "measure" if count != 1 else "measures"
        headline = (
            f"{count} of 3 Core Web Vitals {subject} outside Google's targets "
            "for real visitors."
        )
        explanation = (
            "These are measurements of actual visits over the last 28 days, "
            "not a lab test. This is what your visitors are experiencing on "
            "their own devices and connections, which is why the site can feel "
            "fast to you and still score badly here."
        )
    elif performance is not None:
        # No field data, but we ran the lab audit ourselves. Lead with the
        # number we actually have rather than with an absence: a verdict page
        # whose headline is "no data" tells the client nothing.
        headline = (
            f"Our own testing scores this site {int(performance)} out of 100 "
            "for performance."
        )
        explanation = (
            "This site does not get enough traffic for Google to publish "
            "real-user measurements, so the figures here come from our own "
            "controlled tests on a simulated mid-range phone and mobile "
            "connection. That is a fair proxy, but it cannot tell you what "
            "any individual visitor experiences."
        )
    else:
        headline = "No real-user data is available for this site."
        explanation = (
            "This site does not get enough traffic for Google to publish "
            "real-user measurements, and no lab audit was run, so the "
            "findings below come from network and security checks only."
        )

    lab_stats = [
        LabStat("Server response time", format_ms(values.get("http.ttfb")),
                "Time before the page could start loading at all"),
        LabStat(
            "Total page weight" if values.get("lh.total_bytes") else "Page HTML size",
            format_bytes(values.get("lh.total_bytes") or values.get("http.content_bytes")),
            "Everything the page downloads" if values.get("lh.total_bytes")
            else "The document itself, before images and scripts",
        ),
        LabStat("Compression",
                str(values.get("http.compression", "none")).upper()
                if values.get("http.compressed") else "Not enabled",
                "Text compression cuts transfer size by roughly 70%"),
        LabStat("Redirects before landing",
                f"{int(values.get('redirect.hops') or 0)}",
                "Each one is a full round trip before anything renders"),
    ]

    categories: list[CategoryScore] = []
    for key, label in (
        ("lh.score.performance", "Performance"),
        ("lh.score.accessibility", "Accessibility"),
        ("lh.score.best_practices", "Best Practices"),
        ("lh.score.seo", "SEO"),
    ):
        score = values.get(key)
        if score is None:
            continue
        # Lighthouse's own banding, so a client comparing against
        # PageSpeed Insights sees the same colour they saw there.
        status = score_status(score)
        categories.append(CategoryScore(label, int(score), status,
                                        STATUS_WORDS[status]))

    has_lab = bool(categories) or values.get("lh.lcp") is not None
    runs = values.get("lh.runs")
    lab_note = ""
    if has_lab and runs:
        lab_note = (
            f"Measured {int(runs)} time{'' if runs == 1 else 's'} on a "
            f"{values.get('lh.form_factor', 'mobile')} profile; the median is "
            "reported."
        )
        spread = values.get("lh.score.performance.spread")
        if spread:
            lab_note += (
                f" The performance score varied by {int(spread)} points "
                "between runs."
            )

    return Verdict(
        has_field_data=has_field,
        passes=passes if isinstance(passes, bool) else None,
        headline=headline, explanation=explanation,
        tiles=tiles, lab_stats=lab_stats,
        categories=categories, has_lab_data=has_lab, lab_note=lab_note,
    )


def short_path(url: str) -> str:
    """The path, for a table cell. `/` for the home page."""
    from urllib.parse import urlsplit

    path = urlsplit(url).path or "/"
    query = urlsplit(url).query
    return f"{path}?{query}" if query else path


def build_finding_views(findings: Iterable[dict[str, Any]], *,
                        pages_total: int = 1) -> list[FindingView]:
    """One view per RULE, carrying the pages it fired on.

    Grouping happens here rather than in SQL or in the findings engine, and
    that placement is deliberate. The engine evaluates one page's flat
    ``{metric_key: value}`` dict and cannot express "3 of 12 pages"; teaching
    it to would turn a small declarative interpreter into code, which is the
    thing rule 3 exists to prevent. So rules fire per page, stay dumb, and the
    aggregation lives here with every other presentation decision.

    Findings arrive severity-ordered from the database, so the first row for a
    rule is the representative: highest severity wins, and its title carries
    whichever page's formatted numbers came first.
    """
    import json

    grouped: dict[str, FindingView] = {}
    for row in findings:
        rule_id = row["rule_id"]
        page_url = row.get("url")

        existing = grouped.get(rule_id)
        if existing is not None:
            if page_url and page_url not in existing.pages:
                existing.pages.append(page_url)
            continue

        evidence: list[EvidenceItem] = []
        evidence_keys: list[str] = []
        if row.get("evidence_json"):
            try:
                for key, value in json.loads(row["evidence_json"]).items():
                    evidence_keys.append(key)
                    metric = METRIC_REGISTRY.get(key)
                    evidence.append(EvidenceItem(
                        label=metric.label if metric else key,
                        value_text=_format_metric(key, value),
                    ))
            except (ValueError, AttributeError):
                pass

        # A rule that read only origin-scoped metrics is describing the
        # origin. Its observations live on the home page because storage is
        # page-keyed, not because the problem stops at the home page.
        origin_keys = origin_scoped_keys()
        origin_scoped = bool(evidence_keys) and all(
            key in origin_keys for key in evidence_keys)

        impact = row.get("impact_ms")
        grouped[rule_id] = FindingView(
            rule_id=rule_id,
            severity=row["severity"],
            severity_word=row["severity"].capitalize(),
            status=SEVERITY_STATUS.get(row["severity"], "muted"),
            title=row["title"],
            detail=" ".join((row.get("detail") or "").split()),
            remediation=" ".join(row["remediation"].split()) if row.get("remediation") else None,
            wp_rocket_setting=row.get("wp_rocket_setting"),
            effort_label=EFFORT_LABELS.get(row.get("effort") or "", None),
            impact_text=format_ms(impact) if impact else None,
            evidence=evidence,
            pages=[page_url] if page_url else [],
            pages_total=pages_total,
            origin_scoped=origin_scoped,
        )

    views = list(grouped.values())
    for view in views:
        # Shortest path first: "/" before "/shop/gizmo". A reader scanning the
        # affected-pages list wants the shallow, high-traffic pages first.
        view.pages.sort(key=lambda u: (len(short_path(u)), u))
    return views


def build_page_rows(pages: Iterable[dict[str, Any]],
                    scores: dict[int, float | None] | None = None) -> list[PageRow]:
    """The page inventory. One row per audited page.

    A page with no performance score prints why, never a blank cell: an empty
    cell in a score column reads as a zero to some people and as a pass to
    others, and the honest answer ("not measured") is neither.
    """
    scores = scores or {}
    rows: list[PageRow] = []
    for page in pages:
        depth = page.get("audit_depth") or "light"
        score = scores.get(page["id"])
        measured = score is not None
        if measured:
            status = score_status(score)
            score_text = f"{round(score)}"
            status_word = STATUS_WORDS.get(status, "")
            note = ""
        else:
            status, status_word, score_text = "muted", "", "—"
            note = ("Measured pages only" if depth == "light"
                    else "Browser audit did not complete")
        rows.append(PageRow(
            url=page["url"],
            path=short_path(page["url"]),
            template=(page.get("template_class") or "page").replace("-", " "),
            role=page.get("role") or "discovered",
            depth=depth,
            score=score,
            score_text=score_text,
            status=status,
            status_word=status_word,
            findings=int(page.get("finding_count") or 0),
            urgent=int(page.get("urgent_count") or 0),
            measured=measured,
            depth_note=note,
        ))
    return rows


def build_coverage(values: dict[str, Any], *, pages_audited: int,
                   pages_measured: int) -> Coverage:
    method = str(values.get("discovery.method") or "manual")
    method_text = {
        "sitemap": "the site's sitemap",
        "crawl": "a crawl of the site's own links",
        "manual": "the URL supplied",
    }.get(method, method)
    found = values.get("discovery.found")
    age = values.get("vuln.db_age_days")
    authorised = values.get("exposure.authorised")
    return Coverage(
        pages_audited=pages_audited,
        pages_found=int(found) if found else pages_audited,
        pages_dropped=int(values.get("discovery.dropped") or 0),
        pages_measured=pages_measured,
        method=method,
        method_text=method_text,
        sitemaps=values.get("discovery.sitemap_urls"),
        vuln_db_generated=values.get("vuln.db_generated"),
        vuln_db_age_days=int(age) if age is not None else None,
        vuln_db_sources=values.get("vuln.db_sources"),
        unchecked_ecosystems=values.get("vuln.unchecked_detail"),
        probe_authorised=(bool(authorised) if authorised is not None else None),
    )


def build_security_section(values: dict[str, Any]) -> SecuritySection:
    section = SecuritySection()

    tls_valid = values.get("tls.valid")
    if tls_valid is not None:
        section.tls.append(SecurityRow(
            "Certificate validates",
            "Yes" if tls_valid else f"No: {values.get('tls.error', 'unknown')}",
            "good" if tls_valid else "critical",
            "Valid" if tls_valid else "Invalid",
        ))
    days = values.get("tls.days_to_expiry")
    if days is not None:
        if days < 0:
            # "Expires in -4 days" is technically true and reads as a bug.
            section.tls.append(SecurityRow(
                "Certificate expiry", f"Expired {abs(days):.0f} days ago",
                "critical", "Expired",
            ))
        else:
            status = "good" if days >= 21 else ("warning" if days >= 7 else "critical")
            section.tls.append(SecurityRow(
                "Certificate expires in", f"{days:.0f} days", status,
                "Fine" if status == "good" else "Renew now",
            ))
    protocol = values.get("tls.protocol")
    if protocol:
        # TLS 1.2 is acceptable, not current. Calling it "Current" in a
        # client-facing document overstates the position: 1.3 is current.
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            status, word = "critical", "Obsolete"
        elif protocol == "TLSv1.2":
            status, word = "good", "Acceptable"
        else:
            status, word = "good", "Current"
        section.tls.append(SecurityRow("TLS version", protocol, status, word))
    if values.get("tls.issuer"):
        section.tls.append(SecurityRow(
            "Issued by", str(values["tls.issuer"]), "muted", ""))

    header_labels = {
        "strict-transport-security": ("Strict-Transport-Security", "sec.hsts"),
        "content-security-policy": ("Content-Security-Policy", "sec.csp"),
        "x-content-type-options": ("X-Content-Type-Options", "sec.x_content_type_options"),
        "x-frame-options": ("X-Frame-Options", "sec.x_frame_options"),
        "referrer-policy": ("Referrer-Policy", "sec.referrer_policy"),
        "permissions-policy": ("Permissions-Policy", "sec.permissions_policy"),
    }
    for header in EXPECTED_SECURITY_HEADERS:
        label, key = header_labels[header]
        value = values.get(key)
        present = value is not None
        if present:
            section.headers_present += 1
        text = str(value)
        if present and len(text) > 70:
            text = text[:67] + "..."
        section.headers.append(SecurityRow(
            label, text if present else "Not set",
            "good" if present else "warning",
            "Present" if present else "Missing",
        ))

    total = values.get("sec.cookies_total")
    if total is not None:
        section.cookies.append(SecurityRow(
            "Cookies set by the server", f"{int(total)}", "muted", ""))
        if total:
            for key, label in (
                ("sec.cookies_insecure", "Missing the Secure flag"),
                ("sec.cookies_no_httponly", "Readable by JavaScript"),
                ("sec.cookies_no_samesite", "Missing SameSite"),
            ):
                count = int(values.get(key) or 0)
                section.cookies.append(SecurityRow(
                    label, f"{count} of {int(total)}",
                    "good" if count == 0 else "warning",
                    "None" if count == 0 else "Review",
                ))
    return section


def build_appendix(observations: Iterable[dict[str, Any]]) -> list[AppendixRow]:
    rows: list[AppendixRow] = []
    for row in observations:
        key = row["metric_key"]
        metric = METRIC_REGISTRY.get(key)
        value = row["numeric_value"] if row["numeric_value"] is not None else row["text_value"]
        if row["unit"] == "bool":
            value = bool(value)
        text = _format_metric(key, value)
        if len(text) > 120:
            text = text[:117] + "..."
        rows.append(AppendixRow(
            metric_key=key,
            label=metric.label if metric else key,
            value_text=text,
            source=row["source"],
        ))
    return rows


def split_findings(findings: list[FindingView], *,
                   min_top: int = 3) -> tuple[list[FindingView], list[FindingView]]:
    """Split into the detailed section and the compact list.

    EVERY critical and high finding gets the detailed treatment, with no cap.
    An earlier version took the top 5 by severity, which meant that on a site
    with six critical-or-high findings an alphabetical rule-id tiebreak
    decided which one got demoted to a one-line entry. That silently buried
    the WP Rocket cold-cache finding, which is the single most actionable
    item SLAP produces. Never cap by count what is ranked by severity.
    """
    top = [f for f in findings if f.severity in ("critical", "high")]
    if len(top) < min_top:
        top_ids = {f.rule_id for f in top}
        top += [f for f in findings if f.rule_id not in top_ids][: min_top - len(top)]
    top_ids = {f.rule_id for f in top}
    return top, [f for f in findings if f.rule_id not in top_ids]


def build_report_model(detail: dict[str, Any], *,
                       generated_at: datetime | None = None,
                       branding: dict[str, Any] | None = None,
                       min_top: int = 3) -> ReportModel:
    """Turn `core.get_run_detail()` output into a renderable model."""
    run = detail["run"]
    observations = detail["observations"]
    pages = detail.get("pages") or []

    # The verdict, the TLS section and the technology fingerprint describe the
    # SITE, so they read the home page's values alone. Flattening every page's
    # observations into one dict renders perfectly and reports whichever page
    # was written last, so a site's headline score would change depending on
    # which product page sorted highest. `home_values` is precomputed by the
    # core; falling back to the flat version keeps single-page callers and the
    # existing tests working unchanged.
    values = detail.get("home_values") or flatten_observations(observations)

    home_id = detail.get("home_page_id")
    page_scores: dict[int, float | None] = {}
    if pages:
        by_page: dict[int, dict[str, Any]] = {}
        for row in observations:
            by_page.setdefault(row["page_id"], {})[row["metric_key"]] = row
        for page in pages:
            row = by_page.get(page["id"], {}).get("lh.score.performance")
            page_scores[page["id"]] = row["numeric_value"] if row else None

    page_rows = build_page_rows(pages, page_scores)
    measured = sum(1 for r in page_rows if r.measured)
    coverage = build_coverage(values, pages_audited=max(1, len(page_rows)),
                              pages_measured=measured)

    # Findings arrive already sorted by severity from the database, and are
    # grouped by rule here: one finding carrying twelve pages, never twelve
    # findings saying the same thing.
    findings = build_finding_views(detail["findings"],
                                   pages_total=max(1, len(page_rows)))
    top, other = split_findings(findings, min_top=min_top)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    stamp = generated_at or datetime.now(timezone.utc)

    return ReportModel(
        hostname=run["hostname"],
        url=values.get("redirect.final_url") or run["hostname"],
        final_url=values.get("redirect.final_url"),
        run_id=run["id"],
        generated_at=stamp.strftime("%d %B %Y"),
        audited_at=str(run["started_at"]).replace("T", " ").replace("+00:00", " UTC"),
        verdict=build_verdict(values, detail.get("crux_history")),
        top_findings=top,
        other_findings=other,
        security=build_security_section(values),
        appendix=build_appendix(observations),
        provenance={
            "run_id": run["id"],
            "batch_id": run["batch_id"],
            "slap_version": run["slap_version"],
            "schema_version": run["schema_version"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "lighthouse_version": run.get("lh_version"),
            "chrome_version": run.get("chrome_version"),
            "throttling_profile": run.get("throttling_profile"),
            "lighthouse_runs": values.get("lh.runs"),
            "benchmark_index": values.get("lh.benchmark_index"),
            "status": run["status"],
        },
        tech={
            "cms": values.get("tech.cms"),
            "cdn": values.get("tech.cdn"),
            "page_builder": values.get("tech.page_builder"),
            "cache_plugin": values.get("tech.cache_plugin"),
            "wp_rocket": values.get("wprocket.present"),
            "wp_rocket_version": values.get("wprocket.version"),
            "wp_rocket_cached": values.get("wprocket.page_cached"),
            "server": values.get("http.server"),
        },
        severity_counts=counts,
        branding=branding or {},
        pages=page_rows,
        coverage=coverage,
    )


# --------------------------------------------------------------------------
# Batch index
# --------------------------------------------------------------------------

@dataclass(slots=True)
class BatchRow:
    run_id: int
    hostname: str
    status: str
    cwv: str
    cwv_word: str
    findings: int
    worst_severity: str
    worst_word: str
    worst_status: str
    lcp_text: str
    ttfb_text: str


@dataclass(slots=True)
class BatchModel:
    batch_id: str
    generated_at: str
    total: int
    completed: int
    failed: int
    rows: list[BatchRow] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    branding: dict[str, Any] = field(default_factory=dict)

    @property
    def sites_failing_cwv(self) -> int:
        return sum(1 for r in self.rows if r.cwv == "poor")

    @property
    def sites_without_field_data(self) -> int:
        return sum(1 for r in self.rows if r.cwv == "unknown")


def build_batch_model(batch_id: str, runs: list[dict[str, Any]],
                      details: dict[int, dict[str, Any]], *,
                      generated_at: datetime | None = None,
                      branding: dict[str, Any] | None = None) -> BatchModel:
    """Roll up one batch. ``details`` maps run id to `get_run_detail` output."""
    stamp = generated_at or datetime.now(timezone.utc)
    counts = {s: 0 for s in SEVERITY_ORDER}
    rows: list[BatchRow] = []

    for run in runs:
        detail = details.get(run["id"])
        values = flatten_observations(detail["observations"]) if detail else {}
        findings = detail["findings"] if detail else []

        worst = None
        for severity in SEVERITY_ORDER:
            if any(f["severity"] == severity for f in findings):
                worst = severity
                break
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        # A site with zero findings is "Clean", not "Info". Defaulting to the
        # lowest severity made a genuinely clean site look like it had
        # something worth reading.
        if worst is None:
            worst, worst_word, worst_status = "clean", "Clean", "good"
        else:
            worst_word, worst_status = worst.capitalize(), SEVERITY_STATUS.get(worst, "muted")

        if not values.get("crux.available"):
            cwv = "unknown"
        elif values.get("crux.cwv_pass"):
            cwv = "good"
        else:
            cwv = "poor"

        rows.append(BatchRow(
            run_id=run["id"],
            hostname=run["hostname"],
            status=run["status"],
            cwv=cwv,
            cwv_word={"good": "Pass", "poor": "Fail", "unknown": "No data"}[cwv],
            findings=len(findings),
            worst_severity=worst,
            worst_word=worst_word,
            worst_status=worst_status,
            lcp_text=format_ms(values.get("crux.lcp.p75")),
            ttfb_text=format_ms(values.get("http.ttfb")),
        ))

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    order["clean"] = len(SEVERITY_ORDER)  # clean sites sort last
    rows.sort(key=lambda r: (order[r.worst_severity], -r.findings))

    return BatchModel(
        batch_id=batch_id,
        generated_at=stamp.strftime("%d %B %Y"),
        total=len(runs),
        completed=sum(1 for r in runs if r["status"] == "completed"),
        failed=sum(1 for r in runs if r["status"] == "failed"),
        rows=rows,
        severity_counts=counts,
        branding=branding or {},
    )
