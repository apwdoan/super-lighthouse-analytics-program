"""Phase 0: the frozen observation contract.

Every collector writes into this shape and every report reads out of it.
Freeze this before adding collectors; changing it later is the expensive
rewrite the roadmap is trying to avoid.

Two rules that keep the contract honest:

1. A metric key must be registered in :data:`METRIC_REGISTRY` before a
   collector may emit it. Unregistered keys raise at collection time
   rather than silently producing a column nothing knows how to render.
2. Numeric facts go in ``numeric_value`` with a real :class:`Unit`.
   ``text_value`` is for genuinely categorical data (a header value, a
   CDN name), never for a number that has been stringified.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Source(str, Enum):
    """Where an observation came from. Recorded on every row."""

    HTTP = "http"
    TLS = "tls"
    REDIRECT = "redirect"
    FINGERPRINT = "fingerprint"
    CRUX = "crux"
    CRUX_HISTORY = "crux_history"
    LIGHTHOUSE = "lighthouse"
    OBSERVATORY = "observatory"


class Unit(str, Enum):
    NONE = "none"
    MS = "ms"
    SECONDS = "s"
    BYTES = "bytes"
    COUNT = "count"
    RATIO = "ratio"
    DAYS = "days"
    SCORE = "score"
    BOOL = "bool"


class FormFactor(str, Enum):
    MOBILE = "mobile"
    DESKTOP = "desktop"
    NONE = "none"  # collectors that are not form-factor sensitive


class PageRole(str, Enum):
    """What a page is to the site audit.

    HOME is the anchor: it is the page a site trend line follows across runs,
    and the row origin-scoped observations attach to. Exactly one page per run
    carries it, which is what keeps run-to-run comparison arithmetic rather
    than a join over a page set that changes whenever the site does.
    """

    HOME = "home"
    TEMPLATE = "template"      # a representative of a template class
    DISCOVERED = "discovered"  # found, audited, not chosen as a representative


class DiscoveredVia(str, Enum):
    MANUAL = "manual"
    SITEMAP = "sitemap"
    CRAWL = "crawl"


class AuditDepth(str, Enum):
    """What was *attempted* on a page, not what succeeded.

    Stored rather than derived from artifact presence, because deriving it
    conflates "Lighthouse was never asked to run here" with "Lighthouse ran
    and failed", and the report needs a different sentence for each.
    """

    FULL = "full"    # the browser audit was attempted
    LIGHT = "light"  # no-browser collectors only, by design


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED)


class Scope(str, Enum):
    """Whether a metric describes one page or the whole origin.

    Storage is page-keyed, so an origin-scoped fact still lands on a page row
    (the home page). Scope is what stops the report reprinting "certificate
    expires in 40 days" once per page, and what stops an origin-scoped
    collector running twenty times against the same host.
    """

    PAGE = "page"
    ORIGIN = "origin"


@dataclass(frozen=True, slots=True)
class Metric:
    """Registry entry describing one metric key."""

    key: str
    unit: Unit
    source: Source
    label: str
    higher_is_better: bool | None = None
    #: Defaulted, because every one of the ~180 existing entries is built
    #: positionally through `_m()` and a required field would break the
    #: registry at import time. Most metrics really are page-scoped; only
    #: the handful that describe the origin need to say so.
    scope: Scope = Scope.PAGE


def _m(key: str, unit: Unit, source: Source, label: str,
       higher_is_better: bool | None = None,
       scope: Scope = Scope.PAGE) -> Metric:
    return Metric(key, unit, source, label, higher_is_better, scope)


def origin_scoped_keys() -> frozenset[str]:
    """Metric keys that describe the origin rather than an individual page."""
    return frozenset(k for k, m in METRIC_REGISTRY.items()
                     if m.scope is Scope.ORIGIN)


#: The authoritative list of metric keys. Collectors validate against this.
METRIC_REGISTRY: dict[str, Metric] = {
    m.key: m
    for m in [
        # --- HTTP response ------------------------------------------------
        _m("http.status", Unit.COUNT, Source.HTTP, "Final HTTP status"),
        _m("http.version", Unit.NONE, Source.HTTP, "HTTP protocol version"),
        _m("http.ttfb", Unit.MS, Source.HTTP, "Time to first byte", False),
        _m("http.content_bytes", Unit.BYTES, Source.HTTP, "HTML document size", False),
        _m("http.compression", Unit.NONE, Source.HTTP, "Content-Encoding"),
        _m("http.compressed", Unit.BOOL, Source.HTTP, "Response is compressed", True),
        _m("http.cache_control", Unit.NONE, Source.HTTP, "Cache-Control header"),
        _m("http.cache_max_age", Unit.SECONDS, Source.HTTP, "Cache max-age", True),
        _m("http.has_etag", Unit.BOOL, Source.HTTP, "ETag present", True),
        _m("http.server", Unit.NONE, Source.HTTP, "Server header"),
        # --- Security headers ---------------------------------------------
        _m("sec.hsts", Unit.NONE, Source.HTTP, "Strict-Transport-Security"),
        _m("sec.hsts_max_age", Unit.SECONDS, Source.HTTP, "HSTS max-age", True),
        _m("sec.csp", Unit.NONE, Source.HTTP, "Content-Security-Policy"),
        _m("sec.x_content_type_options", Unit.NONE, Source.HTTP, "X-Content-Type-Options"),
        _m("sec.x_frame_options", Unit.NONE, Source.HTTP, "X-Frame-Options"),
        _m("sec.referrer_policy", Unit.NONE, Source.HTTP, "Referrer-Policy"),
        _m("sec.permissions_policy", Unit.NONE, Source.HTTP, "Permissions-Policy"),
        _m("sec.missing_header_count", Unit.COUNT, Source.HTTP, "Missing security headers", False),
        _m("sec.cookies_total", Unit.COUNT, Source.HTTP, "Cookies set on response"),
        _m("sec.cookies_insecure", Unit.COUNT, Source.HTTP, "Cookies missing Secure", False),
        _m("sec.cookies_no_httponly", Unit.COUNT, Source.HTTP, "Cookies missing HttpOnly", False),
        _m("sec.cookies_no_samesite", Unit.COUNT, Source.HTTP, "Cookies missing SameSite", False),
        # --- Redirects -----------------------------------------------------
        _m("redirect.hops", Unit.COUNT, Source.REDIRECT, "Redirect hops", False),
        _m("redirect.chain", Unit.NONE, Source.REDIRECT, "Redirect chain"),
        _m("redirect.upgrades_to_https", Unit.BOOL, Source.REDIRECT, "HTTP upgrades to HTTPS", True),
        _m("redirect.final_url", Unit.NONE, Source.REDIRECT, "Final URL after redirects"),
        # --- TLS --------------------------------------------------------------
        # Origin-scoped: one certificate serves every page on the host. Running
        # the probe per page is N identical results and N wasted handshakes,
        # and printing it per page is the same sentence twenty times.
        _m("tls.protocol", Unit.NONE, Source.TLS, "Negotiated TLS version", None, Scope.ORIGIN),
        _m("tls.cipher", Unit.NONE, Source.TLS, "Negotiated cipher", None, Scope.ORIGIN),
        _m("tls.issuer", Unit.NONE, Source.TLS, "Certificate issuer", None, Scope.ORIGIN),
        _m("tls.subject", Unit.NONE, Source.TLS, "Certificate subject", None, Scope.ORIGIN),
        _m("tls.days_to_expiry", Unit.DAYS, Source.TLS, "Days until certificate expiry", True, Scope.ORIGIN),
        _m("tls.valid", Unit.BOOL, Source.TLS, "Certificate chain validates", True, Scope.ORIGIN),
        _m("tls.error", Unit.NONE, Source.TLS, "TLS handshake error", None, Scope.ORIGIN),
        # --- Tech fingerprint -------------------------------------------------
        _m("tech.cms", Unit.NONE, Source.FINGERPRINT, "Detected CMS"),
        _m("tech.generator", Unit.NONE, Source.FINGERPRINT, "Generator meta tag"),
        _m("tech.cdn", Unit.NONE, Source.FINGERPRINT, "Detected CDN"),
        _m("tech.page_builder", Unit.NONE, Source.FINGERPRINT, "Detected page builder"),
        _m("tech.cache_plugin", Unit.NONE, Source.FINGERPRINT, "Detected caching layers"),
        _m("wprocket.present", Unit.BOOL, Source.FINGERPRINT, "WP Rocket installed"),
        _m("wprocket.version", Unit.NONE, Source.FINGERPRINT, "WP Rocket version"),
        _m("wprocket.features", Unit.NONE, Source.FINGERPRINT, "WP Rocket enabled features"),
        _m("wprocket.page_cached", Unit.BOOL, Source.FINGERPRINT, "Page served from WP Rocket cache", True),
        _m("wprocket.cached_at", Unit.NONE, Source.FINGERPRINT, "WP Rocket cache timestamp"),
        # --- CrUX field data ---------------------------------------------------
        # Origin-scoped as collected: the CruxCollector queries the origin, so
        # every page of a site would receive an identical answer. Querying it
        # per page is 20x the quota for the same numbers. The API does accept a
        # url parameter, but most individual pages lack the traffic to have a
        # record, so per-URL field data is an enhancement, not the default.
        _m("crux.available", Unit.BOOL, Source.CRUX, "CrUX record exists", True, Scope.ORIGIN),
        _m("crux.lcp.p75", Unit.MS, Source.CRUX, "LCP (field, 75th pct)", False, Scope.ORIGIN),
        _m("crux.inp.p75", Unit.MS, Source.CRUX, "INP (field, 75th pct)", False, Scope.ORIGIN),
        # CLS is a unitless score, NOT a ratio. Declaring it RATIO makes every
        # formatter render 0.06 as "6%", which is wrong and reads as a
        # percentage of something.
        _m("crux.cls.p75", Unit.SCORE, Source.CRUX, "CLS (field, 75th pct)", False, Scope.ORIGIN),
        _m("crux.ttfb.p75", Unit.MS, Source.CRUX, "TTFB (field, 75th pct)", False, Scope.ORIGIN),
        _m("crux.lcp.good", Unit.RATIO, Source.CRUX, "Share of LCP visits rated good", True, Scope.ORIGIN),
        _m("crux.inp.good", Unit.RATIO, Source.CRUX, "Share of INP visits rated good", True, Scope.ORIGIN),
        _m("crux.cls.good", Unit.RATIO, Source.CRUX, "Share of CLS visits rated good", True, Scope.ORIGIN),
        _m("crux.cwv_pass", Unit.BOOL, Source.CRUX, "Passes Core Web Vitals", True, Scope.ORIGIN),
        # --- CrUX history: 25 weekly periods --------------------------------
        # The series itself lives in its own table; these are the run-level
        # facts rules fire on. Origin-scoped, like everything else from CrUX.
        _m("crux.history.available", Unit.BOOL, Source.CRUX_HISTORY,
           "Field-data history exists", True, Scope.ORIGIN),
        _m("crux.history.weeks", Unit.COUNT, Source.CRUX_HISTORY,
           "Weekly periods available", None, Scope.ORIGIN),
        _m("crux.history.lcp.delta", Unit.MS, Source.CRUX_HISTORY,
           "LCP change across the period", False, Scope.ORIGIN),
        _m("crux.history.inp.delta", Unit.MS, Source.CRUX_HISTORY,
           "INP change across the period", False, Scope.ORIGIN),
        _m("crux.history.cls.delta", Unit.SCORE, Source.CRUX_HISTORY,
           "CLS change across the period", False, Scope.ORIGIN),
        _m("crux.history.lcp.first", Unit.MS, Source.CRUX_HISTORY,
           "LCP at the start of the period", False, Scope.ORIGIN),
        _m("crux.history.inp.first", Unit.MS, Source.CRUX_HISTORY,
           "INP at the start of the period", False, Scope.ORIGIN),
        _m("crux.history.cls.first", Unit.SCORE, Source.CRUX_HISTORY,
           "CLS at the start of the period", False, Scope.ORIGIN),
        # Crossed a Core Web Vitals threshold the wrong way. Not a raw delta:
        # 1.2s -> 2.4s doubled and still passes; 2.4s -> 2.6s barely moved and
        # now fails, and only the second is worth telling a client about.
        _m("crux.history.regressed", Unit.BOOL, Source.CRUX_HISTORY,
           "A vital crossed from good to failing", False, Scope.ORIGIN),
        _m("crux.history.regressed_metrics", Unit.NONE, Source.CRUX_HISTORY,
           "Which vitals regressed", None, Scope.ORIGIN),
        _m("crux.history.improved", Unit.BOOL, Source.CRUX_HISTORY,
           "A vital crossed from failing to good", True, Scope.ORIGIN),
        _m("crux.history.improved_metrics", Unit.NONE, Source.CRUX_HISTORY,
           "Which vitals improved", None, Scope.ORIGIN),
        _m("crux.history.first_period", Unit.NONE, Source.CRUX_HISTORY,
           "Earliest period covered", None, Scope.ORIGIN),
        _m("crux.history.last_period", Unit.NONE, Source.CRUX_HISTORY,
           "Latest period covered", None, Scope.ORIGIN),
        # --- Lighthouse: category scores (0-100) --------------------------
        _m("lh.score.performance", Unit.SCORE, Source.LIGHTHOUSE, "Performance score", True),
        _m("lh.score.accessibility", Unit.SCORE, Source.LIGHTHOUSE, "Accessibility score", True),
        _m("lh.score.best_practices", Unit.SCORE, Source.LIGHTHOUSE, "Best Practices score", True),
        _m("lh.score.seo", Unit.SCORE, Source.LIGHTHOUSE, "SEO score", True),
        # --- Lighthouse: lab metrics (median across runs) ------------------
        _m("lh.lcp", Unit.MS, Source.LIGHTHOUSE, "LCP (lab)", False),
        _m("lh.fcp", Unit.MS, Source.LIGHTHOUSE, "First Contentful Paint (lab)", False),
        _m("lh.tbt", Unit.MS, Source.LIGHTHOUSE, "Total Blocking Time (lab)", False),
        _m("lh.cls", Unit.SCORE, Source.LIGHTHOUSE, "CLS (lab)", False),
        _m("lh.speed_index", Unit.MS, Source.LIGHTHOUSE, "Speed Index (lab)", False),
        _m("lh.tti", Unit.MS, Source.LIGHTHOUSE, "Time to Interactive (lab)", False),
        _m("lh.server_response", Unit.MS, Source.LIGHTHOUSE, "Server response time (lab)", False),
        _m("lh.total_bytes", Unit.BYTES, Source.LIGHTHOUSE, "Total page weight", False),
        _m("lh.bootup_time", Unit.MS, Source.LIGHTHOUSE, "JavaScript execution time", False),
        _m("lh.mainthread_work", Unit.MS, Source.LIGHTHOUSE, "Main-thread work", False),
        _m("lh.dom_elements", Unit.COUNT, Source.LIGHTHOUSE, "DOM element count", False),
        # --- Lighthouse: run reproducibility ------------------------------
        # The roadmap's central warning is that contended CPU produces
        # plausible, irreproducible numbers. These are the observations that
        # let the report say so instead of hiding it.
        _m("lh.runs", Unit.COUNT, Source.LIGHTHOUSE, "Lighthouse runs taken"),
        _m("lh.lcp.spread", Unit.MS, Source.LIGHTHOUSE, "LCP spread across runs", False),
        _m("lh.tbt.spread", Unit.MS, Source.LIGHTHOUSE, "TBT spread across runs", False),
        _m("lh.score.performance.spread", Unit.SCORE, Source.LIGHTHOUSE,
           "Performance score spread across runs", False),
        _m("lh.benchmark_index", Unit.SCORE, Source.LIGHTHOUSE,
           "CPU benchmark of the measuring machine", True),
        _m("lh.benchmark_index.spread", Unit.SCORE, Source.LIGHTHOUSE,
           "CPU benchmark spread across runs", False),
        _m("lh.throttling_profile", Unit.NONE, Source.LIGHTHOUSE, "Throttling profile"),
        _m("lh.form_factor", Unit.NONE, Source.LIGHTHOUSE, "Form factor measured"),
        # --- Mixed content and third-party subresources --------------------
        # Page-scoped by nature: this is the whole reason per-page exists. A
        # marketing landing page loads trackers the homepage does not.
        _m("mixed.insecure_count", Unit.COUNT, Source.HTTP,
           "Insecure subresources on an HTTPS page", False),
        _m("mixed.insecure_urls", Unit.NONE, Source.HTTP, "Insecure subresource URLs"),
        # "How the answer was reached" is an observation in its own right,
        # because "no mixed content found" means two different things
        # depending on whether a browser or a regex looked.
        _m("mixed.method", Unit.NONE, Source.HTTP, "How subresources were inspected"),
        # A form action is not a subresource: nothing is fetched until the
        # user submits, and what leaks is what they typed.
        _m("mixed.insecure_forms", Unit.COUNT, Source.HTTP,
           "Forms submitting over plain HTTP", False),
        _m("mixed.insecure_form_urls", Unit.NONE, Source.HTTP, "Insecure form actions"),
        _m("thirdparty.origin_count", Unit.COUNT, Source.HTTP,
           "Distinct third-party origins", False),
        _m("thirdparty.origins", Unit.NONE, Source.HTTP, "Third-party origins"),
        # --- Page inventory -------------------------------------------------
        _m("page.role", Unit.NONE, Source.HTTP, "Role of this page in the audit"),
        _m("page.template_class", Unit.NONE, Source.HTTP, "Detected page template"),
        _m("page.discovered_via", Unit.NONE, Source.HTTP, "How this page was found"),
        _m("page.audit_depth", Unit.NONE, Source.HTTP, "Depth of audit attempted"),
        # --- Discovery, origin-scoped ---------------------------------------
        _m("discovery.method", Unit.NONE, Source.HTTP, "How pages were discovered",
           None, Scope.ORIGIN),
        _m("discovery.found", Unit.COUNT, Source.HTTP, "Pages discovered",
           None, Scope.ORIGIN),
        _m("discovery.audited", Unit.COUNT, Source.HTTP, "Pages audited",
           None, Scope.ORIGIN),
        # A cap that is applied and not stated reads as full coverage. This is
        # the observation that lets the report say "12 of 3,400".
        _m("discovery.dropped", Unit.COUNT, Source.HTTP,
           "Pages discovered but not audited (cap)", False, Scope.ORIGIN),
        _m("discovery.sitemap_urls", Unit.NONE, Source.HTTP, "Sitemaps read",
           None, Scope.ORIGIN),
        # --- Software components --------------------------------------------
        # Page-scoped: a plugin that only enqueues assets on the checkout page
        # is present on the checkout page, and saying so is more useful than
        # flattening it to a site-level fact.
        _m("component.count", Unit.COUNT, Source.FINGERPRINT, "Components detected"),
        _m("component.observed_count", Unit.COUNT, Source.FINGERPRINT,
           "Components with a browser-observed version"),
        _m("component.inferred_count", Unit.COUNT, Source.FINGERPRINT,
           "Components with an inferred version"),
        _m("component.detected", Unit.NONE, Source.FINGERPRINT, "Detected components"),
        # --- Known vulnerabilities -------------------------------------------
        # `confirmed` means the VERSION was observed by a browser, not that the
        # vulnerability was exploited. `possible` means the version came from a
        # ?ver= query string and may be wrong.
        _m("vuln.confirmed_count", Unit.COUNT, Source.FINGERPRINT,
           "Known vulnerabilities in observed versions", False),
        _m("vuln.confirmed_critical", Unit.COUNT, Source.FINGERPRINT,
           "Critical vulnerabilities", False),
        _m("vuln.confirmed_high", Unit.COUNT, Source.FINGERPRINT,
           "High-severity vulnerabilities", False),
        _m("vuln.confirmed_medium", Unit.COUNT, Source.FINGERPRINT,
           "Medium-severity vulnerabilities", False),
        _m("vuln.confirmed_detail", Unit.NONE, Source.FINGERPRINT,
           "Vulnerabilities in observed versions"),
        # Just the identifiers. The title is the only string that survives
        # every rendering path (the compact finding list, the CLI's default
        # output, the web UI's rows all drop the detail), and "2 known
        # vulnerabilities" is not something a client can act on.
        _m("vuln.confirmed_ids", Unit.NONE, Source.FINGERPRINT,
           "Vulnerability identifiers"),
        _m("vuln.possible_ids", Unit.NONE, Source.FINGERPRINT,
           "Possible vulnerability identifiers"),
        _m("vuln.possible_count", Unit.COUNT, Source.FINGERPRINT,
           "Possible vulnerabilities in inferred versions", False),
        _m("vuln.possible_detail", Unit.NONE, Source.FINGERPRINT,
           "Possible vulnerabilities"),
        # Components in an ecosystem with no configured database. The metric
        # that stops "nothing found" being read as "nothing there".
        _m("vuln.unchecked_count", Unit.COUNT, Source.FINGERPRINT,
           "Components not checked against any database", False),
        _m("vuln.unchecked_detail", Unit.NONE, Source.FINGERPRINT,
           "Ecosystems with no vulnerability source"),
        _m("vuln.db_generated", Unit.NONE, Source.FINGERPRINT,
           "Vulnerability database date", None, Scope.ORIGIN),
        _m("vuln.db_age_days", Unit.DAYS, Source.FINGERPRINT,
           "Vulnerability database age", False, Scope.ORIGIN),
        _m("vuln.db_sources", Unit.NONE, Source.FINGERPRINT,
           "Vulnerability sources configured", None, Scope.ORIGIN),
        # --- Exposed endpoints ------------------------------------------------
        # Origin-scoped: these are properties of the server, not of a page.
        _m("exposure.authorised", Unit.BOOL, Source.HTTP,
           "Endpoint probing authorised for this site", None, Scope.ORIGIN),
        _m("exposure.checked", Unit.COUNT, Source.HTTP, "Paths probed",
           None, Scope.ORIGIN),
        _m("exposure.found_count", Unit.COUNT, Source.HTTP,
           "Paths that should not be reachable", False, Scope.ORIGIN),
        _m("exposure.secrets_count", Unit.COUNT, Source.HTTP,
           "Exposed secrets or database dumps", False, Scope.ORIGIN),
        _m("exposure.vcs_count", Unit.COUNT, Source.HTTP,
           "Exposed version-control metadata", False, Scope.ORIGIN),
        _m("exposure.info_count", Unit.COUNT, Source.HTTP,
           "Exposed diagnostic endpoints", False, Scope.ORIGIN),
        _m("exposure.wp_surface_count", Unit.COUNT, Source.HTTP,
           "Exposed WordPress attack surface", False, Scope.ORIGIN),
        _m("exposure.paths", Unit.NONE, Source.HTTP, "Reachable paths",
           None, Scope.ORIGIN),
        # Per category, because one shared list made every exposure rule
        # recite every finding: the version-control rule was describing
        # /.env and /backup.sql as git metadata.
        _m("exposure.secrets_paths", Unit.NONE, Source.HTTP,
           "Reachable credential files", None, Scope.ORIGIN),
        _m("exposure.vcs_paths", Unit.NONE, Source.HTTP,
           "Reachable version-control paths", None, Scope.ORIGIN),
        _m("exposure.info_paths", Unit.NONE, Source.HTTP,
           "Reachable diagnostic endpoints", None, Scope.ORIGIN),
        _m("exposure.wp_surface_paths", Unit.NONE, Source.HTTP,
           "Reachable WordPress endpoints", None, Scope.ORIGIN),
        # How "not found" was decided. A probe run against a site that returns
        # 200 for everything is much weaker evidence and must say so.
        _m("exposure.control_status", Unit.COUNT, Source.HTTP,
           "Status for a path that cannot exist", None, Scope.ORIGIN),
        _m("exposure.soft_404", Unit.BOOL, Source.HTTP,
           "Site returns success for missing paths", False, Scope.ORIGIN),
        _m("exposure.waf_detected", Unit.BOOL, Source.HTTP,
           "A firewall answered instead of the server", None, Scope.ORIGIN),
    ]
}

# --------------------------------------------------------------------------
# Lighthouse opportunities.
#
# Lighthouse 13 replaced the classic opportunity audits with "insights" and
# a new savings API. The old IDs the industry still quotes are GONE:
#
#   render-blocking-resources  ->  render-blocking-insight
#   uses-long-cache-ttl        ->  cache-insight
#   modern-image-formats,      ->  image-delivery-insight  (all four merged)
#   uses-optimized-images,
#   offscreen-images,
#   uses-responsive-images
#   font-display               ->  font-display-insight
#   legacy-javascript          ->  legacy-javascript-insight
#   third-party-summary        ->  third-parties-insight
#   dom-size                   ->  dom-size-insight
#
# Savings moved from ``details.overallSavingsMs`` to
# ``metricSavings: {FCP, LCP, INP, ...}``. Writing rules against the old IDs
# produces rules that never fire and an audit that silently finds nothing.
# --------------------------------------------------------------------------

#: audit id -> (metric key suffix, human label)
LIGHTHOUSE_OPPORTUNITIES: dict[str, tuple[str, str]] = {
    "render-blocking-insight": ("render_blocking", "Render-blocking requests"),
    "cache-insight": ("cache", "Inefficient cache lifetimes"),
    "image-delivery-insight": ("image_delivery", "Image delivery"),
    "document-latency-insight": ("document_latency", "Document request latency"),
    "lcp-discovery-insight": ("lcp_discovery", "LCP image discovery"),
    "legacy-javascript-insight": ("legacy_javascript", "Legacy JavaScript"),
    "duplicated-javascript-insight": ("duplicated_javascript", "Duplicated JavaScript"),
    "font-display-insight": ("font_display", "Font display"),
    "network-dependency-tree-insight": ("network_dependency", "Network dependency chain"),
    "forced-reflow-insight": ("forced_reflow", "Forced reflow"),
    "modern-http-insight": ("modern_http", "Modern HTTP usage"),
    "third-parties-insight": ("third_parties", "Third-party code"),
    "dom-size-insight": ("dom_size", "DOM size"),
    "cls-culprits-insight": ("cls_culprits", "Layout shift causes"),
    "viewport-insight": ("viewport", "Mobile viewport"),
    "unminified-css": ("unminified_css", "Unminified CSS"),
    "unminified-javascript": ("unminified_js", "Unminified JavaScript"),
    "unused-css-rules": ("unused_css", "Unused CSS"),
    "unused-javascript": ("unused_js", "Unused JavaScript"),
}

for _audit_id, (_suffix, _label) in LIGHTHOUSE_OPPORTUNITIES.items():
    METRIC_REGISTRY[f"lh.opp.{_suffix}"] = _m(
        f"lh.opp.{_suffix}", Unit.MS, Source.LIGHTHOUSE,
        f"{_label}: estimated saving", False,
    )
del _audit_id, _suffix, _label

#: Security headers the report expects to see, in the order it lists them.
EXPECTED_SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

#: Core Web Vitals "good" thresholds, per web.dev.
CWV_GOOD_THRESHOLDS: dict[str, float] = {
    "crux.lcp.p75": 2500.0,
    "crux.inp.p75": 200.0,
    "crux.cls.p75": 0.1,
}


class UnknownMetricError(KeyError):
    """Raised when a collector emits a metric key that is not registered."""


def _plural(number: float, noun: str) -> str:
    """`1 hour`, not `1 hours`. Rounds first so 1.4 reads as singular."""
    rounded = round(number)
    return f"{rounded:.0f} {noun}" if abs(rounded) == 1 else f"{rounded:.0f} {noun}s"


def format_value(metric_key: str, value: Any) -> str:
    """Render a value for human eyes, using the registry's declared unit.

    Lives here rather than in the report layer because the findings engine
    substitutes metric values into rule text: a rule author writes
    ``{http.content_bytes}`` and must get "402 KB", not "412000". Rule text
    therefore must NOT append its own unit after a placeholder.
    """
    if value is None:
        return "n/a"
    metric = METRIC_REGISTRY.get(metric_key)
    unit = metric.unit if metric else Unit.NONE

    if unit is Unit.BOOL:
        return "Yes" if value else "No"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)

    if unit is Unit.MS:
        return f"{number / 1000:.1f}s" if number >= 1000 else f"{round(number):g}ms"
    if unit is Unit.BYTES:
        if number >= 1_048_576:
            return f"{number / 1_048_576:.1f} MB"
        if number >= 1024:
            return f"{number / 1024:.0f} KB"
        return f"{number:.0f} bytes"
    if unit is Unit.SECONDS:
        for divisor, noun in ((86400, "day"), (3600, "hour"), (60, "minute")):
            if number >= divisor:
                return _plural(number / divisor, noun)
        return _plural(number, "second")
    if unit is Unit.DAYS:
        return _plural(number, "day")
    if unit is Unit.RATIO:
        return f"{number:.0%}"
    return f"{number:g}"


@dataclass(frozen=True, slots=True)
class Observation:
    """One immutable fact about one page, from one source."""

    source: Source
    metric_key: str
    numeric_value: float | None = None
    text_value: str | None = None
    unit: Unit = Unit.NONE

    def __post_init__(self) -> None:
        metric = METRIC_REGISTRY.get(self.metric_key)
        if metric is None:
            raise UnknownMetricError(
                f"{self.metric_key!r} is not in METRIC_REGISTRY. "
                "Register it in slap.schema before emitting it."
            )
        if self.numeric_value is None and self.text_value is None:
            raise ValueError(f"{self.metric_key!r} observation has no value")
        # Unit defaults to the registry's declaration so collectors cannot drift.
        if self.unit is Unit.NONE and metric.unit is not Unit.NONE:
            object.__setattr__(self, "unit", metric.unit)

    @property
    def label(self) -> str:
        return METRIC_REGISTRY[self.metric_key].label

    @property
    def value(self) -> Any:
        if self.numeric_value is not None:
            if self.unit is Unit.BOOL:
                return bool(self.numeric_value)
            return self.numeric_value
        return self.text_value


def obs(metric_key: str, value: Any, *, source: Source | None = None) -> Observation:
    """Build an Observation, inferring numeric vs text and the unit.

    This is the constructor collectors should use. It exists so a collector
    never has to remember which column a value belongs in.
    """
    metric = METRIC_REGISTRY.get(metric_key)
    if metric is None:
        raise UnknownMetricError(
            f"{metric_key!r} is not in METRIC_REGISTRY. "
            "Register it in slap.schema before emitting it."
        )
    src = source or metric.source
    if isinstance(value, bool):
        return Observation(src, metric_key, numeric_value=float(value), unit=Unit.BOOL)
    if isinstance(value, (int, float)):
        return Observation(src, metric_key, numeric_value=float(value), unit=metric.unit)
    return Observation(src, metric_key, text_value=str(value), unit=metric.unit)


@dataclass(slots=True)
class PageResult:
    """Everything one collector pass produced for one URL."""

    url: str
    final_url: str | None = None
    form_factor: FormFactor = FormFactor.NONE
    observations: list[Observation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: Anything a collector produced that is not an observation: Lighthouse
    #: artifacts and run provenance, for example. Keyed by collector name.
    extras: dict[str, Any] = field(default_factory=dict)
    #: How this page came to be audited, and how deeply. Defaults describe a
    #: single manually supplied page, which is what a one-URL audit is, so
    #: every existing caller keeps its old meaning without saying anything.
    role: PageRole = PageRole.HOME
    discovered_via: DiscoveredVia = DiscoveredVia.MANUAL
    audit_depth: AuditDepth = AuditDepth.LIGHT
    template_class: str | None = None

    def add(self, metric_key: str, value: Any, *, source: Source | None = None) -> None:
        if value is None:
            return
        self.observations.append(obs(metric_key, value, source=source))

    def extend(self, others: list[Observation]) -> None:
        self.observations.extend(others)

    def get(self, metric_key: str) -> Any:
        for o in self.observations:
            if o.metric_key == metric_key:
                return o.value
        return None


@dataclass(frozen=True, slots=True)
class Finding:
    """A rule firing against a page's observations."""

    rule_id: str
    severity: Severity
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    impact_ms: float | None = None
    effort: str | None = None
    remediation: str | None = None
    wp_rocket_setting: str | None = None
