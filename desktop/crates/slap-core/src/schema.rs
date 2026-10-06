//! The frozen observation contract.
//!
//! Every collector writes into this shape and every report reads out of it.
//! The registry, the units, and the formatter are the parts of SLAP that
//! must not drift between app versions: they all write rows into the same
//! `observation` table and render the same rows, so a metric that means one
//! thing in one version and another in the next would silently corrupt
//! months of stored runs.
//!
//! Two rules that keep the contract honest:
//!
//! 1. A metric key must be registered in [`metric_registry`] before a
//!    collector may emit it. Unregistered keys error at collection time
//!    rather than silently producing a column nothing knows how to render.
//! 2. Numeric facts go in `numeric_value` with a real [`Unit`]. `text_value`
//!    is for genuinely categorical data (a header value, a CDN name), never
//!    for a number that has been stringified.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Enums. Each carries the exact strings the shared database stores.
// ---------------------------------------------------------------------------

macro_rules! string_enum {
    ($(#[$doc:meta])* $name:ident {
        $($(#[$vdoc:meta])* $variant:ident => $text:literal),+ $(,)?
    }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            pub fn parse(text: &str) -> Option<Self> {
                match text { $($text => Some(Self::$variant),)+ _ => None }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str(self.as_str())
            }
        }
    };
}

string_enum! {
    /// Where an observation came from. Recorded on every row.
    Source {
        Http => "http",
        Tls => "tls",
        Redirect => "redirect",
        Fingerprint => "fingerprint",
        Crux => "crux",
        CruxHistory => "crux_history",
        Lighthouse => "lighthouse",
        Observatory => "observatory",
    }
}

string_enum! {
    Unit {
        None => "none",
        Ms => "ms",
        Seconds => "s",
        Bytes => "bytes",
        Count => "count",
        Ratio => "ratio",
        Days => "days",
        Score => "score",
        Bool => "bool",
    }
}

string_enum! {
    FormFactor {
        Mobile => "mobile",
        Desktop => "desktop",
        /// Collectors that are not form-factor sensitive.
        None => "none",
    }
}

string_enum! {
    /// What a page is to the site audit. HOME is the anchor: the page a site
    /// trend line follows across runs, and the row origin-scoped
    /// observations attach to. Exactly one page per run carries it.
    PageRole {
        Home => "home",
        Template => "template",
        Discovered => "discovered",
    }
}

string_enum! {
    DiscoveredVia {
        Manual => "manual",
        Sitemap => "sitemap",
        Crawl => "crawl",
    }
}

string_enum! {
    /// What was *attempted* on a page, not what succeeded. Stored rather
    /// than derived, because deriving it conflates "Lighthouse was never
    /// asked to run here" with "Lighthouse ran and failed", and the report
    /// needs a different sentence for each.
    AuditDepth {
        Full => "full",
        Light => "light",
    }
}

string_enum! {
    /// Which of a site's pages get the browser (Lighthouse) audit. Recorded on
    /// the run, because a report has to say which it was: "all 20 discovered
    /// pages measured" and "5 of 20, one per template" are different claims.
    ///
    /// `Sampled` is the default and measures one representative per template,
    /// coverage-ordered, up to the per-site budget. `EveryPage` measures every
    /// page discovery found (still bounded by the discovery cap, which is
    /// disclosed). At ~90s a page and a concurrency cap of 3, every page of a
    /// 100-site, 20-page batch is an overnight job, not a coffee break.
    LighthouseScope {
        Sampled => "sampled",
        EveryPage => "every_page",
    }
}

impl LighthouseScope {
    /// The words a report or the composer prints for this scope.
    pub fn label(self) -> &'static str {
        match self {
            LighthouseScope::Sampled => "One page per template",
            LighthouseScope::EveryPage => "Every discovered page",
        }
    }
}

string_enum! {
    Severity {
        Critical => "critical",
        High => "high",
        Medium => "medium",
        Low => "low",
        Info => "info",
    }
}

impl Severity {
    /// Sort key: critical first. The order every findings list uses.
    pub fn order(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

string_enum! {
    RunStatus {
        Pending => "pending",
        Running => "running",
        Completed => "completed",
        Failed => "failed",
        Cancelled => "cancelled",
    }
}

impl RunStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            RunStatus::Completed | RunStatus::Failed | RunStatus::Cancelled
        )
    }
}

string_enum! {
    /// Whether a metric describes one page or the whole origin. Scope is
    /// what stops the report reprinting "certificate expires in 40 days"
    /// once per page, and what stops an origin-scoped collector running
    /// twenty times against the same host.
    Scope {
        Page => "page",
        Origin => "origin",
    }
}

// ---------------------------------------------------------------------------
// Values. Observation values arrive as dynamic, untyped data; this enum
// names the three shapes they actually take.
// ---------------------------------------------------------------------------

/// One observation value as the engine and templates consume it.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Num(f64),
    Text(String),
    Bool(bool),
}

impl Value {
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Text(t) => t.trim().parse().ok(),
        }
    }

    /// Truthiness, because rule operators like `is: true` lean on it.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Num(n) => *n != 0.0,
            Value::Bool(b) => *b,
            Value::Text(t) => !t.is_empty(),
        }
    }

    /// Plain-text form of a value, for the substring operators. Integral
    /// floats keep their ".0" and bools are capitalised, so `contains`
    /// matches the same text it always has.
    pub fn to_plain_string(&self) -> String {
        match self {
            Value::Text(t) => t.clone(),
            Value::Bool(b) => (if *b { "True" } else { "False" }).to_string(),
            Value::Num(n) => {
                if n.fract() == 0.0 && n.is_finite() {
                    format!("{n:.1}")
                } else {
                    format!("{n}")
                }
            }
        }
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::Num(n)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<&str> for Value {
    fn from(t: &str) -> Self {
        Value::Text(t.to_string())
    }
}
impl From<String> for Value {
    fn from(t: String) -> Self {
        Value::Text(t)
    }
}

// ---------------------------------------------------------------------------
// The metric registry
// ---------------------------------------------------------------------------

/// Registry entry describing one metric key.
#[derive(Clone, Debug)]
pub struct Metric {
    pub key: &'static str,
    pub unit: Unit,
    pub source: Source,
    pub label: &'static str,
    pub higher_is_better: Option<bool>,
    pub scope: Scope,
}

struct M(
    &'static str,
    Unit,
    Source,
    &'static str,
    Option<bool>,
    Scope,
);

fn m(key: &'static str, unit: Unit, source: Source, label: &'static str) -> M {
    M(key, unit, source, label, None, Scope::Page)
}
fn mh(key: &'static str, unit: Unit, source: Source, label: &'static str, hib: bool) -> M {
    M(key, unit, source, label, Some(hib), Scope::Page)
}
fn mo(key: &'static str, unit: Unit, source: Source, label: &'static str) -> M {
    M(key, unit, source, label, None, Scope::Origin)
}
fn moh(key: &'static str, unit: Unit, source: Source, label: &'static str, hib: bool) -> M {
    M(key, unit, source, label, Some(hib), Scope::Origin)
}

/// audit id -> (metric key suffix, human label).
///
/// Lighthouse 13 replaced the classic opportunity audits with "insights"
/// and a new savings API; the old IDs the industry still quotes are GONE
/// (`render-blocking-resources` -> `render-blocking-insight` and so on).
/// Writing rules against the old IDs produces rules that never fire and an
/// audit that silently finds nothing. Ported verbatim.
pub const LIGHTHOUSE_OPPORTUNITIES: &[(&str, &str, &str)] = &[
    (
        "render-blocking-insight",
        "render_blocking",
        "Render-blocking requests",
    ),
    ("cache-insight", "cache", "Inefficient cache lifetimes"),
    ("image-delivery-insight", "image_delivery", "Image delivery"),
    (
        "document-latency-insight",
        "document_latency",
        "Document request latency",
    ),
    (
        "lcp-discovery-insight",
        "lcp_discovery",
        "LCP image discovery",
    ),
    (
        "legacy-javascript-insight",
        "legacy_javascript",
        "Legacy JavaScript",
    ),
    (
        "duplicated-javascript-insight",
        "duplicated_javascript",
        "Duplicated JavaScript",
    ),
    ("font-display-insight", "font_display", "Font display"),
    (
        "network-dependency-tree-insight",
        "network_dependency",
        "Network dependency chain",
    ),
    ("forced-reflow-insight", "forced_reflow", "Forced reflow"),
    ("modern-http-insight", "modern_http", "Modern HTTP usage"),
    ("third-parties-insight", "third_parties", "Third-party code"),
    ("dom-size-insight", "dom_size", "DOM size"),
    (
        "cls-culprits-insight",
        "cls_culprits",
        "Layout shift causes",
    ),
    ("viewport-insight", "viewport", "Mobile viewport"),
    ("unminified-css", "unminified_css", "Unminified CSS"),
    (
        "unminified-javascript",
        "unminified_js",
        "Unminified JavaScript",
    ),
    ("unused-css-rules", "unused_css", "Unused CSS"),
    ("unused-javascript", "unused_js", "Unused JavaScript"),
];

/// Security headers the report expects to see, in the order it lists them.
pub const EXPECTED_SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
];

/// Core Web Vitals "good" thresholds, per web.dev.
pub const CWV_GOOD_THRESHOLDS: &[(&str, f64)] = &[
    ("crux.lcp.p75", 2500.0),
    ("crux.inp.p75", 200.0),
    ("crux.cls.p75", 0.1),
];

fn base_entries() -> Vec<M> {
    use Source::*;
    use Unit::*;
    vec![
        // --- HTTP response ------------------------------------------------
        m("http.status", Count, Http, "Final HTTP status"),
        m("http.version", None, Http, "HTTP protocol version"),
        mh("http.ttfb", Ms, Http, "Time to first byte", false),
        mh(
            "http.content_bytes",
            Bytes,
            Http,
            "HTML document size",
            false,
        ),
        m("http.compression", None, Http, "Content-Encoding"),
        mh(
            "http.compressed",
            Bool,
            Http,
            "Response is compressed",
            true,
        ),
        m("http.cache_control", None, Http, "Cache-Control header"),
        mh("http.cache_max_age", Seconds, Http, "Cache max-age", true),
        mh("http.has_etag", Bool, Http, "ETag present", true),
        m("http.server", None, Http, "Server header"),
        // --- Security headers ---------------------------------------------
        m("sec.hsts", None, Http, "Strict-Transport-Security"),
        mh("sec.hsts_max_age", Seconds, Http, "HSTS max-age", true),
        m("sec.csp", None, Http, "Content-Security-Policy"),
        m(
            "sec.x_content_type_options",
            None,
            Http,
            "X-Content-Type-Options",
        ),
        m("sec.x_frame_options", None, Http, "X-Frame-Options"),
        m("sec.referrer_policy", None, Http, "Referrer-Policy"),
        m("sec.permissions_policy", None, Http, "Permissions-Policy"),
        mh(
            "sec.missing_header_count",
            Count,
            Http,
            "Missing security headers",
            false,
        ),
        m("sec.cookies_total", Count, Http, "Cookies set on response"),
        mh(
            "sec.cookies_insecure",
            Count,
            Http,
            "Cookies missing Secure",
            false,
        ),
        mh(
            "sec.cookies_no_httponly",
            Count,
            Http,
            "Cookies missing HttpOnly",
            false,
        ),
        mh(
            "sec.cookies_no_samesite",
            Count,
            Http,
            "Cookies missing SameSite",
            false,
        ),
        // --- Redirects -----------------------------------------------------
        mh("redirect.hops", Count, Redirect, "Redirect hops", false),
        m("redirect.chain", None, Redirect, "Redirect chain"),
        mh(
            "redirect.upgrades_to_https",
            Bool,
            Redirect,
            "HTTP upgrades to HTTPS",
            true,
        ),
        m(
            "redirect.final_url",
            None,
            Redirect,
            "Final URL after redirects",
        ),
        // Set only when the HTTPS endpoint refused the connection and the audit
        // fell back to plain HTTP. Origin-scoped: it is a fact about the host,
        // not a page. `https.error` carries the transport error for the report.
        moh(
            "https.unreachable",
            Bool,
            Redirect,
            "HTTPS endpoint unreachable",
            false,
        ),
        mo("https.error", None, Redirect, "HTTPS connection error"),
        // --- TLS ------------------------------------------------------------
        // Origin-scoped: one certificate serves every page on the host.
        mo("tls.protocol", None, Tls, "Negotiated TLS version"),
        mo("tls.cipher", None, Tls, "Negotiated cipher"),
        mo("tls.issuer", None, Tls, "Certificate issuer"),
        mo("tls.subject", None, Tls, "Certificate subject"),
        moh(
            "tls.days_to_expiry",
            Days,
            Tls,
            "Days until certificate expiry",
            true,
        ),
        moh("tls.valid", Bool, Tls, "Certificate chain validates", true),
        mo("tls.error", None, Tls, "TLS handshake error"),
        // --- Tech fingerprint -----------------------------------------------
        m("tech.cms", None, Fingerprint, "Detected CMS"),
        m("tech.generator", None, Fingerprint, "Generator meta tag"),
        m("tech.cdn", None, Fingerprint, "Detected CDN"),
        m(
            "tech.page_builder",
            None,
            Fingerprint,
            "Detected page builder",
        ),
        m(
            "tech.cache_plugin",
            None,
            Fingerprint,
            "Detected caching layers",
        ),
        m("wprocket.present", Bool, Fingerprint, "WP Rocket installed"),
        m("wprocket.version", None, Fingerprint, "WP Rocket version"),
        m(
            "wprocket.features",
            None,
            Fingerprint,
            "WP Rocket enabled features",
        ),
        mh(
            "wprocket.page_cached",
            Bool,
            Fingerprint,
            "Page served from WP Rocket cache",
            true,
        ),
        m(
            "wprocket.cached_at",
            None,
            Fingerprint,
            "WP Rocket cache timestamp",
        ),
        // --- CrUX field data -------------------------------------------------
        // Origin-scoped as collected: the collector queries the origin, so
        // every page of a site would receive an identical answer.
        moh("crux.available", Bool, Crux, "CrUX record exists", true),
        moh("crux.lcp.p75", Ms, Crux, "LCP (field, 75th pct)", false),
        moh("crux.inp.p75", Ms, Crux, "INP (field, 75th pct)", false),
        // CLS is a unitless score, NOT a ratio. Declaring it RATIO makes
        // every formatter render 0.06 as "6%", which is wrong.
        moh("crux.cls.p75", Score, Crux, "CLS (field, 75th pct)", false),
        moh("crux.ttfb.p75", Ms, Crux, "TTFB (field, 75th pct)", false),
        moh(
            "crux.lcp.good",
            Ratio,
            Crux,
            "Share of LCP visits rated good",
            true,
        ),
        moh(
            "crux.inp.good",
            Ratio,
            Crux,
            "Share of INP visits rated good",
            true,
        ),
        moh(
            "crux.cls.good",
            Ratio,
            Crux,
            "Share of CLS visits rated good",
            true,
        ),
        moh("crux.cwv_pass", Bool, Crux, "Passes Core Web Vitals", true),
        // --- CrUX history: 25 weekly periods --------------------------------
        moh(
            "crux.history.available",
            Bool,
            CruxHistory,
            "Field-data history exists",
            true,
        ),
        mo(
            "crux.history.weeks",
            Count,
            CruxHistory,
            "Weekly periods available",
        ),
        moh(
            "crux.history.lcp.delta",
            Ms,
            CruxHistory,
            "LCP change across the period",
            false,
        ),
        moh(
            "crux.history.inp.delta",
            Ms,
            CruxHistory,
            "INP change across the period",
            false,
        ),
        moh(
            "crux.history.cls.delta",
            Score,
            CruxHistory,
            "CLS change across the period",
            false,
        ),
        moh(
            "crux.history.lcp.first",
            Ms,
            CruxHistory,
            "LCP at the start of the period",
            false,
        ),
        moh(
            "crux.history.inp.first",
            Ms,
            CruxHistory,
            "INP at the start of the period",
            false,
        ),
        moh(
            "crux.history.cls.first",
            Score,
            CruxHistory,
            "CLS at the start of the period",
            false,
        ),
        // Crossed a Core Web Vitals threshold the wrong way. Not a raw
        // delta: 1.2s -> 2.4s doubled and still passes; 2.4s -> 2.6s barely
        // moved and now fails, and only the second is worth telling a
        // client about.
        moh(
            "crux.history.regressed",
            Bool,
            CruxHistory,
            "A vital crossed from good to failing",
            false,
        ),
        mo(
            "crux.history.regressed_metrics",
            None,
            CruxHistory,
            "Which vitals regressed",
        ),
        moh(
            "crux.history.improved",
            Bool,
            CruxHistory,
            "A vital crossed from failing to good",
            true,
        ),
        mo(
            "crux.history.improved_metrics",
            None,
            CruxHistory,
            "Which vitals improved",
        ),
        mo(
            "crux.history.first_period",
            None,
            CruxHistory,
            "Earliest period covered",
        ),
        mo(
            "crux.history.last_period",
            None,
            CruxHistory,
            "Latest period covered",
        ),
        // --- Lighthouse: category scores (0-100) --------------------------
        mh(
            "lh.score.performance",
            Score,
            Lighthouse,
            "Performance score",
            true,
        ),
        mh(
            "lh.score.accessibility",
            Score,
            Lighthouse,
            "Accessibility score",
            true,
        ),
        mh(
            "lh.score.best_practices",
            Score,
            Lighthouse,
            "Best Practices score",
            true,
        ),
        mh("lh.score.seo", Score, Lighthouse, "SEO score", true),
        // --- Lighthouse: lab metrics (median across runs) ------------------
        mh("lh.lcp", Ms, Lighthouse, "LCP (lab)", false),
        mh(
            "lh.fcp",
            Ms,
            Lighthouse,
            "First Contentful Paint (lab)",
            false,
        ),
        mh("lh.tbt", Ms, Lighthouse, "Total Blocking Time (lab)", false),
        mh("lh.cls", Score, Lighthouse, "CLS (lab)", false),
        mh("lh.speed_index", Ms, Lighthouse, "Speed Index (lab)", false),
        mh("lh.tti", Ms, Lighthouse, "Time to Interactive (lab)", false),
        mh(
            "lh.server_response",
            Ms,
            Lighthouse,
            "Server response time (lab)",
            false,
        ),
        mh(
            "lh.total_bytes",
            Bytes,
            Lighthouse,
            "Total page weight",
            false,
        ),
        mh(
            "lh.bootup_time",
            Ms,
            Lighthouse,
            "JavaScript execution time",
            false,
        ),
        mh(
            "lh.mainthread_work",
            Ms,
            Lighthouse,
            "Main-thread work",
            false,
        ),
        mh(
            "lh.dom_elements",
            Count,
            Lighthouse,
            "DOM element count",
            false,
        ),
        // --- Lighthouse: run reproducibility ------------------------------
        // Contended CPU produces plausible, irreproducible numbers. These
        // are the observations that let the report say so.
        m("lh.runs", Count, Lighthouse, "Lighthouse runs taken"),
        mh(
            "lh.lcp.spread",
            Ms,
            Lighthouse,
            "LCP spread across runs",
            false,
        ),
        mh(
            "lh.tbt.spread",
            Ms,
            Lighthouse,
            "TBT spread across runs",
            false,
        ),
        mh(
            "lh.score.performance.spread",
            Score,
            Lighthouse,
            "Performance score spread across runs",
            false,
        ),
        mh(
            "lh.benchmark_index",
            Score,
            Lighthouse,
            "CPU benchmark of the measuring machine",
            true,
        ),
        mh(
            "lh.benchmark_index.spread",
            Score,
            Lighthouse,
            "CPU benchmark spread across runs",
            false,
        ),
        m(
            "lh.throttling_profile",
            None,
            Lighthouse,
            "Throttling profile",
        ),
        m("lh.form_factor", None, Lighthouse, "Form factor measured"),
        // --- Lighthouse: run-level coverage and machine stability ----------
        // Written once, on the home page, when a run is finalised. Origin-
        // scoped because they describe the whole run rather than any page:
        // which pages were measured, and whether the measuring machine held
        // the same speed from the first page to the last. Over a multi-hour
        // every-page batch it often does not (thermal drift, a laptop that
        // went onto battery), and per-page figures taken hours apart are only
        // comparable if it did.
        mo("lh.run.scope", None, Lighthouse, "Lighthouse coverage"),
        mo(
            "lh.run.pages_planned",
            Count,
            Lighthouse,
            "Pages queued for Lighthouse",
        ),
        mo(
            "lh.run.pages_measured",
            Count,
            Lighthouse,
            "Pages measured by Lighthouse",
        ),
        moh(
            "lh.run.pages_failed",
            Count,
            Lighthouse,
            "Pages Lighthouse could not measure",
            false,
        ),
        moh(
            "lh.run.benchmark_min",
            Score,
            Lighthouse,
            "Slowest CPU benchmark in the run",
            true,
        ),
        moh(
            "lh.run.benchmark_max",
            Score,
            Lighthouse,
            "Fastest CPU benchmark in the run",
            true,
        ),
        moh(
            "lh.run.benchmark_drift",
            Ratio,
            Lighthouse,
            "CPU benchmark drift across the run",
            false,
        ),
        // --- Mixed content and third-party subresources --------------------
        mh(
            "mixed.insecure_count",
            Count,
            Http,
            "Insecure subresources on an HTTPS page",
            false,
        ),
        m(
            "mixed.insecure_urls",
            None,
            Http,
            "Insecure subresource URLs",
        ),
        // "How the answer was reached" is an observation in its own right.
        m(
            "mixed.method",
            None,
            Http,
            "How subresources were inspected",
        ),
        mh(
            "mixed.insecure_forms",
            Count,
            Http,
            "Forms submitting over plain HTTP",
            false,
        ),
        m(
            "mixed.insecure_form_urls",
            None,
            Http,
            "Insecure form actions",
        ),
        mh(
            "thirdparty.origin_count",
            Count,
            Http,
            "Distinct third-party origins",
            false,
        ),
        m("thirdparty.origins", None, Http, "Third-party origins"),
        // --- Page inventory -------------------------------------------------
        m("page.role", None, Http, "Role of this page in the audit"),
        m("page.template_class", None, Http, "Detected page template"),
        m("page.discovered_via", None, Http, "How this page was found"),
        m("page.audit_depth", None, Http, "Depth of audit attempted"),
        // --- Discovery, origin-scoped ---------------------------------------
        mo("discovery.method", None, Http, "How pages were discovered"),
        mo("discovery.found", Count, Http, "Pages discovered"),
        mo("discovery.audited", Count, Http, "Pages audited"),
        // A cap that is applied and not stated reads as full coverage.
        moh(
            "discovery.dropped",
            Count,
            Http,
            "Pages discovered but not audited (cap)",
            false,
        ),
        mo("discovery.sitemap_urls", None, Http, "Sitemaps read"),
        // --- Software components --------------------------------------------
        m("component.count", Count, Fingerprint, "Components detected"),
        m(
            "component.observed_count",
            Count,
            Fingerprint,
            "Components with a browser-observed version",
        ),
        m(
            "component.inferred_count",
            Count,
            Fingerprint,
            "Components with an inferred version",
        ),
        m(
            "component.detected",
            None,
            Fingerprint,
            "Detected components",
        ),
        // --- Known vulnerabilities -------------------------------------------
        // `confirmed` means the VERSION was observed by a browser, not that
        // the vulnerability was exploited.
        mh(
            "vuln.confirmed_count",
            Count,
            Fingerprint,
            "Known vulnerabilities in observed versions",
            false,
        ),
        mh(
            "vuln.confirmed_critical",
            Count,
            Fingerprint,
            "Critical vulnerabilities",
            false,
        ),
        mh(
            "vuln.confirmed_high",
            Count,
            Fingerprint,
            "High-severity vulnerabilities",
            false,
        ),
        mh(
            "vuln.confirmed_medium",
            Count,
            Fingerprint,
            "Medium-severity vulnerabilities",
            false,
        ),
        m(
            "vuln.confirmed_detail",
            None,
            Fingerprint,
            "Vulnerabilities in observed versions",
        ),
        m(
            "vuln.confirmed_ids",
            None,
            Fingerprint,
            "Vulnerability identifiers",
        ),
        m(
            "vuln.possible_ids",
            None,
            Fingerprint,
            "Possible vulnerability identifiers",
        ),
        mh(
            "vuln.possible_count",
            Count,
            Fingerprint,
            "Possible vulnerabilities in inferred versions",
            false,
        ),
        m(
            "vuln.possible_detail",
            None,
            Fingerprint,
            "Possible vulnerabilities",
        ),
        mh(
            "vuln.unchecked_count",
            Count,
            Fingerprint,
            "Components not checked against any database",
            false,
        ),
        m(
            "vuln.unchecked_detail",
            None,
            Fingerprint,
            "Ecosystems with no vulnerability source",
        ),
        mo(
            "vuln.db_generated",
            None,
            Fingerprint,
            "Vulnerability database date",
        ),
        moh(
            "vuln.db_age_days",
            Days,
            Fingerprint,
            "Vulnerability database age",
            false,
        ),
        mo(
            "vuln.db_sources",
            None,
            Fingerprint,
            "Vulnerability sources configured",
        ),
        // --- Exposed endpoints -----------------------------------------------
        mo(
            "exposure.authorised",
            Bool,
            Http,
            "Endpoint probing authorised for this site",
        ),
        mo("exposure.checked", Count, Http, "Paths probed"),
        moh(
            "exposure.found_count",
            Count,
            Http,
            "Paths that should not be reachable",
            false,
        ),
        moh(
            "exposure.secrets_count",
            Count,
            Http,
            "Exposed secrets or database dumps",
            false,
        ),
        moh(
            "exposure.vcs_count",
            Count,
            Http,
            "Exposed version-control metadata",
            false,
        ),
        moh(
            "exposure.info_count",
            Count,
            Http,
            "Exposed diagnostic endpoints",
            false,
        ),
        moh(
            "exposure.wp_surface_count",
            Count,
            Http,
            "Exposed WordPress attack surface",
            false,
        ),
        mo("exposure.paths", None, Http, "Reachable paths"),
        mo(
            "exposure.secrets_paths",
            None,
            Http,
            "Reachable credential files",
        ),
        mo(
            "exposure.vcs_paths",
            None,
            Http,
            "Reachable version-control paths",
        ),
        mo(
            "exposure.info_paths",
            None,
            Http,
            "Reachable diagnostic endpoints",
        ),
        mo(
            "exposure.wp_surface_paths",
            None,
            Http,
            "Reachable WordPress endpoints",
        ),
        mo(
            "exposure.control_status",
            Count,
            Http,
            "Status for a path that cannot exist",
        ),
        moh(
            "exposure.soft_404",
            Bool,
            Http,
            "Site returns success for missing paths",
            false,
        ),
        mo(
            "exposure.waf_detected",
            Bool,
            Http,
            "A firewall answered instead of the server",
        ),
    ]
}

/// The authoritative list of metric keys. Collectors validate against this.
pub fn metric_registry() -> &'static HashMap<&'static str, Metric> {
    static REGISTRY: OnceLock<HashMap<&'static str, Metric>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = HashMap::new();
        for M(key, unit, source, label, hib, scope) in base_entries() {
            registry.insert(
                key,
                Metric {
                    key,
                    unit,
                    source,
                    label,
                    higher_is_better: hib,
                    scope,
                },
            );
        }
        // The lh.opp.* family, appended after the static entries.
        // The labels leak, once, at first use: 19 short strings for the
        // life of the process, in exchange for a registry of &'static str
        // that every call site can borrow from freely.
        for (_audit_id, suffix, label) in LIGHTHOUSE_OPPORTUNITIES {
            let key: &'static str = Box::leak(format!("lh.opp.{suffix}").into_boxed_str());
            let text: &'static str =
                Box::leak(format!("{label}: estimated saving").into_boxed_str());
            registry.insert(
                key,
                Metric {
                    key,
                    unit: Unit::Ms,
                    source: Source::Lighthouse,
                    label: text,
                    higher_is_better: Some(false),
                    scope: Scope::Page,
                },
            );
        }
        registry
    })
}

/// Metric keys that describe the origin rather than an individual page.
pub fn origin_scoped_keys() -> Vec<&'static str> {
    metric_registry()
        .values()
        .filter(|metric| metric.scope == Scope::Origin)
        .map(|metric| metric.key)
        .collect()
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// `1 hour`, not `1 hours`. Rounds first so 1.4 reads as singular.
fn plural(number: f64, noun: &str) -> String {
    let rounded = number.round();
    if rounded.abs() == 1.0 {
        format!("{rounded:.0} {noun}")
    } else {
        format!("{rounded:.0} {noun}s")
    }
}

/// `%g`-ish default: integers drop the decimal point, everything
/// else prints shortest-roundtrip. Scores and CLS values are the traffic
/// here (95, 0.06), where the two formats agree exactly.
fn general(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e15 {
        format!("{}", number as i64)
    } else {
        format!("{number}")
    }
}

/// Render a value for human eyes, using the registry's declared unit.
///
/// Lives in the schema rather than the report layer because the findings
/// engine substitutes metric values into rule text: a rule author writes
/// `{http.content_bytes}` and must get "402 KB", not "412000". Rule text
/// therefore must NOT append its own unit after a placeholder.
pub fn format_value(metric_key: &str, value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "n/a".to_string();
    };
    let unit = metric_registry()
        .get(metric_key)
        .map(|metric| metric.unit)
        .unwrap_or(Unit::None);

    if unit == Unit::Bool {
        return (if value.truthy() { "Yes" } else { "No" }).to_string();
    }
    let number = match value {
        Value::Num(n) => *n,
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Text(t) => match t.trim().parse::<f64>() {
            Ok(n) => n,
            Err(_) => return t.clone(),
        },
    };

    match unit {
        Unit::Ms => {
            if number >= 1000.0 {
                format!("{:.1}s", number / 1000.0)
            } else {
                format!("{}ms", number.round() as i64)
            }
        }
        Unit::Bytes => {
            if number >= 1_048_576.0 {
                format!("{:.1} MB", number / 1_048_576.0)
            } else if number >= 1024.0 {
                format!("{:.0} KB", number / 1024.0)
            } else {
                format!("{number:.0} bytes")
            }
        }
        Unit::Seconds => {
            for (divisor, noun) in [(86400.0, "day"), (3600.0, "hour"), (60.0, "minute")] {
                if number >= divisor {
                    return plural(number / divisor, noun);
                }
            }
            plural(number, "second")
        }
        Unit::Days => plural(number, "day"),
        Unit::Ratio => format!("{:.0}%", number * 100.0),
        _ => general(number),
    }
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct UnknownMetricError(pub String);

impl fmt::Display for UnknownMetricError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{:?} is not in the metric registry. Register it in slap_core::schema \
             before emitting it.",
            self.0
        )
    }
}

impl std::error::Error for UnknownMetricError {}

/// One immutable fact about one page, from one source.
#[derive(Clone, Debug)]
pub struct Observation {
    pub source: Source,
    pub metric_key: &'static str,
    pub numeric_value: Option<f64>,
    pub text_value: Option<String>,
    pub unit: Unit,
}

impl Observation {
    pub fn label(&self) -> &'static str {
        metric_registry()[self.metric_key].label
    }

    pub fn value(&self) -> Value {
        match (self.numeric_value, &self.text_value) {
            (Some(n), _) if self.unit == Unit::Bool => Value::Bool(n != 0.0),
            (Some(n), _) => Value::Num(n),
            (_, Some(t)) => Value::Text(t.clone()),
            _ => unreachable!("an observation always carries a value"),
        }
    }
}

/// Build an Observation, inferring numeric vs text and the unit.
///
/// This is the constructor collectors use. It exists so a collector never
/// has to remember which column a value belongs in.
pub fn obs(metric_key: &str, value: Value) -> Result<Observation, UnknownMetricError> {
    let metric = metric_registry()
        .get(metric_key)
        .ok_or_else(|| UnknownMetricError(metric_key.to_string()))?;
    Ok(match value {
        Value::Bool(b) => Observation {
            source: metric.source,
            metric_key: metric.key,
            numeric_value: Some(if b { 1.0 } else { 0.0 }),
            text_value: None,
            unit: Unit::Bool,
        },
        Value::Num(n) => Observation {
            source: metric.source,
            metric_key: metric.key,
            numeric_value: Some(n),
            text_value: None,
            unit: metric.unit,
        },
        Value::Text(t) => Observation {
            source: metric.source,
            metric_key: metric.key,
            numeric_value: None,
            text_value: Some(t),
            unit: metric.unit,
        },
    })
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// A rule firing against a page's observations.
#[derive(Clone, Debug)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: serde_json::Map<String, serde_json::Value>,
    pub impact_ms: Option<f64>,
    pub effort: Option<String>,
    pub remediation: Option<String>,
    pub wp_rocket_setting: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_matches_the_known_registry_size() {
        // 138 entries carried forward unchanged, plus 2 desktop-era
        // additions (https.unreachable, https.error, for the http-fallback
        // finding), plus the 19 lh.opp.* family. A drift here means a metric was
        // added without updating this count; keep it deliberate so an accidental
        // key is caught.
        // 138 base + 2 + 19 opportunities + 7 run-level Lighthouse entries.
        assert_eq!(metric_registry().len(), 138 + 2 + 19 + 7);
    }

    #[test]
    fn every_lighthouse_opportunity_registered() {
        for (_id, suffix, _label) in LIGHTHOUSE_OPPORTUNITIES {
            let key = format!("lh.opp.{suffix}");
            let metric = metric_registry()
                .get(key.as_str())
                .unwrap_or_else(|| panic!("{key} missing"));
            assert_eq!(metric.unit, Unit::Ms);
            assert_eq!(metric.higher_is_better, Some(false));
        }
    }

    #[test]
    fn cls_is_a_score_not_a_ratio() {
        // The bug the first report render caught: CLS declared RATIO made
        // 0.06 print as "6%".
        assert_eq!(metric_registry()["crux.cls.p75"].unit, Unit::Score);
        assert_eq!(
            format_value("crux.cls.p75", Some(&Value::Num(0.06))),
            "0.06"
        );
    }

    #[test]
    fn milliseconds_flip_to_seconds_at_a_thousand() {
        assert_eq!(format_value("http.ttfb", Some(&Value::Num(412.0))), "412ms");
        assert_eq!(format_value("http.ttfb", Some(&Value::Num(1340.0))), "1.3s");
    }

    #[test]
    fn byte_counts_are_humanised() {
        assert_eq!(
            format_value("http.content_bytes", Some(&Value::Num(412_000.0))),
            "402 KB"
        );
        assert_eq!(
            format_value("http.content_bytes", Some(&Value::Num(3_200_000.0))),
            "3.1 MB"
        );
        assert_eq!(
            format_value("http.content_bytes", Some(&Value::Num(512.0))),
            "512 bytes"
        );
    }

    #[test]
    fn seconds_pick_the_largest_sensible_unit_and_pluralise() {
        assert_eq!(
            format_value("http.cache_max_age", Some(&Value::Num(31536000.0))),
            "365 days"
        );
        assert_eq!(
            format_value("http.cache_max_age", Some(&Value::Num(3600.0))),
            "1 hour"
        );
        assert_eq!(
            format_value("http.cache_max_age", Some(&Value::Num(90.0))),
            "2 minutes"
        );
    }

    #[test]
    fn ratios_render_as_percentages_and_bools_as_words() {
        assert_eq!(
            format_value("crux.lcp.good", Some(&Value::Num(0.38))),
            "38%"
        );
        assert_eq!(
            format_value("crux.cwv_pass", Some(&Value::Bool(true))),
            "Yes"
        );
        assert_eq!(format_value("http.ttfb", None), "n/a");
    }

    #[test]
    fn an_unregistered_key_is_refused_at_collection_time() {
        assert!(obs("made.up.key", Value::Num(1.0)).is_err());
    }

    #[test]
    fn the_constructor_routes_values_to_the_right_column() {
        let numeric = obs("http.ttfb", Value::Num(200.0)).unwrap();
        assert_eq!(numeric.numeric_value, Some(200.0));
        assert_eq!(numeric.unit, Unit::Ms);

        let text = obs("http.server", Value::from("nginx")).unwrap();
        assert_eq!(text.text_value.as_deref(), Some("nginx"));
        assert_eq!(text.numeric_value, None);

        let flag = obs("http.compressed", Value::Bool(true)).unwrap();
        assert_eq!(flag.numeric_value, Some(1.0));
        assert_eq!(flag.unit, Unit::Bool);
        assert_eq!(flag.value(), Value::Bool(true));
    }

    #[test]
    fn enum_strings_round_trip_the_database_spellings() {
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
        assert_eq!(RunStatus::Completed.as_str(), "completed");
        assert!(RunStatus::Completed.is_terminal());
        assert!(!RunStatus::Running.is_terminal());
        assert_eq!(Source::CruxHistory.as_str(), "crux_history");
        assert_eq!(Unit::Seconds.as_str(), "s");
        assert_eq!(
            LighthouseScope::parse("every_page"),
            Some(LighthouseScope::EveryPage)
        );
        assert_eq!(LighthouseScope::Sampled.as_str(), "sampled");
    }

    #[test]
    fn run_level_lighthouse_metrics_are_origin_scoped() {
        // They are written once per run on the home page; a page-scoped
        // declaration would let them leak onto every page's findings.
        for key in [
            "lh.run.scope",
            "lh.run.pages_planned",
            "lh.run.pages_measured",
            "lh.run.pages_failed",
            "lh.run.benchmark_min",
            "lh.run.benchmark_max",
            "lh.run.benchmark_drift",
        ] {
            assert_eq!(metric_registry()[key].scope, Scope::Origin, "{key}");
        }
        assert_eq!(
            format_value("lh.run.benchmark_drift", Some(&Value::Num(0.31))),
            "31%"
        );
    }
}
