//! The client-facing report: a stored run rendered to standalone HTML, and
//! (through the shell) to PDF.
//!
//! It looks like the Lighthouse report a client may already know: category
//! gauges in Lighthouse's three bands, metric rows with Lighthouse's rating
//! shapes, and audit lists. Around that sits what SLAP adds: the verdict
//! first, findings grouped by rule across pages, a cross-page view of every
//! page tested, security and software.
//!
//! It is written for the site's owner, not for whoever ran the audit. The
//! metrics carry plain names with Lighthouse's short name beside them ("Main
//! content", LCP), Lighthouse's audits are retitled by audit id as the
//! problem they describe, savings read as seconds and KB, page templates read
//! as page types, and dates as dates. Technical names stay where the person
//! fixing something needs them, in brackets. Notes about the measurement
//! itself (a busy test machine, a check that could not run) are kept apart
//! from the list of things to fix.
//!
//! The model is assembled straight from the stored run (the observations,
//! findings and pages the app persists) plus the compact per-page Lighthouse
//! summary written beside the database when each page was measured. Every
//! stored value is formatted through `schema::format_value` or, for
//! Lighthouse's own metrics, Lighthouse's own display conventions, so a
//! number in the report is a number from the database. A finding's words
//! come from the current rule, filled in from the page's stored
//! observations, so a run audited before a rule was reworded reads in the
//! current wording; its rule, severity and pages are the run's own.
//!
//! A status never relies on colour alone: every gauge, metric and audit
//! carries Lighthouse's rating shape, and every finding badge and status cell
//! prints its word.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value as Json};
use slap_core::findings::{render_template, FindingsEngine, Rule};
use slap_core::rusqlite::Connection;
use slap_core::schema::{format_value, metric_registry, LighthouseScope, Unit, Value};
use slap_core::storage;

const REPORT_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/report/report.css"
));

const REPORT_TMPL: &str = include_str!("report.html.jinja");

/// Render a run to a standalone HTML document.
pub fn render_html(conn: &Connection, run_id: i64) -> Result<String, String> {
    let model = build_model(conn, run_id)?;
    let env = environment()?;
    let tmpl = env.get_template("report").map_err(|e| e.to_string())?;
    tmpl.render(minijinja::Value::from_serialize(&model))
        .map_err(|e| e.to_string())
}

/// The template environment. Everything the report prints is escaped as
/// HTML text: a Server header, a redirect chain or a component name is the
/// site's own text, and a `<title>` in one must print as those characters,
/// not end the document. The stylesheet is included as it is.
fn environment() -> Result<minijinja::Environment<'static>, String> {
    use minijinja::AutoEscape;
    let mut env = minijinja::Environment::new();
    env.set_auto_escape_callback(|name| {
        if name == "report" {
            AutoEscape::Html
        } else {
            AutoEscape::None
        }
    });
    env.set_formatter(html_text_formatter);
    env.add_template("report.css", REPORT_CSS)
        .map_err(|e| format!("report.css template: {e}"))?;
    env.add_template("report", REPORT_TMPL)
        .map_err(|e| format!("report template: {e}"))?;
    Ok(env)
}

/// minijinja's HTML escaping, except that `/` is left alone, so paths and
/// URLs stay paths and URLs in the source a client may open. `/` needs no
/// escaping in text or in a quoted attribute.
fn html_text_formatter(
    out: &mut minijinja::Output,
    state: &minijinja::State,
    value: &minijinja::Value,
) -> Result<(), minijinja::Error> {
    let Some(text) = value.as_str().filter(|_| {
        state.auto_escape() == minijinja::AutoEscape::Html && !value.is_safe()
    }) else {
        return minijinja::escape_formatter(out, state, value);
    };
    let mut last = 0;
    for (i, c) in text.char_indices() {
        let entity = match c {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#x27;",
            _ => continue,
        };
        out.write_str(&text[last..i])?;
        out.write_str(entity)?;
        last = i + c.len_utf8();
    }
    out.write_str(&text[last..])?;
    Ok(())
}

/// One observation's stored value.
struct Ob {
    num: Option<f64>,
    text: Option<String>,
}

impl Ob {
    fn value(&self) -> Value {
        match self.num {
            Some(n) => Value::Num(n),
            None => Value::from(self.text.clone().unwrap_or_default()),
        }
    }
}

fn str_of<'a>(v: &'a Json, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Json::as_str)
}
fn num_of(v: &Json, key: &str) -> Option<f64> {
    v.get(key).and_then(Json::as_f64)
}

/// A stored observation row as the value the findings engine saw, exactly as
/// `storage::observations_as_dict` reads it.
fn stored_value(o: &Json) -> Option<Value> {
    match (num_of(o, "numeric_value"), str_of(o, "text_value")) {
        (Some(n), _) if str_of(o, "unit") == Some(Unit::Bool.as_str()) => Some(Value::Bool(n != 0.0)),
        (Some(n), _) => Some(Value::Num(n)),
        (None, Some(t)) => Some(Value::Text(t.to_string())),
        (None, None) => None,
    }
}

/// A URL reduced to its path, for a report that lists many pages of one site.
fn short_path(url: &str) -> String {
    let after = url.split("://").nth(1).unwrap_or(url);
    match after.find('/') {
        Some(i) => {
            let p = &after[i..];
            if p == "/" {
                "/ (home)".to_string()
            } else {
                p.to_string()
            }
        }
        None => "/".to_string(),
    }
}

/// A page as a sentence names it: "the home page", or its path.
fn page_name(url: &str) -> String {
    match short_path(url).as_str() {
        "/ (home)" | "/" => "the home page".to_string(),
        path => path.to_string(),
    }
}

/// severity -> the report.css status class (high is "serious", medium "warning").
fn severity_class(sev: &str) -> &'static str {
    match sev {
        "critical" => "critical",
        "high" => "serious",
        "medium" => "warning",
        "low" => "muted",
        _ => "muted",
    }
}
fn severity_word(sev: &str) -> &'static str {
    match sev {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Info",
    }
}

/// Where a value sits against its two thresholds, as a 0-100 meter position
/// with the thresholds pinned at 33% and 66% so three tiles compare by eye.
fn meter_pct(value: f64, good: f64, poor: f64) -> f64 {
    let pct = if value <= good {
        (value / good.max(f64::EPSILON)) * 33.0
    } else if value <= poor {
        33.0 + (value - good) / (poor - good).max(f64::EPSILON) * 33.0
    } else {
        66.0 + ((value - poor) / poor.max(f64::EPSILON) * 34.0).min(34.0)
    };
    pct.clamp(0.0, 100.0)
}

fn cwv_status(value: f64, good: f64, poor: f64) -> (&'static str, &'static str) {
    if value <= good {
        ("good", "Good")
    } else if value <= poor {
        ("needs-improvement", "Needs work")
    } else {
        ("poor", "Poor")
    }
}

/// "2026-10-06T02:16:11+00:00" as "6 October 2026". The time is left out: it
/// is UTC, and the day is what a reader needs.
fn friendly_date(stamp: &str) -> String {
    const MONTHS: [&str; 12] = [
        "January", "February", "March", "April", "May", "June", "July", "August",
        "September", "October", "November", "December",
    ];
    let mut parts = stamp.get(..10).unwrap_or("").split('-');
    let year = parts.next().and_then(|y| y.parse::<i32>().ok());
    let month = parts.next().and_then(|m| m.parse::<usize>().ok());
    let day = parts.next().and_then(|d| d.parse::<u32>().ok());
    match (year, month, day) {
        (Some(y), Some(m @ 1..=12), Some(d)) => format!("{d} {} {y}", MONTHS[m - 1]),
        _ => stamp.replace('T', " "),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// A page template as the kind of page a client would call it.
fn page_kind(template: &str) -> String {
    let kind = match template {
        "home" => "Home page",
        "post" => "Blog post",
        "product" => "Product",
        "archive" => "Listing page",
        "search" => "Search results",
        "contact" => "Contact page",
        "about" => "About page",
        "legal" => "Legal page",
        "checkout" => "Checkout",
        "cart" => "Cart",
        "account" => "Account page",
        "page" => "Page",
        other => {
            return match other.strip_prefix("depth-").and_then(|d| d.parse::<u32>().ok()) {
                Some(1) => "Top-level page".into(),
                Some(2) => "Second-level page".into(),
                Some(3) => "Third-level page".into(),
                Some(n) => format!("Level {n} page"),
                None => {
                    let mut chars = other.chars();
                    match chars.next() {
                        Some(first) => first.to_uppercase().chain(chars).collect(),
                        None => "Page".into(),
                    }
                }
            };
        }
    };
    kind.to_string()
}

/// "Blog post" as it reads mid-sentence: "blog post".
fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Lighthouse's visual language: bands, gauges, metric display and ratings
// ---------------------------------------------------------------------------

/// The four categories, in Lighthouse's order: observation key, the id the
/// summary uses, the label Lighthouse prints, and what it measures, in a
/// sentence a client can read.
const LH_CATEGORIES: [(&str, &str, &str, &str); 4] = [
    (
        "lh.score.performance",
        "performance",
        "Performance",
        "How quickly the page loads and becomes usable.",
    ),
    (
        "lh.score.accessibility",
        "accessibility",
        "Accessibility",
        "How easily people with disabilities can use the page, including with a screen reader or keyboard.",
    ),
    (
        "lh.score.best_practices",
        "best-practices",
        "Best Practices",
        "The page's general technical health and security.",
    ),
    (
        "lh.score.seo",
        "seo",
        "SEO",
        "How easily search engines can read and list the page.",
    ),
];

fn category_label(id: &str) -> &'static str {
    LH_CATEGORIES.iter().find(|c| c.1 == id).map(|c| c.2).unwrap_or("")
}

/// Lighthouse's score bands on the 0-100 scale: 90+ pass, 50-89 average,
/// below 50 fail. The same bands colour every gauge, chip and distribution.
fn band(score: f64) -> &'static str {
    if score >= 90.0 {
        "pass"
    } else if score >= 50.0 {
        "average"
    } else {
        "fail"
    }
}

/// The circumference of a gauge's ring (r = 56 in a 120-unit box).
const GAUGE_RING: f64 = 351.858;

fn gauge(label: &str, score: Option<f64>) -> Json {
    match score {
        Some(v) => {
            let v = v.clamp(0.0, 100.0).round();
            json!({
                "label": label,
                "score": v as i64,
                "rating": band(v),
                "dash": format!("{:.2} {GAUGE_RING:.2}", v / 100.0 * GAUGE_RING),
                // Filled in for the home page when several pages were tested.
                "site_median": Json::Null,
            })
        }
        None => json!({
            "label": label, "score": Json::Null, "rating": "none", "dash": "0 351.86",
            "site_median": Json::Null,
        }),
    }
}

/// `(p10, median)` scoring control points for one metric.
type ControlPoints = (f64, f64);

/// One of the five scored metrics: its observation key, the plain name the
/// report uses, Lighthouse's own short name, one line on what it means, and
/// its scoring control points on mobile and on desktop. A value at or under
/// p10 scores 0.9 (pass) and at or under the median scores 0.5 (average), so
/// the two points ARE the rating bands, with no curve arithmetic needed.
/// Values from Lighthouse's metric audits.
struct LhMetric {
    key: &'static str,
    name: &'static str,
    abbr: &'static str,
    hint: &'static str,
    mobile: ControlPoints,
    desktop: ControlPoints,
}

static LH_METRICS: [LhMetric; 5] = [
    LhMetric {
        key: "lh.fcp",
        name: "First content",
        abbr: "FCP",
        hint: "When the first text or image appears",
        mobile: (1800.0, 3000.0),
        desktop: (934.0, 1600.0),
    },
    LhMetric {
        key: "lh.lcp",
        name: "Main content",
        abbr: "LCP",
        hint: "When the largest text or image appears",
        mobile: (2500.0, 4000.0),
        desktop: (1200.0, 2400.0),
    },
    LhMetric {
        key: "lh.tbt",
        name: "Unresponsive time",
        abbr: "TBT",
        hint: "How long the page is too busy to react to a tap or click",
        mobile: (200.0, 600.0),
        desktop: (150.0, 350.0),
    },
    LhMetric {
        key: "lh.cls",
        name: "Layout shift",
        abbr: "CLS",
        hint: "How much the content jumps around as it loads; 0 is best",
        mobile: (0.1, 0.25),
        desktop: (0.1, 0.25),
    },
    LhMetric {
        key: "lh.speed_index",
        name: "Page fills in",
        abbr: "Speed Index",
        hint: "How quickly the visible page fills in",
        mobile: (3387.0, 5800.0),
        desktop: (1311.0, 2300.0),
    },
];

fn metric_rating(value: f64, (p10, median): ControlPoints) -> &'static str {
    if value <= p10 {
        "pass"
    } else if value <= median {
        "average"
    } else {
        "fail"
    }
}

/// A metric as Lighthouse displays it: paint and speed metrics in seconds to
/// one decimal, blocking time in milliseconds, layout shift as a bare score
/// to three decimals with trailing zeros dropped.
fn lh_display(key: &str, value: f64) -> String {
    match key {
        "lh.tbt" => format!("{} ms", group_thousands(value.round() as i64)),
        "lh.cls" => {
            let text = format!("{value:.3}");
            let text = text.trim_end_matches('0').trim_end_matches('.');
            if text.is_empty() { "0".into() } else { text.to_string() }
        }
        _ => format!("{:.1} s", value / 1000.0),
    }
}

fn group_thousands(n: i64) -> String {
    let digits = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}

fn median_of(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let n = values.len();
    Some(if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    })
}

/// The metrics grid for one page, from its stored medians.
fn metrics_grid(values: &HashMap<String, f64>, desktop: bool) -> Vec<Json> {
    LH_METRICS
        .iter()
        .filter_map(|m| {
            let v = *values.get(m.key)?;
            let spread = match m.key {
                "lh.lcp" => values.get("lh.lcp.spread").copied(),
                "lh.tbt" => values.get("lh.tbt.spread").copied(),
                _ => None,
            }
            .filter(|s| *s > 0.0)
            .map(|s| format!("±{}", lh_display(m.key, s / 2.0)));
            Some(json!({
                "key": m.key,
                "name": m.name,
                "abbr": m.abbr,
                "hint": m.hint,
                "display": lh_display(m.key, v),
                "rating": metric_rating(v, if desktop { m.desktop } else { m.mobile }),
                "spread": spread,
            }))
        })
        .collect()
}

/// A Lighthouse audit, by id, as the problem a client would recognise when
/// it fails. Lighthouse's own titles are written for developers ("Network
/// dependency tree", "Document does not have a main landmark."); these say
/// what is wrong. Several audits that mean the same thing to a reader share a
/// title, and lists are de-duplicated by title. An audit not listed here
/// keeps Lighthouse's title.
fn plain_audit_title(id: &str) -> Option<&'static str> {
    Some(match id {
        // Performance: insights
        "cache-insight" => "Files are not cached for long",
        "cls-culprits-insight" | "layout-shifts" => "Content shifts around while the page loads",
        "document-latency-insight" => "The page itself is slow to arrive",
        "dom-size-insight" => "The page is built from too many elements",
        "duplicated-javascript-insight" => "The same script is loaded more than once",
        "font-display-insight" => "Text is hidden while fonts load",
        "forced-reflow-insight" => "Scripts make the browser redo the layout",
        "image-delivery-insight" => "Images are bigger than they need to be",
        "inp-breakdown-insight" => "Slow responses to taps and clicks",
        "lcp-breakdown-insight" => "What delays the main content",
        "lcp-discovery-insight" => "The main image is found late",
        "legacy-javascript-insight" => "Scripts include code for outdated browsers",
        "modern-http-insight" => "Files are not sent over a modern connection (HTTP/2)",
        "network-dependency-tree-insight" => "Files wait on each other before they load",
        "render-blocking-insight" => "Files hold back the page from appearing",
        "third-parties-insight" => "Third-party code slows the page",
        "viewport-insight" => "The page is not set up for mobile screens",
        // Performance: diagnostics
        "bf-cache" => "The back button cannot restore the page instantly",
        "bootup-time" => "Scripts take a long time to run",
        "mainthread-work-breakdown" => "The browser is kept busy for a long time",
        "long-tasks" => "Long tasks freeze the page",
        "unminified-css" => "Style files contain unneeded spacing (not minified)",
        "unminified-javascript" => "Script files contain unneeded spacing (not minified)",
        "unused-css-rules" => "Unused styles (CSS) are downloaded",
        "unused-javascript" => "Unused scripts (JavaScript) are downloaded",
        "total-byte-weight" => "The page is a very large download",
        "non-composited-animations" => "Some animations are not smooth",
        "unsized-images" => "Images have no set size, so the layout jumps",
        "server-response-time" => "The server is slow to respond",
        "redirects" => "Redirects delay the page",
        // Accessibility
        "accesskeys" => "Keyboard shortcuts are used more than once",
        "aria-allowed-attr" | "aria-allowed-role" | "aria-conditional-attr"
        | "aria-deprecated-role" | "aria-prohibited-attr" | "aria-required-attr"
        | "aria-required-children" | "aria-required-parent" | "aria-roles"
        | "aria-valid-attr" | "aria-valid-attr-value" => {
            "Screen-reader markup (ARIA) is used incorrectly"
        }
        "aria-command-name" | "aria-dialog-name" | "aria-input-field-name"
        | "aria-meter-name" | "aria-progressbar-name" | "aria-toggle-field-name"
        | "aria-tooltip-name" | "aria-treeitem-name" => {
            "Some controls have no name for screen readers"
        }
        "aria-hidden-body" => "The whole page is hidden from screen readers",
        "aria-hidden-focus" => "Hidden elements can still be reached with the keyboard",
        "aria-text" => "Some text is announced incorrectly by screen readers",
        "button-name" => "Some buttons have no name for screen readers",
        "bypass" => "There is no way to skip straight to the main content",
        "color-contrast" => "Some text is hard to read against its background",
        "definition-list" | "dlitem" | "list" | "listitem" => {
            "Some lists are not built correctly for screen readers"
        }
        "document-title" => "The page has no title",
        "duplicate-id-aria" => "Repeated labels confuse screen readers",
        "empty-heading" => "Some headings are empty",
        "form-field-multiple-labels" => "Some form fields have more than one label",
        "frame-title" => "Embedded frames have no title",
        "heading-order" => "Headings skip levels",
        "html-has-lang" => "The page does not say what language it is in",
        "html-lang-valid" | "html-xml-lang-mismatch" | "valid-lang" => {
            "The page's language setting is invalid"
        }
        "image-alt" => "Some images have no text description",
        "image-redundant-alt" => "Some image descriptions repeat the text beside them",
        "input-button-name" => "Some buttons have no readable text",
        "input-image-alt" => "Some image buttons have no text description",
        "label" => "Some form fields have no label",
        "label-content-name-mismatch" => "Some labels do not match what screen readers announce",
        "landmark-one-main" => "The main content is not marked for screen readers",
        "link-in-text-block" => "Some links stand out by colour alone",
        "link-name" => "Some links have no readable text",
        "meta-refresh" => "The page refreshes or redirects by itself",
        "meta-viewport" => "Zooming is blocked on mobile",
        "object-alt" => "Embedded objects have no text description",
        "select-name" => "Some drop-down menus have no label",
        "skip-link" => "Skip links do not work",
        "svg-img-alt" => "Some graphics have no text description",
        "tabindex" => "The keyboard order is forced out of sequence",
        "table-duplicate-name" | "table-fake-caption" | "td-has-header"
        | "td-headers-attr" | "th-has-data-cells" => {
            "Some tables are not built correctly for screen readers"
        }
        "target-size" => "Some buttons and links are too small or too close to tap",
        "video-caption" => "Videos have no captions",
        "presentation-role-conflict" => "Decorative elements are still announced by screen readers",
        "identical-links-same-purpose" => "Links with the same text go to different places",
        "autocomplete-valid" => "Form autofill settings are invalid",
        // Best practices
        "errors-in-console" => "The page causes errors in the browser",
        "deprecations" => "The page uses browser features that are being retired",
        "inspector-issues" => "The browser flagged problems with the page",
        "is-on-https" => "Some files load over an insecure connection",
        "redirects-http" => "http:// visits are not sent to https://",
        "geolocation-on-start" => "The page asks for the visitor's location straight away",
        "notification-on-start" => "The page asks to send notifications straight away",
        "paste-preventing-inputs" => "Pasting into some fields is blocked",
        "image-aspect-ratio" => "Some images are stretched or squashed",
        "image-size-responsive" => "Some images look blurry on sharp screens",
        "doctype" => "The page is missing its HTML doctype",
        "charset" => "The page does not declare its character set",
        "valid-source-maps" => "Large scripts have no source maps for debugging",
        "third-party-cookies" => "The page uses third-party cookies",
        "csp-xss" => "No strong policy limiting which scripts can run",
        "has-hsts" => "No strong always-use-a-secure-connection rule (HSTS)",
        "origin-isolation" => "The page is not isolated from pop-ups (COOP)",
        "clickjacking-mitigation" => "No protection against clickjacking",
        "trusted-types-xss" => "No protection against injected scripts (Trusted Types)",
        // SEO
        "meta-description" => "No description for search results",
        "http-status-code" => "The page returns an error code",
        "link-text" => "Some links have vague text, such as \"click here\"",
        "crawlable-anchors" => "Some links cannot be followed by search engines",
        "is-crawlable" => "Search engines are blocked from listing this page",
        "robots-txt" => "The robots.txt file has errors",
        "hreflang" => "Language versions of the page are not linked correctly",
        "canonical" => "The page's preferred address (canonical link) is invalid",
        _ => return None,
    })
}

/// An audit's title as the report prints it.
fn audit_title(a: &Json) -> String {
    let id = a["id"].as_str().unwrap_or("");
    match plain_audit_title(id) {
        Some(plain) => plain.to_string(),
        None => a["title"]
            .as_str()
            .unwrap_or(id)
            .trim_end_matches('.')
            .to_string(),
    }
}

/// Time as a client reads it, for savings of a tenth of a second or more.
fn approx_seconds(ms: f64) -> Option<String> {
    (ms >= 100.0).then(|| format!("{:.1} s", ms / 1000.0))
}

/// A byte count as a client reads it: decimal KB and MB.
fn approx_bytes(bytes: f64) -> String {
    if bytes >= 1_000_000.0 {
        format!("{:.1} MB", bytes / 1_000_000.0)
    } else {
        format!("{} KB", group_thousands((bytes / 1000.0).round().max(1.0) as i64))
    }
}

/// Bytes from a Lighthouse display string such as "Est savings of 767 KiB".
fn display_bytes(display: &str) -> Option<f64> {
    let mut words = display.split_whitespace().rev();
    let scale = match words.next()? {
        "KiB" => 1024.0,
        "MiB" => 1_048_576.0,
        _ => return None,
    };
    let number: f64 = words.next()?.replace(',', "").parse().ok()?;
    Some(number * scale).filter(|b| *b > 0.0)
}

/// What fixing an audit could save, from Lighthouse's own estimate: time
/// where it gives a meaningful amount, otherwise download size.
fn audit_saving(a: &Json) -> Option<String> {
    if let Some(time) = a["savings_ms"].as_f64().and_then(approx_seconds) {
        return Some(format!("could save about {time}"));
    }
    let bytes = a["savings_bytes"]
        .as_f64()
        .filter(|b| *b > 0.0)
        .or_else(|| display_bytes(a["display"].as_str()?))?;
    Some(format!("could save about {}", approx_bytes(bytes)))
}

/// The audits of one category that failed or need work, as one list
/// (Lighthouse's groups are for developers): failures first, then the
/// largest saving, one row per plain title. Informative audits are left
/// out: Lighthouse does not score them, and a client cannot act on them.
fn failing_audits(cat: &Json) -> Vec<(u8, f64, Json)> {
    let mut rows: Vec<(u8, f64, Json)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut all: Vec<&Json> = cat["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|g| g["audits"].as_array().into_iter().flatten())
        .collect();
    let rank = |a: &Json| match a["rating"].as_str() {
        Some("fail") => 0u8,
        Some("average") => 1,
        _ => 2,
    };
    all.sort_by(|a, b| {
        rank(a).cmp(&rank(b)).then(
            b["savings_ms"]
                .as_f64()
                .unwrap_or(0.0)
                .partial_cmp(&a["savings_ms"].as_f64().unwrap_or(0.0))
                .unwrap_or(Ordering::Equal),
        )
    });
    for a in all {
        let r = rank(a);
        if r > 1 {
            continue;
        }
        let title = audit_title(a);
        if !seen.insert(title.clone()) {
            continue;
        }
        rows.push((
            r,
            a["savings_ms"].as_f64().unwrap_or(0.0),
            json!({ "title": title, "rating": a["rating"], "saving": audit_saving(a) }),
        ));
    }
    rows
}

/// A stored artifact path, or the same file under the current artifact
/// directory when the data folder has been moved since it was written.
fn resolve_artifact(path: &str, artifact_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let direct = std::path::PathBuf::from(path);
    if direct.exists() {
        return Some(direct);
    }
    let normalised = path.replace('\\', "/");
    let tail = normalised.split("/artifacts/").nth(1)?;
    let moved = artifact_dir.join(tail);
    moved.exists().then_some(moved)
}

fn load_summary(path: &std::path::Path) -> Option<Json> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(file).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

/// One category of a page's summary, shaped for the template, its list
/// capped with the remainder counted.
fn category_view(cat: &Json, score: Option<f64>, label: &str, blurb: &str, cap: usize) -> Json {
    let audits = failing_audits(cat);
    let hidden = audits.len().saturating_sub(cap);
    let audits: Vec<Json> = audits.into_iter().take(cap).map(|a| a.2).collect();
    json!({
        "id": cat["id"],
        "label": label,
        "blurb": blurb,
        "gauge": gauge(label, score),
        "audits": audits,
        "hidden": hidden,
        "passed": cat["passed"],
    })
}

/// Everything a Lighthouse-style section for one page needs.
fn page_lighthouse_view(
    path: &str,
    kind: &str,
    values: &HashMap<String, f64>,
    summary: Option<&Json>,
    desktop: bool,
    cap: usize,
    reasons: Vec<String>,
) -> Json {
    let gauges: Vec<Json> = LH_CATEGORIES
        .iter()
        .map(|(key, _, label, _)| gauge(label, values.get(*key).copied()))
        .collect();
    let categories: Vec<Json> = LH_CATEGORIES
        .iter()
        .filter_map(|(key, id, label, blurb)| {
            let cat = summary?["categories"]
                .as_array()?
                .iter()
                .find(|c| c["id"] == *id)?;
            Some(category_view(cat, values.get(*key).copied(), label, blurb, cap))
        })
        .collect();
    json!({
        "path": path,
        "kind": kind,
        "reasons": reasons,
        "gauges": gauges,
        "metrics": metrics_grid(values, desktop),
        "categories": categories,
        "has_summary": summary.is_some(),
        "runs": values.get("lh.runs").map(|r| *r as i64),
        "perf_spread": values.get("lh.score.performance.spread").copied().filter(|s| *s > 0.0),
    })
}

/// A score cell for the page table: Lighthouse's shape, then the number.
fn score_cell(score: Option<f64>) -> Json {
    match score {
        Some(v) => json!({ "text": format!("{}", v.round() as i64), "rating": band(v) }),
        None => json!({ "text": Json::Null, "rating": "none" }),
    }
}

/// What was tested, said plainly: the claim a reader must not have to infer.
/// "Found on the site" only when nothing was left out by the page limit.
fn coverage_text(
    scope: Option<LighthouseScope>,
    measured: usize,
    loaded: usize,
    failed: usize,
    limited: bool,
) -> Option<String> {
    if measured == 0 {
        return match failed {
            0 => None,
            1 => Some("The browser test could not be completed on the one page tried.".to_string()),
            n => Some(format!("The browser tests could not be completed on any of the {n} pages tried.")),
        };
    }
    if measured == 1 && loaded == 1 {
        return Some("The home page was tested.".to_string());
    }
    let failed_note = if failed > 0 {
        format!(
            " {} could not be tested.",
            plural(failed, "page", "pages")
        )
    } else {
        String::new()
    };
    let were = if measured == 1 { "was" } else { "were" };
    Some(match scope {
        Some(LighthouseScope::EveryPage) if measured == loaded && !limited => {
            format!("All {measured} pages found on the site were tested.")
        }
        Some(LighthouseScope::EveryPage) if measured == loaded => {
            format!("All {measured} pages in this audit were tested.")
        }
        Some(LighthouseScope::EveryPage) => {
            format!("{measured} of the {loaded} pages in this audit {were} tested.{failed_note}")
        }
        Some(LighthouseScope::Sampled) => format!(
            "{measured} of {loaded} pages {were} tested: one of each type of page, the most common types first.{failed_note}"
        ),
        None => format!("{measured} of {loaded} pages {were} tested.{failed_note}"),
    })
}

/// The device and connection Lighthouse emulated: words for a sentence, and
/// words for the details table.
fn test_setup(runtime: Option<&Json>, desktop: bool) -> ((String, String), (String, String)) {
    let device = runtime.and_then(|r| r["device"].as_str()).unwrap_or("");
    let is_desktop = desktop || device.to_ascii_lowercase().contains("desktop");
    let device_words = if is_desktop {
        ("a desktop computer".to_string(), "Desktop computer".to_string())
    } else {
        let model = device.strip_prefix("Emulated ").filter(|m| !m.is_empty());
        (
            "a mid-range phone".to_string(),
            match model {
                Some(m) => format!("Mid-range phone ({m})"),
                None => "Mid-range phone".to_string(),
            },
        )
    };
    let network = runtime.and_then(|r| r["network"].as_str()).unwrap_or("");
    let network_words = if network.starts_with("Slow 4G") {
        ("a slow 4G connection".to_string(), "Slow 4G (simulated)".to_string())
    } else if network == "No throttling" {
        ("a full-speed connection".to_string(), "Full speed (not slowed)".to_string())
    } else if is_desktop {
        ("a typical broadband connection".to_string(), "Broadband (simulated)".to_string())
    } else if network.is_empty() {
        ("a slowed-down connection".to_string(), "Slowed down (simulated)".to_string())
    } else {
        ("a slowed-down connection".to_string(), network.to_string())
    };
    (device_words, network_words)
}

/// Rules whose finding is about the audit rather than the site. They are
/// listed as notes on the results, not as things to fix. Every info rule is
/// one of these, except the two the verdict speaks for.
const RULE_NO_FIELD_DATA: &str = "no-field-data";
const RULE_FIELD_IMPROVED: &str = "crux-history-improvement";

fn build_model(conn: &Connection, run_id: i64) -> Result<Json, String> {
    let run = storage::get_run(conn, run_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("run {run_id} not found"))?;
    let pages = storage::run_pages(conn, run_id).map_err(|e| e.to_string())?;
    let findings = storage::get_findings(conn, run_id).map_err(|e| e.to_string())?;
    let observations = storage::get_observations(conn, run_id).map_err(|e| e.to_string())?;

    let hostname = str_of(&run, "hostname").unwrap_or("site").to_string();
    let home_url = pages
        .first()
        .and_then(|p| str_of(p, "url"))
        .unwrap_or("")
        .to_string();

    // The home page's values carry the verdict, security, tech, software and
    // the measurements; the origin collectors (TLS, CrUX, discovery, vuln DB,
    // probe) were persisted onto the home page for exactly this reason.
    let mut home: BTreeMap<String, Ob> = BTreeMap::new();
    // Every page's numeric Lighthouse values, by page id: scores, metric
    // medians and spreads. What the page table, the cross-page view and each
    // page's Lighthouse section are drawn from.
    let mut lh_values: HashMap<i64, HashMap<String, f64>> = HashMap::new();
    for o in &observations {
        let key = str_of(o, "metric_key").unwrap_or("");
        let url = str_of(o, "url").unwrap_or("");
        if key.starts_with("lh.") && !key.starts_with("lh.run.") {
            if let (Some(page_id), Some(n)) = (num_of(o, "page_id"), num_of(o, "numeric_value")) {
                lh_values
                    .entry(page_id as i64)
                    .or_default()
                    .insert(key.to_string(), n);
            }
        }
        if url == home_url && !key.is_empty() {
            home.insert(
                key.to_string(),
                Ob {
                    num: num_of(o, "numeric_value"),
                    text: str_of(o, "text_value").map(str::to_string),
                },
            );
        }
    }

    let fmt = |key: &str| -> Option<String> { home.get(key).map(|o| format_value(key, Some(&o.value()))) };
    let num = |key: &str| -> Option<f64> { home.get(key).and_then(|o| o.num) };
    // Pages Lighthouse measured: the only pages a Lighthouse finding can be on.
    let tested = pages
        .iter()
        .filter(|p| {
            num_of(p, "id")
                .and_then(|id| lh_values.get(&(id as i64)))
                .and_then(|v| v.get("lh.runs"))
                .is_some_and(|runs| *runs > 0.0)
        })
        .count();

    // --- verdict ---
    let cwv = [
        ("crux.lcp.p75", "crux.lcp.good", "LCP", "Main content", 2500.0, 4000.0),
        ("crux.inp.p75", "crux.inp.good", "INP", "Responsiveness", 200.0, 500.0),
        ("crux.cls.p75", "crux.cls.good", "CLS", "Layout shift", 0.1, 0.25),
    ];
    let mut tiles = Vec::new();
    let mut all_good = true;
    for (key, good_key, label, caption, good, poor) in cwv {
        let Some(v) = num(key) else { continue };
        let (status, status_word) = cwv_status(v, good, poor);
        if status != "good" {
            all_good = false;
        }
        let rating = match status {
            "good" => "pass",
            "needs-improvement" => "average",
            _ => "fail",
        };
        tiles.push(json!({
            "label": label,
            "caption": caption,
            "value": fmt(key).unwrap_or_default(),
            "status": status,
            "status_word": status_word,
            "rating": rating,
            "meter_pct": (meter_pct(v, good, poor) * 10.0).round() / 10.0,
            "threshold": format!("good is {} or less", format_value(key, Some(&Value::Num(good)))),
            "good_share": num(good_key).map(|g| format!("{:.0}% of visits were good", g * 100.0)),
        }));
    }
    let has_field = !tiles.is_empty();
    let passes = has_field && all_good;

    let (flag_class, flag_word) = if !has_field {
        ("unknown", "Not enough data")
    } else if passes {
        ("good", "Passed")
    } else {
        ("poor", "Failed")
    };

    // --- findings, grouped by rule across pages ---
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, (Json, Vec<String>)> = BTreeMap::new();
    for f in &findings {
        let rule = str_of(f, "rule_id").unwrap_or("").to_string();
        let url = str_of(f, "url").unwrap_or("").to_string();
        let entry = groups.entry(rule.clone()).or_insert_with(|| {
            order.push(rule.clone());
            (f.clone(), Vec::new())
        });
        if !entry.1.contains(&url) {
            entry.1.push(url);
        }
    }

    // A finding whose evidence is entirely origin-scoped (the TLS certificate,
    // the CrUX record, the run's machine stability) is about the site, not
    // the home page its observations happen to be stored on.
    let origin_rules: HashSet<&str> = groups
        .iter()
        .filter(|(_, (f, _))| evidence_is_origin_scoped(f))
        .map(|(rule, _)| rule.as_str())
        .collect();

    // Which pages each rule fired on, and each page's problems, indexed once:
    // a 2,000-page run has tens of thousands of finding rows. Notes about
    // the audit are not problems. A problem on fewer than half the pages it
    // could be on is one most pages do not have, and earns its page a closer
    // look; a Lighthouse finding can only be on a page Lighthouse tested.
    let page_count = pages.len();
    let mut rule_pages: HashMap<String, HashSet<String>> = HashMap::new();
    let mut findings_by_url: HashMap<&str, Vec<&Json>> = HashMap::new();
    for f in &findings {
        if str_of(f, "severity") == Some("info") {
            continue;
        }
        let url = str_of(f, "url").unwrap_or("");
        rule_pages
            .entry(str_of(f, "rule_id").unwrap_or("").to_string())
            .or_default()
            .insert(url.to_string());
        findings_by_url.entry(url).or_default().push(f);
    }
    let is_rare = |f: &Json| {
        let rule = str_of(f, "rule_id").unwrap_or("");
        let eligible = if rule.starts_with("lh-") { tested } else { page_count };
        matches!(str_of(f, "severity"), Some("critical" | "high" | "medium"))
            && !origin_rules.contains(rule)
            && rule_pages.get(rule).map_or(0, |s| s.len()) * 2 < eligible
    };

    // Each finding's words from the current rule, filled in from the stored
    // observations of the page it was found on (the same values the engine
    // read when the run was finalised). Needed for one page per rule, and
    // for every page with a problem most pages do not have.
    let engine = FindingsEngine::load(None).ok();
    let rules: HashMap<&str, &Rule> = engine
        .iter()
        .flat_map(|e| e.rules.iter())
        .map(|r| (r.id.as_str(), r))
        .collect();
    let needed: HashSet<i64> = groups
        .values()
        .map(|(f, _)| f)
        .chain(findings.iter().filter(|f| is_rare(f)))
        .filter_map(|f| num_of(f, "page_id").map(|n| n as i64))
        .collect();
    let mut page_obs: HashMap<i64, HashMap<String, Value>> = HashMap::new();
    for o in &observations {
        let Some(page_id) = num_of(o, "page_id").map(|n| n as i64) else { continue };
        if !needed.contains(&page_id) {
            continue;
        }
        if let (Some(key), Some(value)) = (str_of(o, "metric_key"), stored_value(o)) {
            page_obs.entry(page_id).or_default().insert(key.to_string(), value);
        }
    }
    const PERIODS: [&str; 2] = ["crux.history.first_period", "crux.history.last_period"];
    let words_of = |f: &Json| -> (String, String, Option<String>, Option<String>) {
        let rule = str_of(f, "rule_id").and_then(|id| rules.get(id));
        let values = num_of(f, "page_id").and_then(|p| page_obs.get(&(p as i64)));
        match (rule, values) {
            (Some(rule), Some(values)) => {
                // A field-data period reads as a date like every other date
                // in the report: "4 May 2026", not "2026-05-04".
                let dated;
                let values = if PERIODS.iter().any(|k| values.contains_key(*k)) {
                    let mut v = values.clone();
                    for key in PERIODS {
                        if let Some(Value::Text(t)) = v.get(key) {
                            let date = friendly_date(t);
                            v.insert(key.to_string(), Value::Text(date));
                        }
                    }
                    dated = v;
                    &dated
                } else {
                    values
                };
                (
                    render_template(&rule.title, values),
                    render_template(&rule.detail, values),
                    rule.remediation.as_ref().map(|t| render_template(t, values)),
                    rule.wp_rocket_setting.clone(),
                )
            }
            _ => (
                str_of(f, "title").unwrap_or("").to_string(),
                str_of(f, "detail").unwrap_or("").to_string(),
                str_of(f, "remediation").map(str::to_string),
                str_of(f, "wp_rocket_setting").map(str::to_string),
            ),
        }
    };

    let mut significant = Vec::new();
    let mut minor = Vec::new();
    let mut notes = Vec::new();
    let mut news = Vec::new();
    let mut counts = json!({"critical":0,"high":0,"medium":0,"low":0});
    for rule in &order {
        let (f, urls) = &groups[rule];
        let sev = str_of(f, "severity").unwrap_or("info");
        // "1 of 20 pages" would understate an origin-scoped finding twentyfold.
        let origin_only = origin_rules.contains(rule.as_str());
        let is_sitewide = (urls.len() == page_count || origin_only) && page_count > 1;
        let (title, detail, remediation, wp_rocket_setting) = words_of(f);
        if sev == "info" {
            match rule.as_str() {
                // The verdict already says this, in the same words.
                RULE_NO_FIELD_DATA => {}
                RULE_FIELD_IMPROVED => news.push(json!(title)),
                _ => notes.push(json!({
                    "title": title,
                    "detail": detail,
                    "scope": if page_count <= 1 || is_sitewide {
                        String::new()
                    } else if urls.len() == 1 {
                        format!("on {}", page_name(&urls[0]))
                    } else {
                        format!("on {} of {} pages", urls.len(), page_count)
                    },
                })),
            }
            continue;
        }
        if let Some(n) = counts.get(sev).and_then(Json::as_i64) {
            counts[sev] = json!(n + 1);
        }
        let scope_text = if page_count <= 1 {
            String::new()
        } else if origin_only {
            "The whole site".to_string()
        } else if is_sitewide {
            format!("All {page_count} pages")
        } else if urls.len() == 1 {
            match page_name(&urls[0]).as_str() {
                "the home page" => "The home page".to_string(),
                path => path.to_string(),
            }
        } else {
            format!("{} of {} pages", urls.len(), page_count)
        };
        let card = json!({
            "status": severity_class(sev),
            "severity_word": severity_word(sev),
            "title": title,
            "detail": detail,
            "remediation": remediation,
            "wp_rocket_setting": wp_rocket_setting,
            "effort_label": effort_label(str_of(f, "effort")),
            "scope_text": scope_text,
            "is_sitewide": is_sitewide,
            "page_count": urls.len(),
            "pages": urls.iter().take(8).map(|u| short_path(u)).collect::<Vec<_>>(),
        });
        if matches!(sev, "critical" | "high" | "medium") {
            significant.push(card);
        } else {
            minor.push(card);
        }
    }
    let total_findings = significant.len() + minor.len();

    // --- Lighthouse: per page, across pages, and the gated page sections ---
    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    let desktop = num("lh.form_factor").is_none()
        && home.get("lh.form_factor").and_then(|o| o.text.as_deref()) == Some("desktop");
    let page_id_of = |p: &Json| num_of(p, "id").map(|n| n as i64).unwrap_or(0);
    let values_of = |p: &Json| lh_values.get(&page_id_of(p)).cloned().unwrap_or_default();
    let measured: Vec<&Json> = pages
        .iter()
        .filter(|p| values_of(p).get("lh.runs").copied().unwrap_or(0.0) > 0.0)
        .collect();
    let lh_failed = pages
        .iter()
        .filter(|p| values_of(p).get("lh.runs") == Some(&0.0))
        .count();

    // The compact summaries written when each page was measured.
    let artifacts = storage::get_artifacts(conn, run_id).map_err(|e| e.to_string())?;
    let mut summaries: HashMap<i64, Json> = HashMap::new();
    for a in &artifacts {
        if str_of(a, "kind") != Some("lh-summary") {
            continue;
        }
        let (Some(page_id), Some(path)) = (num_of(a, "page_id"), str_of(a, "path")) else {
            continue;
        };
        if let Some(summary) = resolve_artifact(path, &settings.artifact_dir).and_then(|p| load_summary(&p)) {
            summaries.insert(page_id as i64, summary);
        }
    }

    // The page table: every page, every category score, and the one lab
    // metric a client reads as load time. A page's issues are its own: a
    // problem with the whole site is stored on the home page, and counting it
    // there would make the home page look worse than any other.
    let lcp_points = LH_METRICS[1].mobile;
    let lcp_points_desktop = LH_METRICS[1].desktop;
    let page_rows: Vec<Json> = pages
        .iter()
        .map(|p| {
            let url = str_of(p, "url").unwrap_or("");
            let v = values_of(p);
            let lcp = v.get("lh.lcp").map(|x| {
                json!({
                    "text": lh_display("lh.lcp", *x),
                    "rating": metric_rating(*x, if desktop { lcp_points_desktop } else { lcp_points }),
                })
            });
            let problems: Vec<&&Json> = findings_by_url
                .get(url)
                .into_iter()
                .flatten()
                .filter(|f| !origin_rules.contains(str_of(f, "rule_id").unwrap_or("")))
                .collect();
            let urgent = problems
                .iter()
                .filter(|f| matches!(str_of(f, "severity"), Some("critical" | "high")))
                .count();
            json!({
                "path": short_path(url),
                "kind": page_kind(str_of(p, "template_class").unwrap_or("page")),
                "measured": v.contains_key("lh.score.performance"),
                "lh_failed": v.get("lh.runs") == Some(&0.0),
                "scores": LH_CATEGORIES.iter().map(|(k, _, _, _)| score_cell(v.get(*k).copied())).collect::<Vec<_>>(),
                "lcp": lcp,
                "issues": problems.len(),
                "urgent": urgent,
            })
        })
        .collect();

    // The home page, as Lighthouse would show it: full detail.
    let home_page = pages.iter().find(|p| str_of(p, "role") == Some("home")).or(pages.first());
    let home_lh = home_page.and_then(|p| {
        let v = values_of(p);
        v.contains_key("lh.score.performance").then(|| {
            page_lighthouse_view(
                &short_path(str_of(p, "url").unwrap_or("")),
                &page_kind(str_of(p, "template_class").unwrap_or("home")),
                &v,
                summaries.get(&page_id_of(p)),
                desktop,
                usize::MAX,
                Vec::new(),
            )
        })
    });

    // Across every measured page: each category's median and how the pages
    // fall into Lighthouse's three bands.
    let distribution: Vec<Json> = LH_CATEGORIES
        .iter()
        .filter_map(|(key, _, label, _)| {
            let mut scores: Vec<f64> = measured
                .iter()
                .filter_map(|p| values_of(p).get(*key).copied())
                .collect();
            let n = scores.len();
            let count = |b: &str| scores.iter().filter(|s| band(**s) == b).count();
            let (fail, average, pass) = (count("fail"), count("average"), count("pass"));
            let median = median_of(&mut scores)?;
            let pct = |c: usize| (c as f64 / n as f64 * 1000.0).round() / 10.0;
            Some(json!({
                "key": key,
                "label": label,
                "median": median.round() as i64,
                "rating": band(median),
                "n": n,
                "fail": fail, "average": average, "pass": pass,
                "fail_pct": pct(fail), "average_pct": pct(average), "pass_pct": pct(pass),
            }))
        })
        .collect();

    // The problems Lighthouse finds on the most pages: the cross-page view
    // only an every-page run can give. One line per plain title, with its
    // reach. (category id, title) -> (pages, savings, any fail)
    let mut reach: HashMap<(String, String), (usize, Vec<f64>, bool)> = HashMap::new();
    for summary in summaries.values() {
        for cat in summary["categories"].as_array().into_iter().flatten() {
            let cat_id = cat["id"].as_str().unwrap_or("").to_string();
            for (rank, saving, a) in failing_audits(cat) {
                let entry = reach
                    .entry((cat_id.clone(), a["title"].as_str().unwrap_or("").to_string()))
                    .or_insert_with(|| (0, Vec::new(), false));
                entry.0 += 1;
                if saving > 0.0 {
                    entry.1.push(saving);
                }
                entry.2 |= rank == 0;
            }
        }
    }
    let summarised = summaries.len();
    let mut common: Vec<Json> = reach
        .iter()
        .map(|((cat_id, title), (pages_hit, savings, any_fail))| {
            let mut savings = savings.clone();
            let saving = median_of(&mut savings).unwrap_or(0.0);
            json!({
                "title": title,
                "category": category_label(cat_id),
                "pages": pages_hit,
                "of": summarised,
                "rating": if *any_fail { "fail" } else { "average" },
                "saving": approx_seconds(saving).map(|s| format!("could save about {s}")),
                "saving_ms": saving,
            })
        })
        .collect();
    common.sort_by(|a, b| {
        b["pages"]
            .as_u64()
            .cmp(&a["pages"].as_u64())
            .then(
                b["saving_ms"]
                    .as_f64()
                    .partial_cmp(&a["saving_ms"].as_f64())
                    .unwrap_or(Ordering::Equal),
            )
            .then(a["title"].as_str().cmp(&b["title"].as_str()))
    });
    let common_total = common.len();
    common.truncate(15);

    let scope = run["lh_scope"].as_str().and_then(LighthouseScope::parse);
    let every_page = scope == Some(LighthouseScope::EveryPage);

    // Which other pages earn a section of their own. When every page was
    // tested, a page gets one only when it stands out: well below the site's
    // typical score, failing a category the site passes, or carrying
    // problems most pages do not have. Everything else is already in the
    // page table and the most common problems. When one page of each type
    // was tested, every one of them gets a section: it speaks for its type.
    // By key, never by position: a category no page has a score for is
    // absent from the distribution, and positions would then shift.
    let cat_medians: HashMap<String, f64> = distribution
        .iter()
        .filter_map(|d| Some((d["key"].as_str()?.to_string(), d["median"].as_f64()?)))
        .collect();
    let perf_median = cat_medians.get("lh.score.performance").copied();
    // (weight, performance, likeness, path, section)
    let mut candidates: Vec<(i32, f64, String, String, Json)> = Vec::new();
    for p in &measured {
        if home_page.is_some_and(|h| page_id_of(h) == page_id_of(p)) {
            continue;
        }
        let url = str_of(p, "url").unwrap_or("");
        let v = values_of(p);
        let perf = v.get("lh.score.performance").copied().unwrap_or(0.0);
        let mut reasons = Vec::new();
        let mut weight = 0;
        if let Some(m) = perf_median {
            if perf <= m - 15.0 {
                reasons.push(format!("Performance {} (typical page: {})", perf.round(), m.round()));
                weight += 3;
            }
        }
        for (key, _, label, _) in LH_CATEGORIES.iter().skip(1) {
            if let (Some(score), Some(m)) = (v.get(*key), cat_medians.get(*key)) {
                if band(*score) == "fail" && band(*m) != "fail" {
                    reasons.push(format!("{label} {} (typical page: {})", score.round(), m.round()));
                    weight += 2;
                }
            }
        }
        // Its own problems, by name: the findings and the failing Lighthouse
        // checks that most other pages do not share.
        let mut own: Vec<String> = Vec::new();
        for f in findings_by_url.get(url).into_iter().flatten() {
            if is_rare(f) {
                let title = words_of(f).0;
                if !own.contains(&title) {
                    own.push(title);
                }
            }
        }
        for cat in summaries
            .get(&page_id_of(p))
            .into_iter()
            .flat_map(|s| s["categories"].as_array().into_iter().flatten())
        {
            let cat_id = cat["id"].as_str().unwrap_or("").to_string();
            for (rank, _, a) in failing_audits(cat) {
                let title = a["title"].as_str().unwrap_or("").to_string();
                let shared = reach.get(&(cat_id.clone(), title.clone())).map_or(0, |r| r.0);
                if rank == 0 && shared * 2 < summarised && !own.contains(&title) {
                    own.push(title);
                }
            }
        }
        if !own.is_empty() {
            weight += 2;
        }
        let kind = page_kind(str_of(p, "template_class").unwrap_or("page"));
        if reasons.is_empty() && own.is_empty() {
            if every_page {
                continue;
            }
            reasons.push(format!("Tested as the example {}", lower_first(&kind)));
        }
        let summary = summaries.get(&page_id_of(p));
        // Pages of one type with the same problems are one section: forty
        // product pages built from one template are one thing to fix, and
        // forty near-identical sections would bury the page that differs.
        let mut problems: Vec<String> = summary
            .into_iter()
            .flat_map(|s| s["categories"].as_array().into_iter().flatten())
            .flat_map(|cat| {
                let cat_id = cat["id"].as_str().unwrap_or("").to_string();
                failing_audits(cat).into_iter().map(move |(_, _, a)| {
                    format!(
                        "{cat_id}/{}/{}",
                        a["rating"].as_str().unwrap_or(""),
                        a["title"].as_str().unwrap_or("")
                    )
                })
            })
            .collect();
        problems.extend(
            findings_by_url
                .get(url)
                .into_iter()
                .flatten()
                .map(|f| str_of(f, "rule_id").unwrap_or("").to_string()),
        );
        problems.sort();
        let likeness = match summary {
            Some(_) => format!("{kind}\n{}", problems.join("\n")),
            None => url.to_string(),
        };
        let path = short_path(url);
        let mut view = page_lighthouse_view(&path, &kind, &v, summary, desktop, 6, reasons);
        view["own"] = json!(own);
        candidates.push((weight, perf, likeness, path, view));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)));
    // The page that stands out most speaks for the pages like it.
    let mut sections: Vec<(Json, Vec<String>)> = Vec::new();
    let mut section_of: HashMap<String, usize> = HashMap::new();
    for (_, _, likeness, path, view) in candidates {
        match section_of.get(&likeness) {
            Some(&i) => sections[i].1.push(path),
            None => {
                section_of.insert(likeness, sections.len());
                sections.push((view, Vec::new()));
            }
        }
    }
    const PAGE_SECTIONS: usize = 25;
    let more_pages: usize = sections.iter().skip(PAGE_SECTIONS).map(|s| 1 + s.1.len()).sum();
    let page_sections: Vec<Json> = sections
        .into_iter()
        .take(PAGE_SECTIONS)
        .map(|(mut view, alike)| {
            view["alike_count"] = json!(alike.len());
            view["alike_more"] = json!(alike.len().saturating_sub(8));
            view["alike"] = json!(alike.into_iter().take(8).collect::<Vec<_>>());
            view
        })
        .collect();
    let pages_covered: usize = page_sections
        .iter()
        .map(|s| 1 + s["alike_count"].as_u64().unwrap_or(0) as usize)
        .sum();

    // What was tested, said plainly.
    let loaded = pages.iter().filter(|p| !p["final_url"].is_null()).count();
    let found = num("discovery.found").map(|n| n as usize);
    let dropped = num("discovery.dropped").map(|n| n as usize).unwrap_or(0);
    let coverage = coverage_text(scope, measured.len(), loaded, lh_failed, dropped > 0);
    let limit_note = match found {
        Some(found) if dropped > 0 => Some(format!(
            "We found {found} pages; this audit was limited to {}.",
            found.saturating_sub(dropped)
        )),
        _ => None,
    };
    let runtime = home_page
        .and_then(|p| summaries.get(&page_id_of(p)))
        .or_else(|| summaries.values().next())
        .map(|s| s["runtime"].clone());
    let ((device_phrase, device_detail), (network_phrase, network_detail)) =
        test_setup(runtime.as_ref(), desktop);
    // Lighthouse ran: it measured pages, or it tried and every page failed.
    let lh_attempted = !measured.is_empty() || lh_failed > 0;

    // The verdict's words depend on what else the report holds: whether our
    // own tests can stand in for field data, and whether a passing site still
    // has urgent problems.
    let urgent_fixes = counts["critical"].as_i64().unwrap_or(0) + counts["high"].as_i64().unwrap_or(0) > 0;
    let (headline, explanation) = verdict_prose(
        has_field,
        passes,
        urgent_fixes,
        &hostname,
        (!measured.is_empty()).then_some(device_phrase.as_str()),
    );

    // Each home gauge carries the typical page's score, matched by category.
    let mut home_lh = home_lh;
    if measured.len() > 1 {
        if let Some(gauges) = home_lh.as_mut().and_then(|h| h["gauges"].as_array_mut()) {
            for (g, (key, _, _, _)) in gauges.iter_mut().zip(LH_CATEGORIES.iter()) {
                if let Some(m) = cat_medians.get(*key) {
                    g["site_median"] = json!(m.round() as i64);
                }
            }
        }
    }
    let runs = num("lh.runs").filter(|r| *r > 0.0).map(|r| r as i64);
    let lighthouse = json!({
        "home": home_lh,
        "measured": measured.len(),
        "attempted": lh_attempted,
        "multi": measured.len() > 1,
        "distribution": distribution,
        "common": common,
        "common_more": common_total.saturating_sub(15),
        "summarised": summarised,
        "pages": page_sections,
        "pages_covered": pages_covered,
        "more_pages": more_pages,
        "every_page": every_page,
        "coverage": coverage,
        "limit_note": limit_note,
        "setup": format!("{device_phrase} on {network_phrase}"),
    });

    // --- software found (components and known security flaws) ---
    let software = home.contains_key("component.count").then(|| {
        let count = num("component.count").unwrap_or(0.0) as usize;
        // The database's date is recorded whenever the check ran; the counts
        // only when they are not zero.
        let checked = home.contains_key("vuln.db_generated");
        let confirmed = num("vuln.confirmed_count").unwrap_or(0.0) as usize;
        let possible = num("vuln.possible_count").unwrap_or(0.0) as usize;
        let unchecked = num("vuln.unchecked_count").unwrap_or(0.0) as usize;
        // A low-severity flaw has no finding of its own, so "listed" is said
        // only when one of the vulnerability findings is in the list.
        let listed = order
            .iter()
            .any(|r| r.starts_with("vuln-confirmed") || r == "vuln-possible");
        let flaws = if !checked {
            "These were not checked against a database of known security flaws.".to_string()
        } else {
            let mut text = if confirmed + possible == 0 {
                "No known security flaw was found for them in the vulnerability database.".to_string()
            } else {
                let mut parts = Vec::new();
                if confirmed > 0 {
                    parts.push(format!("{confirmed} confirmed"));
                }
                if possible > 0 {
                    parts.push(format!("{possible} possible"));
                }
                format!(
                    "Known security flaws: {}.{}",
                    parts.join(" and "),
                    if listed { " The details are in What to fix first." } else { "" }
                )
            };
            if unchecked > 0 {
                text.push_str(&format!(
                    " {} could not be checked.",
                    plural(unchecked, "component", "components")
                ));
            }
            text
        };
        let db_note = fmt("vuln.db_generated").map(|generated| {
            let sources = fmt("vuln.db_sources").unwrap_or_else(|| "the vulnerability database".into());
            // The attribution the NVD's terms of use ask of anything that
            // shows its data.
            let notice = if sources.contains("NVD") {
                " This product uses data from the NVD API but is not endorsed or certified by the NVD."
            } else {
                ""
            };
            format!(
                "Checked against {sources}, as of {}. Confirmed means a browser read the exact version from the page; possible means the version was worked out from file names and should be checked.{notice}",
                friendly_date(&generated)
            )
        });
        json!({
            "detected": fmt("component.detected"),
            "count": count,
            "flaws": flaws,
            "db_note": db_note,
        })
    });

    // --- security, from the home page and the origin ---
    let mut connection: Vec<Json> = Vec::new();
    let mut connection_row = |label: &str, value: String, rating: Option<&str>| {
        connection.push(json!({ "label": label, "value": value, "rating": rating }));
    };
    if let Some(valid) = num("tls.valid") {
        let ok = valid != 0.0;
        let value = match (ok, fmt("tls.error")) {
            (true, _) => "Valid".to_string(),
            (false, Some(e)) => format!("Not valid: {e}"),
            (false, None) => "Not valid".to_string(),
        };
        connection_row("Security certificate", value, Some(if ok { "pass" } else { "fail" }));
    }
    if let Some(issuer) = fmt("tls.issuer") {
        connection_row("Issued by", issuer, None);
    }
    if let (Some(days), Some(text)) = (num("tls.days_to_expiry"), fmt("tls.days_to_expiry")) {
        connection_row("Expires in", text, Some(if days < 21.0 { "fail" } else { "pass" }));
    }
    if let Some(protocol) = fmt("tls.protocol") {
        let (words, rating) = match protocol.as_str() {
            "TLSv1.3" => ("TLS 1.3".to_string(), "pass"),
            "TLSv1.2" => ("TLS 1.2".to_string(), "pass"),
            "TLSv1.1" | "TLSv1" | "SSLv3" => (
                format!("{} (outdated)", protocol.replace("TLSv", "TLS ").replace("SSLv", "SSL ")),
                "fail",
            ),
            other => (other.to_string(), "pass"),
        };
        connection_row("Encryption", words, Some(rating));
    }
    if let Some(upgrades) = num("redirect.upgrades_to_https") {
        let ok = upgrades != 0.0;
        connection_row(
            "Sends http:// visitors to https://",
            if ok { "Yes" } else { "No" }.to_string(),
            Some(if ok { "pass" } else { "fail" }),
        );
    }

    // The six headers the HTTP collector expects (`EXPECTED_SECURITY_HEADERS`),
    // as what each one protects. Frame protection also counts when the CSP
    // sets frame-ancestors, as the clickjacking rule does.
    let checked_headers = home.contains_key("sec.missing_header_count");
    let has = |key: &str| home.contains_key(key);
    let frame_protected = has("sec.x_frame_options")
        || home
            .get("sec.csp")
            .and_then(|o| o.text.as_deref())
            .is_some_and(|csp| csp.to_ascii_lowercase().contains("frame-ancestors"));
    let headers: Vec<Json> = [
        ("Always use a secure connection", "Strict-Transport-Security", has("sec.hsts")),
        ("Limit which scripts can run", "Content-Security-Policy", has("sec.csp")),
        ("Stop other sites showing pages in a frame", "X-Frame-Options", frame_protected),
        ("Stop browsers guessing file types", "X-Content-Type-Options", has("sec.x_content_type_options")),
        ("Keep page addresses private from other sites", "Referrer-Policy", has("sec.referrer_policy")),
        ("Control camera, microphone and location access", "Permissions-Policy", has("sec.permissions_policy")),
    ]
    .iter()
    .map(|(label, name, set)| json!({ "label": label, "name": name, "set": set }))
    .collect();
    let headers_set = headers.iter().filter(|h| h["set"] == true).count();

    let cookies_total = num("sec.cookies_total").map(|n| n as i64);
    let cookies: Vec<Json> = if cookies_total.unwrap_or(0) > 0 {
        [
            ("sec.cookies_total", "Cookies set by the home page"),
            ("sec.cookies_insecure", "Can be sent unencrypted (no Secure flag)"),
            ("sec.cookies_no_httponly", "Readable by scripts (no HttpOnly flag)"),
            ("sec.cookies_no_samesite", "No cross-site protection (no SameSite)"),
        ]
        .into_iter()
        .filter_map(|(k, l)| fmt(k).map(|value| json!({ "label": l, "value": value })))
        .collect()
    } else {
        Vec::new()
    };

    // --- technology ---
    let wp_rocket = if num("wprocket.present") == Some(1.0) {
        Some(fmt("wprocket.version").unwrap_or_else(|| "installed".into()))
    } else {
        None
    };
    let tech = json!({
        "cms": fmt("tech.cms"),
        "cdn": fmt("tech.cdn"),
        "page_builder": fmt("tech.page_builder"),
        "cache_plugin": fmt("tech.cache_plugin"),
        "server": fmt("http.server"),
        "wp_rocket": wp_rocket,
    });

    // --- about this report: how it was tested, notes, other measurements ---
    let date = friendly_date(str_of(&run, "started_at").unwrap_or(""));
    let lh_version = str_of(&run, "lh_version").map(str::to_string).or_else(|| {
        runtime
            .as_ref()
            .and_then(|r| r["lighthouse_version"].as_str())
            .map(str::to_string)
    });
    let chrome_major = str_of(&run, "chrome_version")
        .and_then(|v| v.split('.').next())
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let mut details: Vec<Json> = vec![json!({ "label": "Date tested", "value": date })];
    if lh_attempted {
        // Of the pages in this audit, as the page table counts them.
        let tested = match (measured.len(), loaded) {
            (m, l) if m == l && l > 1 => format!("All {l}"),
            (m, l) if m == l => m.to_string(),
            (m, l) => format!("{m} of {l}"),
        };
        details.push(json!({ "label": "Pages tested", "value": tested }));
        details.push(json!({ "label": "Device", "value": device_detail }));
        details.push(json!({ "label": "Connection", "value": network_detail }));
        if let Some(v) = &lh_version {
            details.push(json!({ "label": "Testing tool", "value": format!("Google Lighthouse {v}") }));
        }
        if let Some(c) = &chrome_major {
            details.push(json!({ "label": "Browser", "value": format!("Chrome {c}") }));
        }
        match runs {
            Some(1) => details.push(json!({ "label": "Tests per page", "value": "1" })),
            Some(r) => details.push(json!({ "label": "Tests per page", "value": format!("{r}, middle result used") })),
            None => {}
        }
    }
    details.push(json!({ "label": "Audit reference", "value": run_id.to_string() }));

    // A short list of further figures a client might ask about, in plain
    // words. The complete set stays in the app.
    let method_words = |m: &str| -> String {
        match m {
            "sitemap" => "From the site's sitemap".into(),
            "crawl" => "By following links from the home page".into(),
            "manual" => "Supplied for this audit".into(),
            other => other.into(),
        }
    };
    let compression_words = |c: &str| -> String {
        match c {
            "none" => "None".into(),
            "br" => "Brotli".into(),
            "gzip" => "Gzip".into(),
            "zstd" => "Zstandard".into(),
            "deflate" => "Deflate".into(),
            other => other.into(),
        }
    };
    let mut other: Vec<Json> = Vec::new();
    let mut other_row = |label: &str, value: Option<String>| {
        if let Some(value) = value {
            other.push(json!({ "label": label, "value": value }));
        }
    };
    // Discovery that was not run records nothing found, not a site of none.
    other_row("Pages found on the site", fmt("discovery.found").filter(|_| found.unwrap_or(0) > 0));
    other_row("How the pages were found", fmt("discovery.method").map(|m| method_words(&m)));
    if dropped > 0 {
        other_row("Pages left out by the page limit", fmt("discovery.dropped"));
    }
    other_row("Server response time (home page)", fmt("http.ttfb"));
    other_row("Home page HTML size", fmt("http.content_bytes"));
    other_row("Home page total download", fmt("lh.total_bytes"));
    other_row("Compression", fmt("http.compression").map(|c| compression_words(&c)));
    other_row("Connection protocol", fmt("http.version"));
    other_row("Redirects before the home page", fmt("redirect.hops"));
    other_row("Time spent running scripts", fmt("lh.bootup_time"));
    other_row("Total browser processing time", fmt("lh.mainthread_work"));
    other_row("Other websites the home page loads from", fmt("thirdparty.origin_count"));

    let branding = json!({
        "company_name": settings.branding.get("company_name"),
        "accent": settings.branding.get("accent"),
        "logo_data_uri": settings.branding.get("logo_data_uri"),
    });

    Ok(json!({
        "hostname": hostname,
        "date": date,
        "run_id": run_id,
        "branding": branding,
        // Report-content switches (Settings screen): whether findings carry
        // the "In WP Rocket" remediation line, and their "How to fix" advice.
        // Detection in the technology section is unaffected by either.
        "show_wp_rocket": settings.wp_rocket_suggestions,
        "show_fix_advice": settings.fix_advice,
        "verdict": {
            "flag_class": flag_class, "flag_word": flag_word,
            "headline": headline, "explanation": explanation,
            "has_field": has_field, "tiles": tiles, "news": news,
        },
        "total_findings": total_findings,
        "severity_counts": counts,
        "is_multipage": page_count > 1,
        "significant": significant,
        "minor": minor,
        "pages": page_rows,
        "lh": lighthouse,
        "software": software,
        "tech": tech,
        "security": {
            "connection": connection,
            "checked_headers": checked_headers,
            "headers": headers,
            "headers_set": headers_set,
            "headers_total": 6,
            "cookies_total": cookies_total,
            "cookies": cookies,
        },
        "about": {
            // "tested", "failed" (tried, and no page could be measured) or "none".
            "lighthouse": if !measured.is_empty() {
                "tested"
            } else if lh_attempted {
                "failed"
            } else {
                "none"
            },
            "runs": runs,
            "device": device_phrase,
            "network": network_phrase,
            "details": details,
            "notes": notes,
            "other": other,
        },
        "provenance": {
            "slap_version": str_of(&run, "slap_version").unwrap_or(""),
            "lighthouse_version": lh_version,
        },
    }))
}

/// Whether every evidence key a finding cites describes the origin.
fn evidence_is_origin_scoped(finding: &Json) -> bool {
    let Some(text) = str_of(finding, "evidence_json") else {
        return false;
    };
    let Ok(Json::Object(evidence)) = serde_json::from_str::<Json>(text) else {
        return false;
    };
    let registry = metric_registry();
    !evidence.is_empty()
        && evidence.keys().all(|key| {
            registry
                .get(key.as_str())
                .is_some_and(|m| m.scope == slap_core::schema::Scope::Origin)
        })
}

/// The verdict's headline and explanation. `tested_as` is the device our own
/// browser tests emulated, when they ran; `urgent` is whether any critical or
/// high problem is listed below.
fn verdict_prose(
    has_field: bool,
    passes: bool,
    urgent: bool,
    hostname: &str,
    tested_as: Option<&str>,
) -> (String, String) {
    if !has_field {
        let ours = match tested_as {
            Some(device) => format!(
                "the scores in this report come from our own tests, which load each page \
                 the way {device} would"
            ),
            None => "the figures in this report come from our own checks of the site".to_string(),
        };
        (
            format!("Google does not have enough real-visitor data for {hostname} yet."),
            format!(
                "Google only reports how a site performs for real visitors once it gets \
                 enough traffic. Until then, {ours}."
            ),
        )
    } else if passes {
        (
            "Real visitors are getting a good experience.".to_string(),
            format!(
                "Google's data from real visits over the last 28 days puts loading speed, \
                 responsiveness and layout stability all within its \"good\" range. {}",
                if urgent {
                    "Some of the issues below still need attention."
                } else {
                    "The issues below are smaller improvements, not a failing grade."
                }
            ),
        )
    } else {
        (
            "Real visitors are not getting a good enough experience.".to_string(),
            "Google's data from real visits over the last 28 days puts at least one of \
             loading speed, responsiveness and layout stability outside its \"good\" \
             range. That affects visitors and can affect search rankings. The issues \
             to fix first are listed below."
                .to_string(),
        )
    }
}

fn effort_label(effort: Option<&str>) -> Option<String> {
    match effort? {
        "low" => Some("Quick fix".into()),
        "medium" => Some("Some work".into()),
        "high" => Some("Bigger job".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_path_reduces_a_url_to_its_path() {
        assert_eq!(short_path("https://example.com/"), "/ (home)");
        assert_eq!(short_path("https://example.com/shop/widget"), "/shop/widget");
        assert_eq!(short_path("https://example.com"), "/");
    }

    #[test]
    fn meter_pins_thresholds_at_a_third_and_two_thirds() {
        assert!((meter_pct(2500.0, 2500.0, 4000.0) - 33.0).abs() < 0.01);
        assert!((meter_pct(4000.0, 2500.0, 4000.0) - 66.0).abs() < 0.01);
        assert_eq!(meter_pct(0.0, 2500.0, 4000.0), 0.0);
        assert!(meter_pct(20000.0, 2500.0, 4000.0) <= 100.0);
    }

    #[test]
    fn metrics_display_and_rate_the_way_lighthouse_does() {
        assert_eq!(lh_display("lh.lcp", 9500.0), "9.5 s");
        assert_eq!(lh_display("lh.fcp", 800.0), "0.8 s", "paint metrics stay in seconds");
        assert_eq!(lh_display("lh.tbt", 1234.4), "1,234 ms");
        assert_eq!(lh_display("lh.cls", 0.0), "0");
        assert_eq!(lh_display("lh.cls", 0.012), "0.012");
        assert_eq!(lh_display("lh.cls", 0.25), "0.25");
        // Mobile LCP: 2.5s and under passes, to 4s is average, beyond fails.
        let lcp = LH_METRICS[1].mobile;
        assert_eq!(LH_METRICS[1].key, "lh.lcp");
        assert_eq!(metric_rating(2500.0, lcp), "pass");
        assert_eq!(metric_rating(2501.0, lcp), "average");
        assert_eq!(metric_rating(4001.0, lcp), "fail");
        // Lighthouse's score bands, and the gauge arc that draws them.
        assert_eq!((band(90.0), band(89.0), band(50.0), band(49.0)), ("pass", "average", "average", "fail"));
        let g = gauge("Performance", Some(63.0));
        assert_eq!(g["rating"], "average");
        assert_eq!(g["dash"], "221.67 351.86");
        assert_eq!(gauge("SEO", None)["rating"], "none");
    }

    #[test]
    fn lighthouse_audits_read_as_plain_problems_with_plain_savings() {
        let image = json!({"id": "image-delivery-insight", "title": "Improve image delivery",
                           "display": "Est savings of 767 KiB", "savings_ms": 4050.0});
        assert_eq!(audit_title(&image), "Images are bigger than they need to be");
        assert_eq!(audit_saving(&image).as_deref(), Some("could save about 4.0 s"));
        // No meaningful time saving: the download size, in decimal KB.
        let css = json!({"id": "unminified-css", "display": "Est savings of 229 KiB", "savings_ms": 40.0});
        assert_eq!(audit_saving(&css).as_deref(), Some("could save about 234 KB"));
        // Neither: nothing printed, rather than "2 failure reasons".
        let bf = json!({"id": "bf-cache", "display": "2 failure reasons"});
        assert_eq!(audit_saving(&bf), None);
        // An audit with no plain title keeps Lighthouse's, without its full stop.
        let other = json!({"id": "some-new-audit", "title": "Something Lighthouse added."});
        assert_eq!(audit_title(&other), "Something Lighthouse added");
    }

    #[test]
    fn audits_that_mean_the_same_thing_are_listed_once() {
        let cat = json!({"id": "accessibility", "groups": [{"audits": [
            {"id": "aria-roles", "rating": "fail"},
            {"id": "aria-valid-attr", "rating": "fail"},
            {"id": "color-contrast", "rating": "average"},
            {"id": "csp-xss", "rating": "informative"},
        ]}]});
        let titles: Vec<String> = failing_audits(&cat)
            .into_iter()
            .map(|(_, _, a)| a["title"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            titles,
            vec![
                "Screen-reader markup (ARIA) is used incorrectly",
                "Some text is hard to read against its background"
            ],
            "duplicates merged, informative audits left out"
        );
    }

    #[test]
    fn dates_page_types_and_coverage_read_plainly() {
        assert_eq!(friendly_date("2026-10-06T02:16:11+00:00"), "6 October 2026");
        assert_eq!(friendly_date("not a date"), "not a date");
        assert_eq!(page_kind("post"), "Blog post");
        assert_eq!(page_kind("depth-1"), "Top-level page");
        assert_eq!(page_kind("depth-7"), "Level 7 page");
        assert_eq!(page_kind("gallery"), "Gallery");
        let every = Some(LighthouseScope::EveryPage);
        assert_eq!(
            coverage_text(every, 6, 6, 0, false).as_deref(),
            Some("All 6 pages found on the site were tested.")
        );
        assert_eq!(
            coverage_text(every, 6, 6, 0, true).as_deref(),
            Some("All 6 pages in this audit were tested.")
        );
        assert_eq!(
            coverage_text(every, 5, 6, 1, false).as_deref(),
            Some("5 of the 6 pages in this audit were tested. 1 page could not be tested.")
        );
        assert!(coverage_text(Some(LighthouseScope::Sampled), 3, 8, 0, false)
            .unwrap()
            .starts_with("3 of 8 pages were tested: one of each type of page"));
        assert!(coverage_text(Some(LighthouseScope::Sampled), 1, 20, 0, false)
            .unwrap()
            .starts_with("1 of 20 pages was tested"));
        assert_eq!(
            coverage_text(Some(LighthouseScope::Sampled), 1, 1, 0, false).as_deref(),
            Some("The home page was tested.")
        );
        // Lighthouse tried and failed everywhere: said so, not left unsaid.
        assert_eq!(
            coverage_text(every, 0, 6, 6, false).as_deref(),
            Some("The browser tests could not be completed on any of the 6 pages tried.")
        );
        assert_eq!(coverage_text(every, 0, 6, 0, false), None);
    }

    #[test]
    fn the_verdict_only_mentions_our_tests_when_they_ran() {
        let (_, with) = verdict_prose(false, false, false, "example.com", Some("a mid-range phone"));
        assert!(with.contains("the way a mid-range phone would"), "{with}");
        let (_, without) = verdict_prose(false, false, false, "example.com", None);
        assert!(!without.contains("phone") && without.contains("our own checks"), "{without}");
        let (_, passing_but_urgent) = verdict_prose(true, true, true, "example.com", None);
        assert!(passing_but_urgent.contains("still need attention"), "{passing_but_urgent}");
    }

    #[test]
    fn a_finding_about_the_origin_is_site_wide() {
        let tls = json!({ "evidence_json": "{\"tls.valid\": false, \"tls.error\": \"expired\"}" });
        assert!(evidence_is_origin_scoped(&tls));
        let drift = json!({ "evidence_json": "{\"lh.run.benchmark_drift\": 0.3}" });
        assert!(evidence_is_origin_scoped(&drift));
        let page = json!({ "evidence_json": "{\"lh.lcp\": 4000, \"tls.valid\": true}" });
        assert!(!evidence_is_origin_scoped(&page), "one page-scoped key makes it a page finding");
        assert!(!evidence_is_origin_scoped(&json!({})));
    }

    #[test]
    fn severity_maps_high_to_serious_and_medium_to_warning() {
        assert_eq!(severity_class("high"), "serious");
        assert_eq!(severity_class("medium"), "warning");
        assert_eq!(severity_word("critical"), "Critical");
    }

    /// A one-page run in an in-memory database: observations as the
    /// collectors would store them, and findings stored with out-of-date
    /// wording, as a run audited under an older rules file has.
    fn stored_run() -> (Connection, i64) {
        use slap_core::schema::obs;
        let conn = storage::open_db(std::path::Path::new(":memory:")).unwrap();
        let site = storage::upsert_site(&conn, "example.com", None, None).unwrap();
        let run = storage::create_run(&conn, "batch-1", site, "0.1.0", slap_core::SCHEMA_VERSION, None).unwrap();
        let mut page = storage::NewPage::new("https://example.com/");
        page.final_url = Some("https://example.com/");
        let page_id = storage::create_page(&conn, run, &page).unwrap();
        let observations: Vec<_> = [
            ("crux.available", Value::Bool(false)),
            ("sec.cookies_total", Value::Num(2.0)),
            ("sec.cookies_insecure", Value::Num(2.0)),
            ("sec.hsts", Value::from("max-age=31536000")),
            ("sec.missing_header_count", Value::Num(5.0)),
            ("lh.benchmark_index", Value::Num(700.0)),
        ]
        .into_iter()
        .map(|(k, v)| obs(k, v).unwrap())
        .collect();
        storage::insert_observations(&conn, page_id, &observations).unwrap();
        let values = storage::observations_as_dict(&conn, page_id).unwrap();
        let mut findings = FindingsEngine::load(None).unwrap().run(&values).unwrap();
        for f in &mut findings {
            f.title = format!("OLD WORDING {}", f.rule_id);
        }
        storage::insert_findings(&conn, page_id, &findings).unwrap();
        (conn, run)
    }

    #[test]
    fn findings_read_in_the_current_rules_words_and_notes_stay_out_of_the_fix_list() {
        let (conn, run) = stored_run();
        let model = build_model(&conn, run).unwrap();
        let titles = |list: &str| -> Vec<String> {
            model[list]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["title"].as_str().unwrap().to_string())
                .collect()
        };
        let fixes = [titles("significant"), titles("minor")].concat();
        assert!(
            fixes.contains(&"2 cookie(s) can be sent without encryption".to_string()),
            "rendered from the current rule with the stored value: {fixes:?}"
        );
        assert!(!fixes.iter().any(|t| t.starts_with("OLD WORDING")), "{fixes:?}");
        // The busy test machine is a note on the results, not a problem with
        // the site, and the missing field data is the verdict's to say.
        let notes = model["about"]["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(notes[0]["title"], "The testing computer was slow or busy during this audit");
        assert!(!fixes.iter().any(|t| t.contains("testing computer") || t.contains("real-visitor data")));
        assert_eq!(model["total_findings"].as_u64().unwrap() as usize, fixes.len());
        // Six protective headers checked; HSTS is the one set.
        assert_eq!(model["security"]["headers_total"], 6);
        assert_eq!(model["security"]["headers_set"], 1);
        assert_eq!(model["security"]["cookies"].as_array().unwrap().len(), 2, "only the counts recorded");
    }

    #[test]
    fn the_sites_own_text_prints_as_text() {
        // A Server header, a redirect chain or a component name is the site's
        // text. Markup in one must not become the report's markup, and a path
        // keeps its slashes.
        let env = environment().unwrap();
        let tmpl = env.get_template("report").unwrap();
        let (conn, run) = stored_run();
        let mut model = build_model(&conn, run).unwrap();
        model["significant"][0]["title"] = json!("Served by <title>Evil</title> at /blog/post");
        let html = tmpl.render(minijinja::Value::from_serialize(&model)).unwrap();
        assert!(html.contains("Served by &lt;title&gt;Evil&lt;/title&gt; at /blog/post"));
        assert!(!html.contains("<title>Evil"));
        assert!(html.contains("<title>Site audit: example.com</title>"), "the template's own markup is untouched");
        assert!(html.contains(".gauge {"), "the stylesheet is included as it is");
    }

    #[test]
    fn the_masthead_renders_the_configured_brand_name_and_logo() {
        // Also guards that the whole template still parses and renders.
        let env = environment().unwrap();
        let tmpl = env.get_template("report").unwrap();
        let (conn, run) = stored_run();
        let real = build_model(&conn, run).unwrap();
        let base = |branding: Json| -> Json {
            let mut model = real.clone();
            model["branding"] = branding;
            model
        };
        let render = |m: Json| tmpl.render(minijinja::Value::from_serialize(&m)).unwrap();

        let both = render(base(
            json!({ "company_name": "Acme Audits", "logo_data_uri": "data:image/png;base64,ZZZZ" }),
        ));
        assert!(both.contains("Acme Audits"), "brand name shown");
        assert!(both.contains("data:image/png;base64,ZZZZ"), "logo shown");

        let neither = render(base(json!({ "company_name": Json::Null, "logo_data_uri": Json::Null })));
        assert!(
            neither.contains("Site performance and security audit"),
            "neutral default when unbranded"
        );
        assert!(!neither.contains("<img class=\"logo\""), "no logo image when unset");
        assert!(neither.contains("About this report"));
        assert!(!neither.contains("Section 1"), "no section numbers");
        assert!(!neither.contains("sec.cookies_total"), "no raw measurement keys");
    }

    #[test]
    fn wp_rocket_suggestion_shows_only_when_enabled() {
        // The "In WP Rocket" fix line follows the show_wp_rocket flag; the
        // plain fix advice is always shown. Also proves no empty .fix block is
        // left when the WP Rocket setting is a finding sole fix and it is off.
        let env = environment().unwrap();
        let tmpl = env.get_template("report").unwrap();
        let (conn, run) = stored_run();
        let real = build_model(&conn, run).unwrap();
        let model = |show: bool, remediation: Json| -> Json {
            let mut model = real.clone();
            model["show_wp_rocket"] = json!(show);
            model["show_fix_advice"] = json!(true);
            model["minor"] = json!([]);
            model["significant"] = json!([{
                "status":"serious","severity_word":"High","title":"Slow images","detail":"d",
                "remediation": remediation, "wp_rocket_setting":"Enable LazyLoad for images",
                "effort_label": Json::Null, "scope_text":"",
                "is_sitewide": false, "page_count": 1, "pages": []
            }]);
            model
        };
        let render = |m: Json| tmpl.render(minijinja::Value::from_serialize(&m)).unwrap();

        let on = render(model(true, json!("Compress the hero image")));
        assert!(on.contains("In WP Rocket"), "suggestion shown when enabled");
        assert!(on.contains("Enable LazyLoad for images"));

        let off = render(model(false, json!("Compress the hero image")));
        assert!(!off.contains("In WP Rocket"), "suggestion hidden when disabled");
        assert!(!off.contains("Enable LazyLoad for images"));
        assert!(off.contains("Compress the hero image"), "the plain fix still shows");

        // A finding whose ONLY fix is the WP Rocket one: off means no fix block.
        let only_wpr_off = render(model(false, Json::Null));
        assert!(!only_wpr_off.contains("class=\"fix\""), "no empty fix block");
        let only_wpr_on = render(model(true, Json::Null));
        assert!(only_wpr_on.contains("In WP Rocket"), "lone WP Rocket fix shows when on");

        // "How to fix" switched off: the advice goes, the WP Rocket line
        // follows its own switch, and with both off no empty block is left.
        let mut no_advice = model(true, json!("Compress the hero image"));
        no_advice["show_fix_advice"] = json!(false);
        let html = render(no_advice.clone());
        assert!(!html.contains("How to fix") && !html.contains("Compress the hero image"));
        assert!(html.contains("Enable LazyLoad for images"), "WP Rocket line is independent");
        no_advice["show_wp_rocket"] = json!(false);
        assert!(!render(no_advice).contains("class=\"fix\""), "no empty fix block");
    }
}
