//! Software component detection: which libraries, CMS, and plugins a page is
//! running, and how sure we are of each version. Extends the technology
//! fingerprint from names to named-and-versioned software, so the vulnerability
//! matcher (`vulndb`) has something concrete to look up.
//!
//! Two confidence levels, and the distinction is the whole point:
//! - **Observed**: the version was read from a place that names the real file,
//!   a versioned asset path like `jquery-3.6.0.min.js` or `/jquery/3.6.0/`, or
//!   the CMS generator tag. A browser saw this; it is not a guess.
//! - **Inferred**: the version came only from a `?ver=` asset query string,
//!   which WordPress reuses for its core version and caching plugins rewrite.
//!   It is a lead, not a fact, and never drives a confirmed finding.
//!
//! Pure over HTML plus headers, like the fingerprint it extends: no network.

use std::collections::BTreeMap;

use slap_core::schema::{obs, Observation, Value};

use crate::vulndb;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confidence {
    Observed,
    Inferred,
}

#[derive(Clone, Debug)]
pub struct Component {
    /// The vulndb ecosystem: "npm", "wordpress", or "wordpress-plugin".
    pub ecosystem: String,
    /// The vulndb package key (a jQuery is "jquery", Yoast is "wordpress-seo").
    pub package: String,
    /// How the component is named to a human in the report.
    pub display: String,
    pub version: Option<String>,
    pub confidence: Confidence,
}

// A JS library: its vulndb package key, its display name, and the URL
// substrings that identify it. Order matters: the most specific needle wins, so
// jquery-ui is listed before jquery. The last few are common libraries the
// database does NOT cover; detecting them lets the report say "not checked"
// rather than silently omitting them.
const JS_LIBS: &[(&str, &str, &[&str])] = &[
    ("jquery-ui", "jQuery UI", &["jquery-ui", "jquery.ui", "jqueryui"]),
    ("jquery", "jQuery", &["jquery"]),
    ("bootstrap", "Bootstrap", &["bootstrap"]),
    ("angular", "Angular", &["angular"]),
    (
        "react",
        "React",
        &["react-dom", "react.production", "react.development", "/react@", "/react/"],
    ),
    ("lodash", "Lodash", &["lodash"]),
    ("underscore", "Underscore.js", &["underscore"]),
    ("moment", "Moment.js", &["moment.min.js", "moment.js", "/moment@", "/moment/"]),
    ("handlebars", "Handlebars", &["handlebars"]),
    ("knockout", "Knockout", &["knockout"]),
    ("highcharts", "Highcharts", &["highcharts"]),
    ("socket.io", "Socket.IO", &["socket.io"]),
    ("dojo", "Dojo", &["/dojo/dojo", "/dojo/"]),
    ("yui", "YUI", &["/yui/", "yui-min", "yui3"]),
    ("next", "Next.js", &["/_next/static"]),
    // Common but NOT in the database -> these surface as "unchecked".
    ("vue", "Vue.js", &["vue.min.js", "vue.runtime", "vue.global", "/vue@", "vue.js"]),
    ("swiper", "Swiper", &["swiper-bundle", "swiper.min", "/swiper@", "swiper.js"]),
    ("slick", "Slick", &["slick.min.js", "slick-carousel", "slick.js"]),
    ("font-awesome", "Font Awesome", &["font-awesome", "fontawesome"]),
    ("gsap", "GSAP", &["gsap.min.js", "/gsap@", "tweenmax"]),
];

/// The `src`/`href` URLs referenced in the HTML, lightly parsed. This does not
/// need a DOM: it wants the asset URLs, and a scan for the two attributes that
/// carry them is enough and dependency-free.
fn asset_urls(html: &str) -> Vec<String> {
    let bytes = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    for attr in ["src=", "href=", "data-src=", "data-rocket-src="] {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(attr) {
            let start = from + rel + attr.len();
            from = start;
            if start >= bytes.len() {
                break;
            }
            let quote = bytes[start];
            if quote != b'"' && quote != b'\'' {
                continue;
            }
            let value_start = start + 1;
            if let Some(rel_end) = html[value_start..].find(quote as char) {
                let value = &html[value_start..value_start + rel_end];
                if !value.is_empty() {
                    out.push(value.to_string());
                }
                from = value_start + rel_end + 1;
            }
        }
    }
    out
}

/// Split a URL into its path (lowercased) and query (lowercased) halves.
fn path_and_query(url: &str) -> (String, String) {
    let lower = url.to_ascii_lowercase();
    match lower.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (lower, String::new()),
    }
}

/// The first dotted-numeric version token in a string (`X.Y` or `X.Y.Z`).
fn first_version_token(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let token = s[start..i].trim_end_matches('.');
            if token.contains('.') && token.split('.').all(|p| !p.is_empty()) {
                return Some(token.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The version a `?ver=` (or `?v=`) query string carries, if it is a version.
fn version_from_query(query: &str) -> Option<String> {
    for pair in query.split('&') {
        let value = pair
            .strip_prefix("ver=")
            .or_else(|| pair.strip_prefix("v="))
            .or_else(|| pair.strip_prefix("version="))?;
        if let Some(v) = first_version_token(value) {
            return Some(v);
        }
    }
    None
}

/// Given a matched asset URL, decide the version and how sure we are of it: a
/// version in the path is observed; one only in the `?ver=` string is inferred.
fn version_of(path: &str, query: &str) -> (Option<String>, Confidence) {
    if let Some(v) = first_version_token(path) {
        (Some(v), Confidence::Observed)
    } else if let Some(v) = version_from_query(query) {
        (Some(v), Confidence::Inferred)
    } else {
        (None, Confidence::Inferred)
    }
}

fn detect_js_libraries(urls: &[String]) -> Vec<Component> {
    let mut found: BTreeMap<&str, Component> = BTreeMap::new();
    for url in urls {
        let (path, query) = path_and_query(url);
        let haystack = format!("{path}?{query}");
        // The first library whose needle appears claims this URL.
        let hit = JS_LIBS
            .iter()
            .find(|(_, _, needles)| needles.iter().any(|n| haystack.contains(n)));
        let Some((package, display, _)) = hit else {
            continue;
        };
        let (version, confidence) = version_of(&path, &query);
        let candidate = Component {
            ecosystem: "npm".into(),
            package: (*package).into(),
            display: (*display).into(),
            version,
            confidence,
        };
        // Keep the strongest reading per library: a versioned, observed hit
        // beats a bare or inferred one seen elsewhere on the page.
        match found.get(package) {
            Some(existing) if reading_rank(existing) >= reading_rank(&candidate) => {}
            _ => {
                found.insert(package, candidate);
            }
        }
    }
    found.into_values().collect()
}

/// How informative a reading is: observed+version beats inferred+version beats
/// no version.
fn reading_rank(c: &Component) -> u8 {
    match (c.version.is_some(), c.confidence) {
        (true, Confidence::Observed) => 2,
        (true, Confidence::Inferred) => 1,
        _ => 0,
    }
}

/// WordPress core, whose authoritative version is the generator meta tag.
fn detect_wordpress_core(html: &str) -> Option<Component> {
    let lower = html.to_ascii_lowercase();
    let is_wp = lower.contains("/wp-content/")
        || lower.contains("/wp-includes/")
        || lower.contains("wp-json")
        || lower.contains("content=\"wordpress");
    if !is_wp {
        return None;
    }
    // "WordPress 6.5" in a generator tag is the real core version, observed.
    let version = lower
        .find("wordpress")
        .and_then(|i| first_version_token(&html[i..(i + 40).min(html.len())]));
    Some(Component {
        ecosystem: "wordpress".into(),
        package: "wordpress".into(),
        display: "WordPress".into(),
        version,
        confidence: Confidence::Observed,
    })
}

/// WordPress plugins, from `/wp-content/plugins/<slug>/` asset paths. The `?ver`
/// on a plugin asset is the only version a site publishes for it, so it is
/// inferred, never observed.
fn detect_wp_plugins(urls: &[String]) -> Vec<Component> {
    let mut found: BTreeMap<String, Component> = BTreeMap::new();
    for url in urls {
        let (path, query) = path_and_query(url);
        let Some(after) = path.split("/wp-content/plugins/").nth(1) else {
            continue;
        };
        let slug = after.split('/').next().unwrap_or("").trim();
        if slug.is_empty() || slug.len() > 60 {
            continue;
        }
        let version = version_from_query(&query);
        let candidate = Component {
            ecosystem: "wordpress-plugin".into(),
            package: slug.to_string(),
            display: slug.to_string(),
            version,
            confidence: Confidence::Inferred,
        };
        match found.get(slug) {
            Some(existing) if existing.version.is_some() => {}
            _ => {
                found.insert(slug.to_string(), candidate);
            }
        }
    }
    found.into_values().collect()
}

/// Every component detected on the page.
pub fn detect_components(html: &str) -> Vec<Component> {
    let urls = asset_urls(html);
    let mut components = Vec::new();
    if let Some(core) = detect_wordpress_core(html) {
        components.push(core);
    }
    components.extend(detect_wp_plugins(&urls));
    components.extend(detect_js_libraries(&urls));
    components
}

/// Pure: HTML to the page's `component.*` and `vuln.*` observations. Headers are
/// accepted for symmetry with the fingerprint collector and future header-based
/// signals; today detection is HTML-driven.
pub fn observations_from_page(html: &str, _headers: &BTreeMap<String, String>) -> Vec<Observation> {
    let components = detect_components(html);
    let mut out = Vec::new();
    if components.is_empty() {
        return out;
    }

    let observed = components
        .iter()
        .filter(|c| c.version.is_some() && c.confidence == Confidence::Observed)
        .count();
    let inferred = components
        .iter()
        .filter(|c| c.version.is_some() && c.confidence == Confidence::Inferred)
        .count();

    let mut push = |key: &str, value: Value| {
        if let Ok(o) = obs(key, value) {
            out.push(o);
        }
    };
    push("component.count", Value::Num(components.len() as f64));
    push("component.observed_count", Value::Num(observed as f64));
    push("component.inferred_count", Value::Num(inferred as f64));
    push("component.detected", Value::from(describe(&components)));

    out.extend(vulndb::assess(&components));
    out
}

fn describe(components: &[Component]) -> String {
    let mut parts: Vec<String> = components
        .iter()
        .map(|c| match (&c.version, c.confidence) {
            (Some(v), Confidence::Inferred) => format!("{} {v} (inferred)", c.display),
            (Some(v), Confidence::Observed) => format!("{} {v}", c.display),
            (None, _) => c.display.clone(),
        })
        .collect();
    parts.sort_unstable();
    parts.dedup();
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(obs: Vec<Observation>) -> std::collections::HashMap<String, Value> {
        obs.into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect()
    }

    #[test]
    fn a_versioned_asset_path_is_an_observed_version() {
        let html = r#"<script src="/assets/vendor/jquery-3.6.0.min.js"></script>"#;
        let comps = detect_components(html);
        let jq = comps.iter().find(|c| c.package == "jquery").unwrap();
        assert_eq!(jq.version.as_deref(), Some("3.6.0"));
        assert_eq!(jq.confidence, Confidence::Observed);
    }

    #[test]
    fn a_ver_query_string_is_only_inferred() {
        let html = r#"<script src="/wp-includes/js/jquery/jquery.min.js?ver=1.12.4"></script>"#;
        let jq = detect_components(html)
            .into_iter()
            .find(|c| c.package == "jquery")
            .unwrap();
        assert_eq!(jq.version.as_deref(), Some("1.12.4"));
        assert_eq!(jq.confidence, Confidence::Inferred);
    }

    #[test]
    fn wordpress_core_version_comes_from_the_generator() {
        let html = r#"<meta name="generator" content="WordPress 6.5.2"><link href="/wp-content/themes/x/style.css">"#;
        let core = detect_wordpress_core(html).unwrap();
        assert_eq!(core.package, "wordpress");
        assert_eq!(core.version.as_deref(), Some("6.5.2"));
        assert_eq!(core.confidence, Confidence::Observed);
    }

    #[test]
    fn wp_plugins_are_detected_by_slug_with_an_inferred_version() {
        let html = r#"<link href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.21.0">
                      <script src="/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js?ver=8.5.0"></script>"#;
        let comps = detect_components(html);
        let elem = comps.iter().find(|c| c.package == "elementor").unwrap();
        assert_eq!(elem.ecosystem, "wordpress-plugin");
        assert_eq!(elem.version.as_deref(), Some("3.21.0"));
        assert_eq!(elem.confidence, Confidence::Inferred);
        assert!(comps.iter().any(|c| c.package == "woocommerce"));
    }

    #[test]
    fn a_real_looking_wordpress_page_produces_components_and_vuln_observations() {
        let html = r#"<html>
          <meta name="generator" content="WordPress 6.5">
          <link href="/wp-content/plugins/elementor/frontend.css?ver=3.21.0">
          <script src="/assets/vendor/jquery-1.6.2.min.js"></script>
          <script src="/assets/swiper-bundle.min.js?ver=9.0.0"></script>
        </html>"#;
        let v = values(observations_from_page(html, &BTreeMap::new()));
        // Four components: WordPress, elementor, jquery, swiper.
        assert_eq!(v["component.count"], Value::Num(4.0));
        // jQuery 1.6.2 in a versioned path is observed and old enough to be a
        // real (confirmed) hit; swiper is not in the database (unchecked).
        assert!(v.contains_key("vuln.confirmed_count"), "observed jquery confirms");
        assert!(v.contains_key("vuln.unchecked_count"), "swiper is unchecked");
        assert!(v.contains_key("component.detected"));
    }

    #[test]
    fn a_plain_page_detects_nothing() {
        assert!(observations_from_page("<html><body>hi</body></html>", &BTreeMap::new()).is_empty());
    }
}
