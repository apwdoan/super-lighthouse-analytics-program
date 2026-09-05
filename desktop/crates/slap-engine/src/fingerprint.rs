//! Technology fingerprint, including the WP Rocket signals.
//!
//! Per the roadmap, WP Rocket is not a data source; it is a detectable
//! signal and a remediation target. The observation that earns its keep is
//! the pair "WP Rocket is installed" + "this URL was NOT served from its
//! cache", which is the finding a client reads twice.
//!
//! Everything here is a pure function over HTML text plus response headers,
//! so it tests with a string and no network. It reads the document the HTTP
//! collector already fetched; it never makes its own request.

use std::collections::BTreeMap;

use slap_core::schema::{obs, Observation, Value};

// ---------------------------------------------------------------------------
// Meta tags
// ---------------------------------------------------------------------------

/// Attributes of one HTML tag, lowercased keys. A small hand parser rather
/// than a DOM library: this only ever inspects <meta> tags and marker
/// substrings, and a full parser would be a heavy dependency for that.
fn parse_attrs(tag: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find an attribute name start (a letter).
        while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || bytes[i] == b'-'
                || bytes[i] == b':'
                || bytes[i] == b'_')
        {
            i += 1;
        }
        if i == name_start {
            i += 1;
            continue;
        }
        let name = tag[name_start..i].to_ascii_lowercase();
        // Skip whitespace, expect '='.
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'=' {
            out.insert(name, String::new());
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let value = if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
            let quote = bytes[j];
            j += 1;
            let start = j;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            let v = tag[start..j].to_string();
            j += 1;
            v
        } else {
            let start = j;
            while j < bytes.len() && !bytes[j].is_ascii_whitespace() && bytes[j] != b'>' {
                j += 1;
            }
            tag[start..j].to_string()
        };
        out.insert(name, value);
        i = j;
    }
    out
}

/// Every `<meta ...>` tag's attributes, in document order.
fn meta_tags(html: &str) -> Vec<BTreeMap<String, String>> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<meta") {
        let start = from + rel;
        let end = html[start..]
            .find('>')
            .map(|e| start + e + 1)
            .unwrap_or(html.len());
        out.push(parse_attrs(&html[start..end]));
        from = end;
    }
    out
}

fn generator_metas(html: &str) -> Vec<BTreeMap<String, String>> {
    meta_tags(html)
        .into_iter()
        .filter(|attrs| {
            attrs
                .get("name")
                .map(|n| n.eq_ignore_ascii_case("generator"))
                .unwrap_or(false)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// WP Rocket
// ---------------------------------------------------------------------------

const WPR_MARKUP_SIGNALS: &[&str] = &[
    "data-rocket-src",
    "data-rocket-href",
    "data-rocket-defer",
    "data-rocket-type",
    "wp-content/cache/wp-rocket",
    "rocket-lazyload",
    "wpr-lazyload",
    "rocketlazyloadscript",
];

#[derive(Debug, Default, PartialEq)]
pub struct WpRocket {
    pub present: bool,
    pub version: Option<String>,
    pub features: Option<String>,
    /// None when WP Rocket is not present, so "not installed" is
    /// distinguishable from "installed but cold".
    pub page_cached: Option<bool>,
    pub cached_at: Option<String>,
}

fn version_after(content_lower: &str, content: &str) -> Option<String> {
    let idx = content_lower
        .find("wp rocket")
        .or_else(|| content_lower.find("wp  rocket"))?;
    let tail = &content[idx..];
    let digits: String = tail
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!digits.is_empty()).then_some(digits)
}

pub fn detect_wp_rocket(html: &str, headers: &BTreeMap<String, String>) -> WpRocket {
    let mut result = WpRocket::default();

    // 1. The generator meta tag carries version and the feature bitfield.
    for attrs in generator_metas(html) {
        let content = attrs.get("content").cloned().unwrap_or_default();
        if content.to_ascii_lowercase().contains("wp rocket") {
            result.present = true;
            result.version = version_after(&content.to_ascii_lowercase(), &content);
            if let Some(features) = attrs.get("data-wpr-features") {
                result.features = Some(features.trim().to_string());
            }
            break;
        }
    }

    // 2. Markup signals, for installs that strip the generator tag.
    if !result.present {
        let haystack = html.to_ascii_lowercase();
        if WPR_MARKUP_SIGNALS.iter().any(|sig| haystack.contains(sig)) {
            result.present = true;
        }
    }

    // 3. The footer comment proves the page was served from cache.
    if let Some(stamp) = html
        .to_ascii_lowercase()
        .find("debug: cached@")
        .map(|i| &html[i + "debug: cached@".len()..])
    {
        let digits: String = stamp.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            result.present = true;
            result.page_cached = Some(true);
            result.cached_at = Some(digits);
        }
    } else if html
        .to_ascii_lowercase()
        .contains("performance optimized by wp rocket")
    {
        result.present = true;
        result.page_cached = Some(false);
    } else if result.present {
        result.page_cached = Some(false);
    }

    // Some hosts surface cache state in a header instead.
    if result.present && result.page_cached == Some(false) {
        let cache_header = ["x-rocket-cache", "x-cache", "cf-cache-status"]
            .iter()
            .filter_map(|k| headers.get(*k))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        if cache_header.contains("hit") {
            result.page_cached = Some(true);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// CMS, CDN, page builder, competing cache plugins
// ---------------------------------------------------------------------------

const CMS_MARKUP: &[(&str, &[&str])] = &[
    ("WordPress", &["/wp-content/", "/wp-includes/", "wp-json"]),
    (
        "Shopify",
        &["cdn.shopify.com", "shopify-features", "/cdn/shop/"],
    ),
    (
        "Wix",
        &["static.wixstatic.com", "wix-code", "_wixcssstates"],
    ),
    (
        "Squarespace",
        &["static1.squarespace.com", "squarespace-headers"],
    ),
    ("Drupal", &["/sites/default/files/", "drupal-settings-json"]),
    ("Joomla", &["/media/jui/", "joomla-script-options"]),
    (
        "Webflow",
        &["assets.website-files.com", "w-webflow-badge", "webflow.js"],
    ),
    ("Ghost", &["/assets/built/", "ghost-sdk"]),
];

const CDN_HEADERS: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cf-ray", "cf-cache-status"]),
    ("Amazon CloudFront", &["x-amz-cf-id", "x-amz-cf-pop"]),
    ("Fastly", &["x-served-by", "x-fastly-request-id"]),
    ("Akamai", &["x-akamai-transformed", "akamai-grn"]),
    ("Sucuri", &["x-sucuri-id", "x-sucuri-cache"]),
    ("Vercel", &["x-vercel-id"]),
    ("Netlify", &["x-nf-request-id"]),
];

const CDN_SERVER_STRINGS: &[(&str, &str)] = &[
    ("Cloudflare", "cloudflare"),
    ("BunnyCDN", "bunnycdn"),
    ("KeyCDN", "keycdn"),
    ("Netlify", "netlify"),
    ("Akamai", "akamaighost"),
    ("Amazon CloudFront", "cloudfront"),
];

const PAGE_BUILDERS: &[(&str, &[&str])] = &[
    (
        "Elementor",
        &["/plugins/elementor/", "elementor-page", "elementor-widget"],
    ),
    ("Divi", &["/themes/divi/", "et_pb_section", "et-db"]),
    ("WPBakery", &["js_composer", "vc_row", "wpb_wrapper"]),
    ("Beaver Builder", &["fl-builder", "/plugins/bb-plugin/"]),
    ("Bricks", &["/themes/bricks/", "brxe-"]),
    ("Oxygen", &["/plugins/oxygen/", "ct_section", "oxy-"]),
    (
        "Gutenberg",
        &["wp-block-", "/wp-includes/css/dist/block-library/"],
    ),
];

const CACHE_PLUGINS: &[(&str, &[&str])] = &[
    (
        "WP Rocket",
        &["wp-content/cache/wp-rocket", "data-rocket-src"],
    ),
    (
        "W3 Total Cache",
        &["w3 total cache", "wp-content/cache/minify", "w3tc"],
    ),
    (
        "WP Super Cache",
        &["wp super cache", "wp-content/cache/supercache"],
    ),
    ("LiteSpeed Cache", &["litespeed", "x-litespeed-cache"]),
    ("WP Fastest Cache", &["wp fastest cache", "wpfc-"]),
    (
        "Autoptimize",
        &["autoptimize", "wp-content/cache/autoptimize"],
    ),
];

fn match_first(
    haystack: &str,
    table: &[(&'static str, &'static [&'static str])],
) -> Option<&'static str> {
    table.iter().find_map(|(name, needles)| {
        needles
            .iter()
            .any(|n| haystack.contains(n))
            .then_some(*name)
    })
}

pub fn detect_cms(html: &str, headers: &BTreeMap<String, String>) -> Option<&'static str> {
    for attrs in generator_metas(html) {
        let content = attrs
            .get("content")
            .cloned()
            .unwrap_or_default()
            .to_ascii_lowercase();
        for name in [
            "wordpress",
            "drupal",
            "joomla",
            "ghost",
            "typo3",
            "concrete",
        ] {
            if content.contains(name) {
                return Some(match name {
                    "wordpress" => "WordPress",
                    "drupal" => "Drupal",
                    "joomla" => "Joomla",
                    "ghost" => "Ghost",
                    "typo3" => "Typo3",
                    _ => "Concrete",
                });
            }
        }
    }
    if headers.contains_key("x-shopid") || headers.contains_key("x-shopify-stage") {
        return Some("Shopify");
    }
    if headers.keys().any(|k| k.starts_with("x-wix")) {
        return Some("Wix");
    }
    if headers
        .get("x-generator")
        .map(|v| v.to_ascii_lowercase().starts_with("drupal"))
        .unwrap_or(false)
    {
        return Some("Drupal");
    }
    match_first(&html.to_ascii_lowercase(), CMS_MARKUP)
}

pub fn detect_cdn(headers: &BTreeMap<String, String>) -> Option<&'static str> {
    for (name, keys) in CDN_HEADERS {
        if keys.iter().any(|k| headers.contains_key(*k)) {
            return Some(name);
        }
    }
    let server = format!(
        "{} {}",
        headers.get("server").cloned().unwrap_or_default(),
        headers.get("via").cloned().unwrap_or_default()
    )
    .to_ascii_lowercase();
    CDN_SERVER_STRINGS
        .iter()
        .find_map(|(name, needle)| server.contains(needle).then_some(*name))
}

pub fn detect_page_builder(html: &str) -> Option<&'static str> {
    match_first(&html.to_ascii_lowercase(), PAGE_BUILDERS)
}

pub fn detect_cache_plugins(html: &str, headers: &BTreeMap<String, String>) -> Vec<&'static str> {
    let haystack = format!(
        "{} {}",
        html.to_ascii_lowercase(),
        headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    );
    CACHE_PLUGINS
        .iter()
        .filter(|(_, needles)| needles.iter().any(|n| haystack.contains(n)))
        .map(|(name, _)| *name)
        .collect()
}

/// Pure: HTML plus headers to fingerprint observations.
pub fn observations_from_html(html: &str, headers: &BTreeMap<String, String>) -> Vec<Observation> {
    let mut out = Vec::new();
    let mut push = |key: &str, value: Value| {
        if let Ok(o) = obs(key, value) {
            out.push(o);
        }
    };

    if let Some(cms) = detect_cms(html, headers) {
        push("tech.cms", Value::from(cms));
    }
    let generators = generator_metas(html);
    if !generators.is_empty() {
        let joined = generators
            .iter()
            .filter_map(|a| a.get("content"))
            .filter(|c| !c.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        if !joined.is_empty() {
            push(
                "tech.generator",
                Value::from(joined.chars().take(500).collect::<String>()),
            );
        }
    }
    if let Some(cdn) = detect_cdn(headers) {
        push("tech.cdn", Value::from(cdn));
    }
    if let Some(builder) = detect_page_builder(html) {
        push("tech.page_builder", Value::from(builder));
    }
    let plugins = detect_cache_plugins(html, headers);
    if !plugins.is_empty() {
        push("tech.cache_plugin", Value::from(plugins.join(", ")));
    }

    let rocket = detect_wp_rocket(html, headers);
    push("wprocket.present", Value::Bool(rocket.present));
    if rocket.present {
        if let Some(version) = rocket.version {
            push("wprocket.version", Value::from(version));
        }
        if let Some(features) = rocket.features {
            push("wprocket.features", Value::from(features));
        }
        if let Some(cached) = rocket.page_cached {
            push("wprocket.page_cached", Value::Bool(cached));
        }
        if let Some(at) = rocket.cached_at {
            push("wprocket.cached_at", Value::from(at));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn values(obs: Vec<Observation>) -> std::collections::HashMap<String, Value> {
        obs.into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect()
    }

    #[test]
    fn wp_rocket_installed_but_cold_is_the_finding() {
        let html = r#"<meta name="generator" content="WP Rocket 3.15.2" data-wpr-features="lazyload,minify">"#;
        let r = detect_wp_rocket(html, &BTreeMap::new());
        assert!(r.present);
        assert_eq!(r.version.as_deref(), Some("3.15.2"));
        assert_eq!(r.features.as_deref(), Some("lazyload,minify"));
        assert_eq!(
            r.page_cached,
            Some(false),
            "generator present, no cached@ stamp"
        );
    }

    #[test]
    fn wp_rocket_cached_stamp_proves_a_cache_hit() {
        let html = "<html>..<!-- Debug: cached@1699999999 --></html>";
        let r = detect_wp_rocket(html, &BTreeMap::new());
        assert!(r.present);
        assert_eq!(r.page_cached, Some(true));
        assert_eq!(r.cached_at.as_deref(), Some("1699999999"));
    }

    #[test]
    fn wp_rocket_absent_leaves_page_cached_none() {
        let r = detect_wp_rocket("<html>nothing here</html>", &BTreeMap::new());
        assert!(!r.present);
        assert_eq!(
            r.page_cached, None,
            "not installed must differ from installed-but-cold"
        );
    }

    #[test]
    fn a_cache_header_hit_upgrades_a_cold_reading() {
        let html = r#"<meta name="generator" content="WP Rocket 3.15">"#;
        let r = detect_wp_rocket(html, &headers(&[("x-cache", "HIT")]));
        assert_eq!(r.page_cached, Some(true));
    }

    #[test]
    fn cms_detected_from_generator_then_markup() {
        assert_eq!(
            detect_cms(
                r#"<meta name="generator" content="WordPress 6.5">"#,
                &BTreeMap::new()
            ),
            Some("WordPress")
        );
        assert_eq!(
            detect_cms("<link href='/wp-content/themes/x.css'>", &BTreeMap::new()),
            Some("WordPress")
        );
        assert_eq!(
            detect_cms("<html>plain</html>", &headers(&[("x-shopid", "42")])),
            Some("Shopify")
        );
        assert_eq!(detect_cms("<html>plain</html>", &BTreeMap::new()), None);
    }

    #[test]
    fn cdn_detected_from_headers_and_server() {
        assert_eq!(
            detect_cdn(&headers(&[("cf-ray", "abc")])),
            Some("Cloudflare")
        );
        assert_eq!(
            detect_cdn(&headers(&[("server", "cloudfront")])),
            Some("Amazon CloudFront")
        );
        assert_eq!(detect_cdn(&headers(&[("server", "nginx")])), None);
    }

    #[test]
    fn a_wordpress_page_with_elementor_and_wp_rocket_fingerprints_fully() {
        let html = r#"<html>
          <meta name="generator" content="WordPress 6.5">
          <meta name="generator" content="WP Rocket 3.15.2" data-wpr-features="minify">
          <link rel="stylesheet" href="/wp-content/plugins/elementor/frontend.css">
          <script data-rocket-src="/app.js"></script>
          <!-- Debug: cached@1700000000 -->
        </html>"#;
        let v = values(observations_from_html(
            html,
            &headers(&[("server", "nginx")]),
        ));
        assert_eq!(v["tech.cms"], Value::Text("WordPress".into()));
        assert_eq!(v["tech.page_builder"], Value::Text("Elementor".into()));
        assert_eq!(v["wprocket.present"], Value::Bool(true));
        assert_eq!(v["wprocket.page_cached"], Value::Bool(true));
        assert!(v.contains_key("tech.cache_plugin"));
    }
}
