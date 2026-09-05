//! Finding the pages of a site.
//!
//! Discovery is deliberately NOT a collector: a collector takes one URL and
//! returns observations, and discovery runs before any URL list exists and
//! produces it. The order is robots.txt `Sitemap:` directives, then the
//! conventional sitemap locations, then a shallow same-origin crawl.
//!
//! Three silent failure modes shaped this and are preserved here:
//! a `<sitemapindex>` is a list of *sitemaps*, not pages (checked on the root
//! element, never by a substring); `.xml.gz` is served as `application/gzip`
//! with no content-encoding, so the gzip is the payload and is sniffed by
//! magic bytes; and a cap that is applied and not stated reads as full
//! coverage, so the result carries `found` and `dropped`.
//!
//! Every parser is a pure function over bytes/strings, tested without a
//! network.

use std::collections::HashSet;

use slap_core::schema::DiscoveredVia;

pub const WELL_KNOWN_SITEMAPS: &[&str] = &[
    "/sitemap.xml",
    "/sitemap_index.xml", // Yoast
    "/wp-sitemap.xml",    // WordPress core 5.5+
    "/sitemap-index.xml",
];

const NON_PAGE_SUFFIXES: &[&str] = &[
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico", ".css", ".js",
    ".mjs", ".json", ".xml", ".txt", ".zip", ".gz", ".mp4", ".mp3", ".webm", ".woff", ".woff2",
    ".ttf", ".eot", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rss", ".atom",
];

#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub pages_per_site: usize,
    pub crawl_depth: usize,
    pub allow_crawl: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pages_per_site: 20,
            crawl_depth: 2,
            allow_crawl: true,
        }
    }
}

#[derive(Debug)]
pub struct DiscoveryResult {
    pub urls: Vec<String>,
    pub method: DiscoveredVia,
    pub found: usize,
    pub dropped: usize,
    pub sitemaps: Vec<String>,
    pub errors: Vec<String>,
}

impl Default for DiscoveryResult {
    fn default() -> Self {
        // Manual is the identity of "we were handed this URL", the right
        // default before any sitemap or crawl has changed it.
        Self {
            urls: Vec::new(),
            method: DiscoveredVia::Manual,
            found: 0,
            dropped: 0,
            sitemaps: Vec::new(),
            errors: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure parsing helpers
// ---------------------------------------------------------------------------

/// A stable identity for a page URL: fragment dropped, empty path becomes
/// `/`, host lowercased, one trailing-slash policy (kept only on root), query
/// KEPT (`?p=12` is a different page). Without this, `/about` and `/about/`
/// become two pages and every finding prints twice.
pub fn canonical_url(url: &str) -> String {
    let parsed = match url::Url::parse(url.trim()) {
        Ok(u) => u,
        Err(_) => return url.trim().to_string(),
    };
    let scheme = parsed.scheme().to_lowercase();
    let host = parsed.host_str().unwrap_or("").to_lowercase();
    let mut authority = host;
    if let Some(port) = parsed.port() {
        let default = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
        if !default {
            authority = format!("{authority}:{port}");
        }
    }
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path = "/".into();
    }
    if path.len() > 1 && path.ends_with('/') {
        path = path.trim_end_matches('/').to_string();
        if path.is_empty() {
            path = "/".into();
        }
    }
    let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
    format!("{scheme}://{authority}{path}{query}")
}

pub fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(pa), Ok(pb)) => {
            pa.scheme() == pb.scheme() && pa.host_str() == pb.host_str() && pa.port() == pb.port()
        }
        _ => false,
    }
}

/// False for assets and documents a page audit cannot describe.
pub fn looks_like_a_page(url: &str) -> bool {
    let path = url::Url::parse(url)
        .map(|u| u.path().to_lowercase())
        .unwrap_or_default();
    !NON_PAGE_SUFFIXES.iter().any(|s| path.ends_with(s))
}

/// Gunzip when the body is gzipped whatever the headers claim (a
/// `sitemap.xml.gz` is `application/gzip` with the gzip as payload).
pub fn decode_body(content: &[u8]) -> Vec<u8> {
    if content.len() >= 2 && content[0] == 0x1f && content[1] == 0x8b {
        use std::io::Read;
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(content)
            .read_to_end(&mut out)
            .is_ok()
        {
            return out;
        }
    }
    content.to_vec()
}

/// Every `Sitemap:` directive, case-insensitive and group-independent
/// (`Sitemap` is not scoped to a `User-agent` block).
pub fn parse_robots_sitemaps(text: &str, base: &url::Url) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("sitemap") {
                let value = value.trim();
                if !value.is_empty() {
                    if let Ok(joined) = base.join(value) {
                        out.push(joined.to_string());
                    }
                }
            }
        }
    }
    out
}

fn local_name(tag: &str) -> String {
    tag.rsplit(':').next().unwrap_or(tag).to_ascii_lowercase()
}

/// `(locations, is_index)` from a sitemap document. One parser for both
/// shapes: the `<loc>` extraction is identical, and only the root element
/// (`<sitemapindex>` vs `<urlset>`) decides whether the locations are child
/// sitemaps or pages. Getting that wrong audits a site's sitemaps instead of
/// its pages.
pub fn parse_sitemap(content: &[u8], base: &str) -> (Vec<String>, bool) {
    let body = decode_body(content);
    let text = String::from_utf8_lossy(&body);
    // The root element: the first tag that is not <?xml?>, a comment, or a
    // <!DOCTYPE>.
    let is_index = root_element(&text)
        .map(|t| local_name(&t) == "sitemapindex")
        .unwrap_or(false);
    let base_url = url::Url::parse(base).ok();
    let mut locations = Vec::new();
    for loc in extract_tag_text(&text, "loc") {
        let loc = loc.trim();
        if loc.is_empty() {
            continue;
        }
        let resolved = match &base_url {
            Some(b) => b
                .join(loc)
                .map(|u| u.to_string())
                .unwrap_or_else(|_| loc.to_string()),
            None => loc.to_string(),
        };
        locations.push(resolved);
    }
    (locations, is_index)
}

/// The local name of the first real element in an XML document.
fn root_element(text: &str) -> Option<String> {
    let mut rest = text;
    loop {
        let start = rest.find('<')?;
        rest = &rest[start..];
        if rest.starts_with("<?") {
            let end = rest.find("?>")?;
            rest = &rest[end + 2..];
        } else if rest.starts_with("<!--") {
            let end = rest.find("-->")?;
            rest = &rest[end + 3..];
        } else if rest.starts_with("<!") {
            let end = rest.find('>')?;
            rest = &rest[end + 1..];
        } else {
            // A real element. Read its name.
            let name: String = rest[1..]
                .chars()
                .take_while(|c| !c.is_ascii_whitespace() && *c != '>' && *c != '/')
                .collect();
            return Some(name);
        }
    }
}

/// The inner text of every `<tag>...</tag>` (namespace-insensitive).
fn extract_tag_text(text: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}");
    let mut from = 0;
    while let Some(rel) = lower[from..].find(&open) {
        let tag_start = from + rel;
        // Skip to the end of the opening tag.
        let Some(gt) = text[tag_start..].find('>') else {
            break;
        };
        let content_start = tag_start + gt + 1;
        let Some(crel) = lower[content_start..].find(&close) else {
            break;
        };
        let content_end = content_start + crel;
        out.push(unescape(&text[content_start..content_end]));
        from = content_end;
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .trim()
        .to_string()
}

/// Same-origin `href` targets, absolute and canonical. A regex-free scan over
/// already-fetched bytes: missing a link costs one page, not a wrong number.
pub fn extract_links(html: &str, base: &str) -> Vec<String> {
    let base_url = match url::Url::parse(base) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<a") {
        let start = from + rel;
        let Some(gt) = html[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + gt];
        from = start + gt + 1;
        let Some(href) = attr_value(tag, "href") else {
            continue;
        };
        let href = href.split('#').next().unwrap_or("").trim();
        if href.is_empty()
            || href.starts_with("mailto:")
            || href.starts_with("tel:")
            || href.starts_with("javascript:")
            || href.starts_with("data:")
        {
            continue;
        }
        let Ok(joined) = base_url.join(href) else {
            continue;
        };
        let absolute = canonical_url(joined.as_str());
        if seen.contains(&absolute)
            || !same_origin(&absolute, base)
            || !looks_like_a_page(&absolute)
        {
            continue;
        }
        seen.insert(absolute.clone());
        out.push(absolute);
    }
    out
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(name) {
        let at = from + rel;
        let after = at + name.len();
        let rest = lower[after..].trim_start();
        if rest.starts_with('=') {
            let eq = after + lower[after..].find('=').unwrap();
            let mut val = tag[eq + 1..].trim_start();
            let quote = val.chars().next();
            if quote == Some('"') || quote == Some('\'') {
                let q = quote.unwrap();
                val = &val[1..];
                if let Some(end) = val.find(q) {
                    return Some(val[..end].to_string());
                }
            } else {
                let end = val
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .unwrap_or(val.len());
                return Some(val[..end].to_string());
            }
        }
        from = after;
    }
    None
}

// ---------------------------------------------------------------------------
// The network side
// ---------------------------------------------------------------------------

async fn get_bytes(
    client: &reqwest::Client,
    url: &str,
    ua: &str,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    let response = client
        .get(url)
        .header(reqwest::header::USER_AGENT, ua)
        .timeout(timeout)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.bytes().await.ok().map(|b| b.to_vec())
}

/// Discover the pages of a site, home first, capped. Never returns fewer than
/// the home URL, so a site with no sitemap and crawling disabled still audits
/// its home page.
pub async fn discover(
    client: &reqwest::Client,
    home: &str,
    ua: &str,
    cfg: &DiscoveryConfig,
    timeout: std::time::Duration,
) -> DiscoveryResult {
    let home_canon = canonical_url(home);
    let mut result = DiscoveryResult {
        method: DiscoveredVia::Manual,
        ..Default::default()
    };
    if !cfg.enabled {
        result.urls = vec![home_canon];
        return result;
    }
    let base = match url::Url::parse(&home_canon) {
        Ok(u) => u,
        Err(_) => {
            result.urls = vec![home_canon];
            return result;
        }
    };

    // 1. Sitemaps: robots.txt directives, then the conventional locations.
    let mut sitemap_urls: Vec<String> = Vec::new();
    if let Some(robots) = get_bytes(
        client,
        base.join("/robots.txt").unwrap().as_str(),
        ua,
        timeout,
    )
    .await
    {
        sitemap_urls.extend(parse_robots_sitemaps(
            &String::from_utf8_lossy(&robots),
            &base,
        ));
    }
    for path in WELL_KNOWN_SITEMAPS {
        if let Ok(u) = base.join(path) {
            let s = u.to_string();
            if !sitemap_urls.contains(&s) {
                sitemap_urls.push(s);
            }
        }
    }

    let mut pages: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push_page = |url: &str, pages: &mut Vec<String>, seen: &mut HashSet<String>| {
        let c = canonical_url(url);
        if same_origin(&c, &home_canon) && looks_like_a_page(&c) && seen.insert(c.clone()) {
            pages.push(c);
        }
    };

    // Read sitemaps, following an index one level down.
    let mut to_read = sitemap_urls.clone();
    let mut read_count = 0;
    while let Some(sm) = to_read.pop() {
        if read_count >= 50 {
            break; // a runaway index should not fan out forever
        }
        read_count += 1;
        let Some(bytes) = get_bytes(client, &sm, ua, timeout).await else {
            continue;
        };
        let (locations, is_index) = parse_sitemap(&bytes, &sm);
        if is_index {
            for child in locations {
                if !result.sitemaps.contains(&child) {
                    to_read.push(child);
                }
            }
        } else {
            result.sitemaps.push(sm);
            for loc in locations {
                push_page(&loc, &mut pages, &mut seen);
            }
        }
    }

    if !pages.is_empty() {
        result.method = DiscoveredVia::Sitemap;
    } else if cfg.allow_crawl {
        // 2. Crawl fallback: shallow same-origin BFS from the home page.
        result.method = DiscoveredVia::Crawl;
        let mut frontier = vec![home_canon.clone()];
        let mut visited: HashSet<String> = HashSet::new();
        for _ in 0..cfg.crawl_depth {
            let mut next = Vec::new();
            for url in frontier.drain(..) {
                if !visited.insert(url.clone()) {
                    continue;
                }
                push_page(&url, &mut pages, &mut seen);
                if pages.len() >= cfg.pages_per_site * 3 {
                    break;
                }
                if let Some(bytes) = get_bytes(client, &url, ua, timeout).await {
                    for link in extract_links(&String::from_utf8_lossy(&bytes), &url) {
                        if !visited.contains(&link) {
                            next.push(link);
                        }
                    }
                }
            }
            frontier = next;
        }
    }

    // The home page is always present and always first.
    pages.retain(|p| p != &home_canon);
    let mut ordered = vec![home_canon];
    ordered.extend(pages);

    result.found = ordered.len();
    if ordered.len() > cfg.pages_per_site {
        result.dropped = ordered.len() - cfg.pages_per_site;
        ordered.truncate(cfg.pages_per_site);
    }
    result.urls = ordered;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalisation_folds_trailing_slash_but_keeps_query() {
        assert_eq!(canonical_url("https://X.com/about/"), "https://x.com/about");
        assert_eq!(canonical_url("https://x.com"), "https://x.com/");
        assert_eq!(
            canonical_url("https://x.com/p?id=12#frag"),
            "https://x.com/p?id=12"
        );
        assert_eq!(
            canonical_url("https://x.com:443/a"),
            "https://x.com/a",
            "default port dropped"
        );
    }

    #[test]
    fn assets_are_not_pages() {
        assert!(looks_like_a_page("https://x.com/about"));
        assert!(!looks_like_a_page("https://x.com/logo.png"));
        assert!(!looks_like_a_page("https://x.com/style.css"));
    }

    #[test]
    fn a_sitemap_index_is_distinguished_from_a_urlset() {
        let index = br#"<?xml version="1.0"?><sitemapindex xmlns="http://x"><sitemap><loc>https://x.com/sm1.xml</loc></sitemap></sitemapindex>"#;
        let (locs, is_index) = parse_sitemap(index, "https://x.com/");
        assert!(is_index);
        assert_eq!(locs, vec!["https://x.com/sm1.xml"]);

        let urlset = br#"<urlset><url><loc>https://x.com/a</loc></url><url><loc>https://x.com/b</loc></url></urlset>"#;
        let (locs, is_index) = parse_sitemap(urlset, "https://x.com/");
        assert!(!is_index);
        assert_eq!(locs, vec!["https://x.com/a", "https://x.com/b"]);
    }

    #[test]
    fn a_gzipped_sitemap_is_sniffed_and_decoded() {
        use std::io::Write;
        let xml = br#"<urlset><url><loc>https://x.com/g</loc></url></urlset>"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(xml).unwrap();
        let gz = enc.finish().unwrap();
        let (locs, _) = parse_sitemap(&gz, "https://x.com/");
        assert_eq!(locs, vec!["https://x.com/g"]);
    }

    #[test]
    fn robots_sitemaps_are_group_independent() {
        let robots = "User-agent: *\nDisallow: /wp-admin\nSitemap: https://x.com/sitemap.xml\n# c\nSitemap: https://x.com/news.xml";
        let base = url::Url::parse("https://x.com/").unwrap();
        assert_eq!(
            parse_robots_sitemaps(robots, &base),
            vec!["https://x.com/sitemap.xml", "https://x.com/news.xml"]
        );
    }

    #[test]
    fn links_are_same_origin_absolute_and_deduped() {
        let html = r#"<a href="/about">A</a><a href="about">dup</a><a href="https://other.com/x">off</a><a href="/logo.png">img</a><a href="mailto:a@b">m</a>"#;
        let links = extract_links(html, "https://x.com/");
        assert_eq!(
            links,
            vec!["https://x.com/about"],
            "one page, off-origin/asset/mailto excluded"
        );
    }

    #[test]
    fn coverage_ordering_measures_the_templates_that_speak_for_most_pages() {
        // home, page, contact, checkout, post x3, product x3.
        let mut pages = std::collections::HashMap::new();
        pages.insert("https://x.com/".to_string(), "home".to_string());
        pages.insert("https://x.com/page".to_string(), "page".to_string());
        pages.insert("https://x.com/contact".to_string(), "contact".to_string());
        pages.insert("https://x.com/checkout".to_string(), "checkout".to_string());
        for i in 0..3 {
            pages.insert(format!("https://x.com/post/{i}"), "post".to_string());
            pages.insert(format!("https://x.com/product/{i}"), "product".to_string());
        }
        let chosen = choose_lighthouse_pages(&pages, 4, Some("https://x.com/"));
        assert_eq!(chosen[0], "https://x.com/", "home first");
        let classes: HashSet<&str> = chosen.iter().map(|u| pages[u].as_str()).collect();
        assert!(
            classes.contains("post") && classes.contains("product"),
            "coverage ordering must include the high-count templates, got {classes:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Template classification (used to pick which pages get the browser audit)
// ---------------------------------------------------------------------------

const BODY_CLASS_TEMPLATES: &[(&str, &[&str])] = &[
    ("checkout", &["woocommerce-checkout"]),
    ("cart", &["woocommerce-cart"]),
    ("account", &["woocommerce-account"]),
    ("product", &["single-product"]),
    ("post", &["single-post", "single-format-standard"]),
    ("archive", &["archive", "category", "tag", "blog"]),
    ("search", &["search-results", "search-no-results"]),
    ("contact", &["page-template-contact"]),
    ("page", &["page-template", "page-id-"]),
];

const PATH_TEMPLATES: &[(&str, &[&str])] = &[
    ("checkout", &["/checkout", "/cart", "/basket"]),
    ("account", &["/account", "/my-account", "/login", "/signin"]),
    ("product", &["/product/", "/products/", "/shop/", "/item/"]),
    ("post", &["/blog/", "/news/", "/post/", "/article/"]),
    ("archive", &["/category/", "/tag/", "/archive/", "/topics/"]),
    ("contact", &["/contact"]),
    ("about", &["/about"]),
    ("legal", &["/privacy", "/terms", "/legal", "/cookie"]),
];

fn body_classes(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let Some(at) = lower.find("<body") else {
        return Vec::new();
    };
    let Some(gt) = html[at..].find('>') else {
        return Vec::new();
    };
    let tag = &html[at..at + gt];
    attr_value(tag, "class")
        .map(|c| {
            c.to_ascii_lowercase()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Name the template a page is an instance of, so one representative per
/// template gets the browser audit (a client acts on "product pages are
/// slow", not the 400th product page individually).
pub fn classify_template(url: &str, html: Option<&str>, is_home: bool) -> String {
    if is_home {
        return "home".into();
    }
    let classes: HashSet<String> = html
        .map(body_classes)
        .unwrap_or_default()
        .into_iter()
        .collect();
    if classes.contains("home") || classes.contains("front-page") {
        return "home".into();
    }
    for (name, needles) in BODY_CLASS_TEMPLATES {
        for needle in *needles {
            if needle.ends_with('-') {
                if classes.iter().any(|c| c.starts_with(needle)) {
                    return name.to_string();
                }
            } else if classes.contains(*needle) {
                return name.to_string();
            }
        }
    }
    let path = url::Url::parse(url)
        .map(|u| u.path().to_lowercase())
        .unwrap_or_default();
    if path.is_empty() || path == "/" {
        return "home".into();
    }
    for (name, needles) in PATH_TEMPLATES {
        if needles.iter().any(|n| path.contains(n)) {
            return name.to_string();
        }
    }
    let depth = path.split('/').filter(|p| !p.is_empty()).count().max(1);
    format!("depth-{depth}")
}

/// One representative per template class, home first, capped. Templates
/// covering MORE pages are measured first (ordering by coverage, not
/// alphabetically, or a 10-page site can measure four pages that speak for
/// four pages and say nothing about the other six). Ties break on class then
/// URL so two runs measure the same pages.
pub fn choose_lighthouse_pages(
    pages: &std::collections::HashMap<String, String>,
    limit: usize,
    home_url: Option<&str>,
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let mut chosen = Vec::new();
    let mut seen_classes = HashSet::new();
    if let Some(home) = home_url {
        if let Some(class) = pages.get(home) {
            chosen.push(home.to_string());
            seen_classes.insert(class.clone());
        }
    }
    let mut coverage: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for template in pages.values() {
        *coverage.entry(template.as_str()).or_insert(0) += 1;
    }
    let mut urls: Vec<&String> = pages.keys().collect();
    urls.sort_by(|a, b| {
        let (ca, cb) = (&pages[*a], &pages[*b]);
        (std::cmp::Reverse(coverage[ca.as_str()]), ca, *a).cmp(&(
            std::cmp::Reverse(coverage[cb.as_str()]),
            cb,
            *b,
        ))
    });
    for url in urls {
        if chosen.len() >= limit {
            break;
        }
        if chosen.contains(url) {
            continue;
        }
        let class = &pages[url];
        if seen_classes.contains(class) {
            continue;
        }
        seen_classes.insert(class.clone());
        chosen.push(url.clone());
    }
    chosen.truncate(limit);
    chosen
}
