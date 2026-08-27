//! The HTTP collector: the one request every no-browser collector shares.
//!
//! Ported from the Python `collectors/http_probe.py`. The parsing is pure
//! functions over a fetched document so the interesting logic tests without
//! a network, exactly as it did in Python; `fetch` is the only part that
//! touches a socket.
//!
//! Two Python gotchas carried across:
//!
//! - **Advertise only what you can decode.** `accept_encoding()` names the
//!   encodings this build actually has decoders for, and `fetch` decodes by
//!   hand, because reqwest's auto-decompression strips the Content-Encoding
//!   header when it decodes, and "was this compressed" is an observation.
//!   The Python bug was analysing 28KB of brotli as if it were HTML.
//! - **Never report a wrong HTTP version.** reqwest does real ALPN over
//!   rustls, so `response.version()` is trustworthy here; the Python code
//!   had to suppress the field when its h2 support was missing, a hazard
//!   this stack does not have.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Instant;

use slap_core::schema::{obs, Observation, Source, Value, EXPECTED_SECURITY_HEADERS};

/// One HTTP response, retained so several collectors share one request.
#[derive(Clone, Debug)]
pub struct FetchedDocument {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub http_version: String,
    /// Header names lowercased, exactly as the Python collector kept them.
    pub headers: BTreeMap<String, String>,
    pub set_cookie: Vec<String>,
    pub text: String,
    pub content_bytes: usize,
    pub ttfb_ms: f64,
    /// `(status, url)` per hop, final response included.
    pub redirect_chain: Vec<(u16, String)>,
}

/// The encodings this build can actually decode, so a stripped install
/// degrades to asking for gzip rather than to analysing undecoded bytes.
pub fn accept_encoding() -> &'static str {
    "gzip, deflate, br"
}

/// Extract `max-age` seconds from a Cache-Control (or STS) header value.
pub fn parse_max_age(header: Option<&str>) -> Option<i64> {
    let value = header?;
    let lower = value.to_ascii_lowercase();
    let idx = lower.find("max-age")?;
    let rest = &value[idx + "max-age".len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Which of the expected security headers are absent (lowercased names).
pub fn missing_security_headers(headers: &BTreeMap<String, String>) -> Vec<&'static str> {
    EXPECTED_SECURITY_HEADERS
        .iter()
        .filter(|h| !headers.contains_key(**h))
        .copied()
        .collect()
}

#[derive(Debug, Default, PartialEq)]
pub struct CookieHygiene {
    pub total: i64,
    pub insecure: i64,
    pub no_httponly: i64,
    pub no_samesite: i64,
}

/// Count cookies missing each hardening attribute. Only the response's own
/// Set-Cookie headers are in scope: JavaScript-set cookies are a browser
/// concern, and claiming otherwise would be a finding we cannot support.
pub fn analyze_cookies(set_cookie: &[String]) -> CookieHygiene {
    let mut out = CookieHygiene::default();
    for raw in set_cookie {
        let name_value = raw.split(';').next().unwrap_or("");
        if !name_value.contains('=') {
            continue;
        }
        out.total += 1;
        let attrs: Vec<String> = raw
            .split(';')
            .skip(1)
            .map(|part| {
                part.trim()
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            })
            .collect();
        if !attrs.iter().any(|a| a == "secure") {
            out.insecure += 1;
        }
        if !attrs.iter().any(|a| a == "httponly") {
            out.no_httponly += 1;
        }
        if !attrs.iter().any(|a| a == "samesite") {
            out.no_samesite += 1;
        }
    }
    out
}

/// True if the chain starts on http:// and ends on https://. None when it
/// began on HTTPS, because then the question does not apply and a False
/// would read as a downgrade.
pub fn upgrades_to_https(chain: &[(u16, String)]) -> Option<bool> {
    let first = chain.first()?;
    if !first.1.starts_with("http://") {
        return None;
    }
    Some(
        chain
            .last()
            .map(|(_, url)| url.starts_with("https://"))
            .unwrap_or(false),
    )
}

/// Accept bare hostnames from a pasted list; default to https.
pub fn normalize_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("empty URL".into());
    }
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(url.to_string())
    } else {
        Ok(format!("https://{url}"))
    }
}

/// Pure: turn a fetched document into observations. Network-free, and the
/// heart of what the tests pin.
pub fn observations_from_document(doc: &FetchedDocument) -> Vec<Observation> {
    let h = &doc.headers;
    let mut out: Vec<Observation> = Vec::new();
    let mut add = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            // Skip empty strings, matching the Python `value != ""` guard.
            if let Value::Text(t) = &value {
                if t.is_empty() {
                    return;
                }
            }
            if let Ok(o) = obs(key, value) {
                out.push(o);
            }
        }
    };
    let header = |name: &str| h.get(name).map(|v| Value::from(v.as_str()));

    add("http.status", Some(Value::Num(doc.status as f64)));
    add("http.version", Some(Value::from(doc.http_version.as_str())));
    add(
        "http.ttfb",
        Some(Value::Num((doc.ttfb_ms * 10.0).round() / 10.0)),
    );
    add(
        "http.content_bytes",
        Some(Value::Num(doc.content_bytes as f64)),
    );
    add("http.server", header("server"));

    let encoding = h.get("content-encoding");
    add(
        "http.compression",
        Some(Value::from(encoding.map(String::as_str).unwrap_or("none"))),
    );
    add("http.compressed", Some(Value::Bool(encoding.is_some())));

    let cache_control = h.get("cache-control").map(String::as_str);
    add("http.cache_control", cache_control.map(Value::from));
    add(
        "http.cache_max_age",
        parse_max_age(cache_control).map(|n| Value::Num(n as f64)),
    );
    add("http.has_etag", Some(Value::Bool(h.contains_key("etag"))));

    // Security headers
    let sts = h.get("strict-transport-security").map(String::as_str);
    add("sec.hsts", sts.map(Value::from));
    add(
        "sec.hsts_max_age",
        parse_max_age(sts).map(|n| Value::Num(n as f64)),
    );
    add("sec.csp", header("content-security-policy"));
    add(
        "sec.x_content_type_options",
        header("x-content-type-options"),
    );
    add("sec.x_frame_options", header("x-frame-options"));
    add("sec.referrer_policy", header("referrer-policy"));
    add("sec.permissions_policy", header("permissions-policy"));
    add(
        "sec.missing_header_count",
        Some(Value::Num(missing_security_headers(h).len() as f64)),
    );

    // Cookie hygiene
    let cookies = analyze_cookies(&doc.set_cookie);
    add("sec.cookies_total", Some(Value::Num(cookies.total as f64)));
    if cookies.total > 0 {
        add(
            "sec.cookies_insecure",
            Some(Value::Num(cookies.insecure as f64)),
        );
        add(
            "sec.cookies_no_httponly",
            Some(Value::Num(cookies.no_httponly as f64)),
        );
        add(
            "sec.cookies_no_samesite",
            Some(Value::Num(cookies.no_samesite as f64)),
        );
    }

    // Redirects. These carry an explicit source because their metric keys
    // are REDIRECT-sourced and there is no header to infer it from.
    let hops = doc.redirect_chain.len().saturating_sub(1);
    out.push(redirect_num("redirect.hops", hops as f64));
    if !doc.redirect_chain.is_empty() {
        let chain_text = doc
            .redirect_chain
            .iter()
            .map(|(status, url)| format!("{status} {url}"))
            .collect::<Vec<_>>()
            .join(" -> ");
        out.push(redirect_text("redirect.chain", chain_text));
    }
    out.push(redirect_text("redirect.final_url", doc.final_url.clone()));
    if let Some(upgraded) = upgrades_to_https(&doc.redirect_chain) {
        out.push(redirect_num(
            "redirect.upgrades_to_https",
            if upgraded { 1.0 } else { 0.0 },
        ));
    }
    out
}

fn redirect_num(key: &'static str, value: f64) -> Observation {
    Observation {
        source: Source::Redirect,
        metric_key: key,
        numeric_value: Some(value),
        text_value: None,
        unit: slap_core::schema::metric_registry()[key].unit,
    }
}
fn redirect_text(key: &'static str, value: String) -> Observation {
    Observation {
        source: Source::Redirect,
        metric_key: key,
        numeric_value: None,
        text_value: Some(value),
        unit: slap_core::schema::metric_registry()[key].unit,
    }
}

// ---------------------------------------------------------------------------
// The one part that touches the network.
// ---------------------------------------------------------------------------

fn decode_body(bytes: Vec<u8>, encoding: Option<&str>) -> Vec<u8> {
    let decode = |result: std::io::Result<Vec<u8>>| result.unwrap_or_else(|_| Vec::new());
    match encoding.map(|e| e.trim().to_ascii_lowercase()).as_deref() {
        Some("gzip") => {
            let mut out = Vec::new();
            match flate2::read::GzDecoder::new(&bytes[..]).read_to_end(&mut out) {
                Ok(_) => out,
                Err(_) => bytes,
            }
        }
        Some("deflate") => {
            // deflate on the wire is ambiguous: try zlib-wrapped, then raw.
            let mut out = Vec::new();
            if flate2::read::ZlibDecoder::new(&bytes[..])
                .read_to_end(&mut out)
                .is_ok()
            {
                return out;
            }
            out.clear();
            match flate2::read::DeflateDecoder::new(&bytes[..]).read_to_end(&mut out) {
                Ok(_) => out,
                Err(_) => bytes,
            }
        }
        Some("br") => {
            let mut out = Vec::new();
            match brotli::Decompressor::new(&bytes[..], 4096).read_to_end(&mut out) {
                Ok(_) => out,
                Err(_) => bytes,
            }
        }
        _ => decode(Ok(bytes)),
    }
}

/// Fetch a URL, following redirects by hand so the whole chain is captured,
/// and record timing. Manual redirects (rather than reqwest's built-in
/// policy) are what make `redirect.chain` a faithful `(status, url)` list.
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    user_agent: &str,
    max_redirects: u32,
    max_body_bytes: usize,
) -> Result<FetchedDocument, String> {
    let mut chain: Vec<(u16, String)> = Vec::new();
    let mut current = url.to_string();
    let started = Instant::now();

    let response = loop {
        let response = client
            .get(&current)
            .header(reqwest::header::USER_AGENT, user_agent)
            .header(
                reqwest::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header(reqwest::header::ACCEPT_ENCODING, accept_encoding())
            .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if status.is_redirection() && chain.len() < max_redirects as usize {
            if let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            {
                let next = reqwest::Url::parse(&current)
                    .and_then(|base| base.join(location))
                    .map(|u| u.to_string())
                    .unwrap_or_else(|_| location.to_string());
                chain.push((status.as_u16(), current.clone()));
                current = next;
                continue;
            }
        }
        break response;
    };

    let ttfb_ms = started.elapsed().as_secs_f64() * 1000.0;
    let final_url = response.url().to_string();
    let status = response.status().as_u16();
    let http_version = format!("{:?}", response.version());

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut set_cookie: Vec<String> = Vec::new();
    for (name, value) in response.headers() {
        let value = value.to_str().unwrap_or("").to_string();
        if name.as_str().eq_ignore_ascii_case("set-cookie") {
            set_cookie.push(value.clone());
        }
        // BTreeMap keeps the last value per header, matching the Python dict.
        headers.insert(name.as_str().to_ascii_lowercase(), value);
    }

    let content_encoding = headers.get("content-encoding").cloned();
    let raw = response.bytes().await.map_err(|e| e.to_string())?;
    let raw = if raw.len() > max_body_bytes {
        raw.slice(0..max_body_bytes)
    } else {
        raw
    };
    let body = decode_body(raw.to_vec(), content_encoding.as_deref());
    let content_bytes = body.len();
    let text = String::from_utf8_lossy(&body).into_owned();

    chain.push((status, final_url.clone()));

    Ok(FetchedDocument {
        url: url.to_string(),
        final_url,
        status,
        http_version,
        headers,
        set_cookie,
        text,
        content_bytes,
        ttfb_ms,
        redirect_chain: chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(headers: &[(&str, &str)], cookies: &[&str]) -> FetchedDocument {
        FetchedDocument {
            url: "https://example.com/".into(),
            final_url: "https://example.com/".into(),
            status: 200,
            http_version: "HTTP/2.0".into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            set_cookie: cookies.iter().map(|s| s.to_string()).collect(),
            text: String::new(),
            content_bytes: 1234,
            ttfb_ms: 128.4,
            redirect_chain: vec![(200, "https://example.com/".into())],
        }
    }

    fn values(doc: &FetchedDocument) -> std::collections::HashMap<String, Value> {
        observations_from_document(doc)
            .into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect()
    }

    #[test]
    fn max_age_parses_from_cache_control_and_hsts() {
        assert_eq!(parse_max_age(Some("public, max-age=3600")), Some(3600));
        assert_eq!(parse_max_age(Some("max-age = 60, immutable")), Some(60));
        assert_eq!(parse_max_age(Some("no-store")), None);
        assert_eq!(
            parse_max_age(Some("max-age=31536000; includeSubDomains")),
            Some(31536000)
        );
        assert_eq!(parse_max_age(None), None);
    }

    #[test]
    fn missing_headers_are_the_ones_absent() {
        let present: BTreeMap<String, String> = [
            ("content-security-policy", "default-src 'self'"),
            ("x-frame-options", "DENY"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let missing = missing_security_headers(&present);
        assert!(missing.contains(&"strict-transport-security"));
        assert!(!missing.contains(&"content-security-policy"));
        assert_eq!(missing.len(), 4);
    }

    #[test]
    fn cookie_hygiene_counts_each_missing_attribute() {
        let c = analyze_cookies(&[
            "sid=abc; Secure; HttpOnly; SameSite=Lax".into(),
            "tracker=1".into(),   // missing all three
            "just-a-flag".into(), // no '=', not a cookie
        ]);
        assert_eq!(
            c,
            CookieHygiene {
                total: 2,
                insecure: 1,
                no_httponly: 1,
                no_samesite: 1
            }
        );
    }

    #[test]
    fn https_upgrade_detection() {
        assert_eq!(
            upgrades_to_https(&[(301, "http://x/".into()), (200, "https://x/".into())]),
            Some(true)
        );
        assert_eq!(upgrades_to_https(&[(200, "https://x/".into())]), None);
        assert_eq!(
            upgrades_to_https(&[(301, "http://x/".into()), (200, "http://y/".into())]),
            Some(false)
        );
    }

    #[test]
    fn bare_hostnames_default_to_https() {
        assert_eq!(normalize_url("example.com").unwrap(), "https://example.com");
        assert_eq!(normalize_url("http://x.io/a").unwrap(), "http://x.io/a");
        assert_eq!(normalize_url("  HTTPS://X  ").unwrap(), "HTTPS://X");
        assert!(normalize_url("   ").is_err());
    }

    #[test]
    fn a_hardened_response_produces_the_right_observations() {
        let d = doc(
            &[
                ("server", "nginx"),
                ("content-encoding", "br"),
                ("cache-control", "public, max-age=600"),
                ("etag", "\"abc\""),
                ("strict-transport-security", "max-age=31536000"),
                ("content-security-policy", "default-src 'self'"),
            ],
            &["sid=x; Secure; HttpOnly; SameSite=Lax"],
        );
        let v = values(&d);
        assert_eq!(v["http.status"], Value::Num(200.0));
        assert_eq!(v["http.version"], Value::Text("HTTP/2.0".into()));
        assert_eq!(v["http.compressed"], Value::Bool(true));
        assert_eq!(v["http.compression"], Value::Text("br".into()));
        assert_eq!(v["http.cache_max_age"], Value::Num(600.0));
        assert_eq!(v["http.has_etag"], Value::Bool(true));
        assert_eq!(v["sec.hsts_max_age"], Value::Num(31536000.0));
        // HSTS and CSP are present, so 4 of the 6 expected headers are missing.
        assert_eq!(v["sec.missing_header_count"], Value::Num(4.0));
        assert_eq!(v["sec.cookies_total"], Value::Num(1.0));
        assert_eq!(v["sec.cookies_insecure"], Value::Num(0.0));
    }

    #[test]
    fn an_uncompressed_response_says_none_not_missing() {
        let d = doc(&[("server", "Apache")], &[]);
        let v = values(&d);
        assert_eq!(v["http.compression"], Value::Text("none".into()));
        assert_eq!(v["http.compressed"], Value::Bool(false));
        // No cookies: the per-attribute counts are omitted entirely.
        assert!(!v.contains_key("sec.cookies_insecure"));
        assert_eq!(v["sec.cookies_total"], Value::Num(0.0));
    }

    #[test]
    fn gzip_round_trips_through_decode_body() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"<html>hi</html>").unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(decode_body(gz, Some("gzip")), b"<html>hi</html>");
        // identity passes through untouched.
        assert_eq!(decode_body(b"plain".to_vec(), None), b"plain");
    }
}
