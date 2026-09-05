//! Active endpoint probing: does the origin serve files it should not?
//! ORIGIN-scoped and strictly opt-in: it runs
//! only for a host the user has explicitly authorised, because unlike every
//! other collector it actively requests sensitive paths rather than reading the
//! page the site already served.
//!
//! Two disciplines carried over make the results trustworthy:
//! - **Confirm by content, not status.** A 200 proves nothing on a site with a
//!   catch-all, so a finding requires the body to match the file it claims to
//!   be: a `.env` is a finding only if it actually contains `.env` keys.
//! - **Detect the two ways a probe lies.** A soft-404 (success for every path)
//!   makes the absence of findings weak evidence, and a web application
//!   firewall answering instead of the origin makes every path look identical.
//!   Both are detected: the soft-404 is disclosed, and a WAF stops the probe
//!   rather than letting it report a wall of identical block pages as findings.

use std::collections::BTreeMap;
use std::time::Duration;

use slap_core::schema::{obs, Observation, Value};

use crate::crux::TokenBucket;

/// A path that cannot exist on a normal site, used to learn how the origin
/// answers a request for something missing (a real 404, a soft-404 success, or
/// a firewall block).
const CONTROL_PATH: &str = "/slap-probe-control-6f1b9c2e4a.html";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    Secrets,
    Vcs,
    Info,
    WpSurface,
}

/// (path, body signatures). A hit needs a success status AND a signature, so a
/// soft-404 HTML page is never mistaken for the real file. Signatures are the
/// strings the genuine file contains, checked case-insensitively.
const SECRETS: &[(&str, &[&str])] = &[
    ("/.env", &["db_password", "app_key", "secret", "app_env", "database_url"]),
    ("/.env.local", &["db_password", "app_key", "secret"]),
    ("/.env.bak", &["db_password", "app_key", "secret"]),
    ("/wp-config.php.bak", &["db_password", "db_name", "auth_key"]),
    ("/wp-config.php~", &["db_password", "db_name", "auth_key"]),
    ("/config.php.bak", &["password", "mysql", "define("]),
    ("/.htpasswd", &[":$apr1$", ":$2y$", ":{sha}"]),
    ("/backup.sql", &["insert into", "create table", "drop table"]),
    ("/database.sql", &["insert into", "create table"]),
    ("/dump.sql", &["insert into", "create table"]),
];

const VCS: &[(&str, &[&str])] = &[
    ("/.git/HEAD", &["ref:", "refs/heads"]),
    ("/.git/config", &["[core]", "repositoryformatversion"]),
    ("/.svn/wc.db", &["sqlite format", "svn"]),
    ("/.hg/requires", &["revlogv1", "store", "dotencode"]),
];

const INFO: &[(&str, &[&str])] = &[
    ("/phpinfo.php", &["phpinfo()", "php version", "php_uname"]),
    ("/info.php", &["phpinfo()", "php version"]),
    ("/server-status", &["apache server status", "server uptime"]),
    ("/server-info", &["apache server information", "server settings"]),
];

const WP_SURFACE: &[(&str, &[&str])] = &[
    (
        "/xmlrpc.php",
        &["xml-rpc server accepts post requests only", "methodresponse", "faultcode"],
    ),
    ("/wp-json/wp/v2/users", &["\"slug\"", "\"id\":", "\"name\""]),
];

/// Firewall block-page signatures. A WAF answering the probe makes every path
/// look the same, so it is detected and the probe stops.
const WAF_BODY: &[&str] = &[
    "cloudflare",
    "attention required",
    "access denied",
    "web application firewall",
    "request unsuccessful",
    "incapsula",
    "sucuri",
    "mod_security",
    "you have been blocked",
    "ddos protection",
];

/// One probe response: the status, lowercased headers, and a body prefix.
pub type Resp = (u16, BTreeMap<String, String>, String);

#[derive(Clone)]
pub struct ProbeConfig {
    pub rate_per_second: f64,
    pub timeout: Duration,
    pub user_agent: String,
}

/// A probe category paired with its table of (path, body signatures).
type CategoryTable = (Category, &'static [(&'static str, &'static [&'static str])]);

fn categories() -> [CategoryTable; 4] {
    [
        (Category::Secrets, SECRETS),
        (Category::Vcs, VCS),
        (Category::Info, INFO),
        (Category::WpSurface, WP_SURFACE),
    ]
}

/// A success status whose body proves it is the file it claims to be.
fn confirmed(resp: &Resp, signatures: &[&str]) -> bool {
    let (status, _, body) = resp;
    if !(200..300).contains(status) {
        return false;
    }
    let body = body.to_ascii_lowercase();
    signatures.iter().any(|s| body.contains(s))
}

/// A firewall answered instead of the origin.
fn is_waf(resp: &Resp) -> bool {
    let (status, headers, body) = resp;
    let blocky = matches!(status, 403 | 406 | 429 | 503);
    let body = body.to_ascii_lowercase();
    let body_sig = WAF_BODY.iter().any(|s| body.contains(s));
    let header_block = headers.contains_key("x-sucuri-block")
        || headers
            .get("server")
            .map(|s| s.to_ascii_lowercase().contains("sucuri"))
            .unwrap_or(false);
    (blocky && body_sig) || header_block
}

fn count_key(c: Category) -> &'static str {
    match c {
        Category::Secrets => "exposure.secrets_count",
        Category::Vcs => "exposure.vcs_count",
        Category::Info => "exposure.info_count",
        Category::WpSurface => "exposure.wp_surface_count",
    }
}

fn paths_key(c: Category) -> &'static str {
    match c {
        Category::Secrets => "exposure.secrets_paths",
        Category::Vcs => "exposure.vcs_paths",
        Category::Info => "exposure.info_paths",
        Category::WpSurface => "exposure.wp_surface_paths",
    }
}

/// Pure: turn the control response and the category probe results into the
/// `exposure.*` observations. Separated from the network so the whole judgement
/// (soft-404, WAF, content-confirmation) is unit-testable. `checked` is the
/// number of paths actually requested.
pub fn observations_from_probe(
    checked: usize,
    control: Option<&Resp>,
    results: &[(Category, &str, Option<Resp>)],
) -> Vec<Observation> {
    let mut out = Vec::new();
    let mut push = |key: &str, value: Value| {
        if let Ok(o) = obs(key, value) {
            out.push(o);
        }
    };
    push("exposure.authorised", Value::Bool(true));
    push("exposure.checked", Value::Num(checked as f64));

    // The control probe: a success means the site 200s for anything (soft-404);
    // a firewall block means a WAF is in front of the origin.
    let mut waf = false;
    if let Some(control) = control {
        push("exposure.control_status", Value::Num(control.0 as f64));
        if is_waf(control) {
            waf = true;
        } else if (200..300).contains(&control.0) {
            push("exposure.soft_404", Value::Bool(true));
        }
    }
    if !waf && results.iter().any(|(_, _, r)| r.as_ref().is_some_and(is_waf)) {
        waf = true;
    }
    if waf {
        // A WAF makes every path look identical; reporting those as findings
        // would be wrong. Disclose it and stop, per probe-blocked-by-firewall.
        push("exposure.waf_detected", Value::Bool(true));
        return out;
    }

    let mut all_paths: Vec<String> = Vec::new();
    for (category, _) in categories() {
        let found: Vec<&str> = results
            .iter()
            .filter(|(c, _, _)| *c == category)
            .filter_map(|(_, path, resp)| {
                let resp = resp.as_ref()?;
                let signatures = signatures_for(category, path)?;
                confirmed(resp, signatures).then_some(*path)
            })
            .collect();
        if !found.is_empty() {
            push(count_key(category), Value::Num(found.len() as f64));
            push(paths_key(category), Value::from(found.join(", ")));
            all_paths.extend(found.iter().map(|p| p.to_string()));
        }
    }
    if !all_paths.is_empty() {
        push("exposure.found_count", Value::Num(all_paths.len() as f64));
        push("exposure.paths", Value::from(all_paths.join(", ")));
    }
    out
}

fn signatures_for(category: Category, path: &str) -> Option<&'static [&'static str]> {
    categories()
        .iter()
        .find(|(c, _)| *c == category)
        .and_then(|(_, table)| table.iter().find(|(p, _)| *p == path).map(|(_, s)| *s))
}

/// Fetch one path, returning its status, lowercased headers, and a bounded body
/// prefix (enough to confirm a signature, not the whole file).
async fn fetch_path(client: &reqwest::Client, url: &str, cfg: &ProbeConfig) -> Option<Resp> {
    let resp = client
        .get(url)
        .header(reqwest::header::USER_AGENT, &cfg.user_agent)
        .timeout(cfg.timeout)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let bytes = resp.bytes().await.ok()?;
    let end = bytes.len().min(16_384);
    let body = String::from_utf8_lossy(&bytes[..end]).to_string();
    Some((status, headers, body))
}

/// Probe an authorised origin's sensitive paths and return the `exposure.*`
/// observations. Rate-limited, and stops the moment a firewall is detected.
pub async fn probe(client: &reqwest::Client, origin: &str, cfg: &ProbeConfig) -> Vec<Observation> {
    let bucket = TokenBucket::new(cfg.rate_per_second.max(0.1));

    bucket.acquire().await;
    let control = fetch_path(client, &format!("{origin}{CONTROL_PATH}"), cfg).await;
    let mut checked = 1;

    // If the control probe already shows a firewall, do not hammer the host.
    let control_is_waf = control.as_ref().is_some_and(is_waf);

    let mut results: Vec<(Category, &str, Option<Resp>)> = Vec::new();
    if !control_is_waf {
        'outer: for (category, table) in categories() {
            for (path, _) in table {
                bucket.acquire().await;
                let resp = fetch_path(client, &format!("{origin}{path}"), cfg).await;
                checked += 1;
                let hit_waf = resp.as_ref().is_some_and(is_waf);
                results.push((category, path, resp));
                if hit_waf {
                    break 'outer;
                }
            }
        }
    }

    observations_from_probe(checked, control.as_ref(), &results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Resp {
        (status, BTreeMap::new(), body.to_string())
    }
    fn values(obs: Vec<Observation>) -> std::collections::HashMap<String, Value> {
        obs.into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect()
    }

    #[test]
    fn a_real_env_file_is_confirmed_by_content_not_status() {
        let hit = resp(200, "APP_KEY=base64:xxxx\nDB_PASSWORD=hunter2\n");
        assert!(confirmed(&hit, SECRETS[0].1));
        // A 200 that is really the site's HTML 404 page is NOT a finding.
        let soft = resp(200, "<!doctype html><title>Page not found</title>");
        assert!(!confirmed(&soft, SECRETS[0].1));
        // A 404 with the right words is not reachable, so not a finding.
        let missing = resp(404, "APP_KEY DB_PASSWORD");
        assert!(!confirmed(&missing, SECRETS[0].1));
    }

    #[test]
    fn a_firewall_block_is_recognised() {
        let block = (
            403u16,
            BTreeMap::new(),
            "Attention Required! | Cloudflare".to_string(),
        );
        assert!(is_waf(&block));
        // A normal 403 without a firewall signature is just a 403.
        assert!(!is_waf(&resp(403, "Forbidden")));
    }

    #[test]
    fn a_soft_404_site_is_disclosed_but_content_findings_still_stand() {
        let control = resp(200, "<html>our friendly 404 page</html>");
        let results = vec![
            (Category::Secrets, "/.env", Some(resp(200, "APP_KEY=x\nDB_PASSWORD=y"))),
            (
                Category::Vcs,
                "/.git/HEAD",
                Some(resp(200, "<html>friendly 404</html>")),
            ),
        ];
        let v = values(observations_from_probe(3, Some(&control), &results));
        assert_eq!(v["exposure.soft_404"], Value::Bool(true));
        // The .env matched by content; the .git/HEAD (soft-404 HTML) did not.
        assert_eq!(v["exposure.secrets_count"], Value::Num(1.0));
        assert!(!v.contains_key("exposure.vcs_count"));
        assert_eq!(v["exposure.found_count"], Value::Num(1.0));
    }

    #[test]
    fn a_waf_stops_the_probe_and_reports_no_exposures() {
        let control = (
            403u16,
            BTreeMap::new(),
            "Access Denied - Web Application Firewall".to_string(),
        );
        // Even if a later result "matched", a WAF means we trust none of it.
        let results = vec![(Category::Secrets, "/.env", Some(resp(200, "APP_KEY=x DB_PASSWORD=y")))];
        let v = values(observations_from_probe(2, Some(&control), &results));
        assert_eq!(v["exposure.waf_detected"], Value::Bool(true));
        assert!(!v.contains_key("exposure.secrets_count"));
        assert!(!v.contains_key("exposure.found_count"));
    }

    #[test]
    fn a_clean_site_reports_it_was_checked_and_found_nothing() {
        let control = resp(404, "not found");
        let results = vec![
            (Category::Secrets, "/.env", Some(resp(404, "nope"))),
            (Category::WpSurface, "/xmlrpc.php", Some(resp(405, "method not allowed"))),
        ];
        let v = values(observations_from_probe(3, Some(&control), &results));
        assert_eq!(v["exposure.authorised"], Value::Bool(true));
        assert_eq!(v["exposure.checked"], Value::Num(3.0));
        assert_eq!(v["exposure.control_status"], Value::Num(404.0));
        assert!(!v.contains_key("exposure.found_count"));
        assert!(!v.contains_key("exposure.soft_404"));
    }

    #[test]
    fn xmlrpc_and_the_users_endpoint_are_wordpress_surface() {
        let control = resp(404, "not found");
        let results = vec![
            (
                Category::WpSurface,
                "/xmlrpc.php",
                Some(resp(200, "XML-RPC server accepts POST requests only.")),
            ),
            (
                Category::WpSurface,
                "/wp-json/wp/v2/users",
                Some(resp(200, r#"[{"id":1,"name":"admin","slug":"admin"}]"#)),
            ),
        ];
        let v = values(observations_from_probe(3, Some(&control), &results));
        assert_eq!(v["exposure.wp_surface_count"], Value::Num(2.0));
    }

    /// The observations must drive the shipped exposure rules, or none of this
    /// reaches a report.
    #[test]
    fn the_findings_engine_fires_the_exposure_rules() {
        use slap_core::findings::FindingsEngine;
        let engine = FindingsEngine::load(None).expect("embedded rules load");
        let control = resp(404, "not found");
        let results = vec![
            (Category::Secrets, "/.env", Some(resp(200, "APP_KEY=x\nDB_PASSWORD=y"))),
            (Category::Vcs, "/.git/HEAD", Some(resp(200, "ref: refs/heads/main"))),
        ];
        let values: std::collections::HashMap<String, Value> =
            observations_from_probe(3, Some(&control), &results)
                .iter()
                .map(|o| (o.metric_key.to_string(), o.value()))
                .collect();
        let ids: Vec<String> = engine
            .run(&values)
            .unwrap()
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert!(ids.iter().any(|id| id == "exposed-secrets"), "got {ids:?}");
        assert!(ids.iter().any(|id| id == "exposed-vcs"), "got {ids:?}");
    }
}
