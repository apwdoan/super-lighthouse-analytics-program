//! In-app regeneration of the vulnerability database from the NIST NVD.
//!
//! The Rust port of `scripts/build-vulndb.mjs`, so the packaged app can refresh
//! its CVE data with no Node, no repo, and no command line. It queries the NVD
//! 2.0 REST API by CPE for exactly the components the detector recognises,
//! extracts affected version ranges and CVSS severity, and returns the JSON the
//! matcher reads. The shell writes that JSON to the user data directory and
//! hot-swaps it into [`crate::vulndb`].
//!
//! The design decisions and their rationale live in the project doc
//! `vulndb-nvd-generator.md`; the load-bearing ones, repeated where they bite:
//!   - Every target is an explicit NVD `vendor:product` pair (or several).
//!     NVD's product names almost never equal a plugin's slug, so the pairs are
//!     data, discovered from real CVEs, not derived. A wrong pair returns
//!     nothing; it can widen a gap, never invent a match.
//!   - Matching is on `vendor:product` alone, not constrained to
//!     `target_sw=wordpress`: several plugins carry rows with an unset
//!     `target_sw`, and requiring it silently dropped them.
//!   - A row with neither a concrete version nor a range means "all versions";
//!     matching every detected version off it is how a vague CVE becomes a page
//!     of false positives, so it is dropped.
//!   - No silent shrinkage: a covered package that returns fewer CVEs than the
//!     database being replaced fails the build (NVD rate-limits by answering,
//!     not refusing).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value as Json;

// --- What the detector recognises, mapped to NVD CPEs ---------------------
//
// These mirror the maps in components.rs (the npm libraries and the plugin
// slugs) and must stay in step with them: the key is what the detector emits,
// the value is the NVD `vendor:product` pair(s) that key's software appears
// under. Kept identical to scripts/build-vulndb.mjs.

const NPM: &[(&str, &[&str])] = &[
    ("jquery", &["jquery:jquery"]),
    ("jquery-ui", &["jqueryui:jquery_ui"]),
    ("bootstrap", &["getbootstrap:bootstrap"]),
    ("angular", &["angular:angular", "google:angularjs", "angularjs:angular.js"]),
    ("react", &["facebook:react"]),
    ("lodash", &["lodash:lodash"]),
    ("underscore", &["underscorejs:underscore", "jashkenas:underscore.js"]),
    ("moment", &["momentjs:moment"]),
    ("handlebars", &["handlebarsjs:handlebars"]),
    ("knockout", &["knockoutjs:knockout"]),
    ("highcharts", &["highcharts:highcharts", "highsoft:highcharts"]),
    ("socket.io", &["socket:socket.io", "socketio:socket.io"]),
    ("dojo", &["dojotoolkit:dojo", "dojofoundation:dojo"]),
    ("yui", &["yahoo:yui"]),
    ("next", &["vercel:next.js", "zeit:next.js"]),
];

const WORDPRESS: &[(&str, &[&str])] = &[("wordpress", &["wordpress:wordpress"])];

const WP_PLUGINS: &[(&str, &[&str])] = &[
    // The originally-covered twelve.
    ("akismet", &["automattic:akismet"]),
    ("contact-form-7", &["rocklobster:contact_form_7"]),
    ("elementor", &["elementor:website_builder"]),
    ("gutenberg", &["wordpress:gutenberg"]),
    ("jetpack", &["automattic:jetpack"]),
    ("litespeed-cache", &["litespeedtech:litespeed_cache"]),
    ("w3-total-cache", &["boldgrid:w3_total_cache"]),
    ("woocommerce", &["woocommerce:woocommerce"]),
    ("wordpress-seo", &["yoast:yoast_seo"]),
    ("wp-super-cache", &["automattic:wp_super_cache"]),
    ("wpforms", &["wpforms:wpforms"]),
    ("wpforms-lite", &["wpforms:wpforms"]),
    // Expanded coverage, each product pinned from real NVD CVEs.
    ("advanced-custom-fields", &["advancedcustomfields:advanced_custom_fields"]),
    (
        "all-in-one-seo-pack",
        &["semperfiwebdesign:all_in_one_seo_pack", "semperplugins:all_in_one_seo_pack"],
    ),
    ("all-in-one-wp-migration", &["servmask:all-in-one_wp_migration"]),
    ("autoptimize", &["autoptimize:autoptimize"]),
    ("backwpup", &["inpsyde:backwpup"]),
    ("better-wp-security", &["ithemes:ithemes_security", "ithemes:security"]),
    (
        "broken-link-checker",
        &["broken_link_checker_project:broken_link_checker", "managewp:broken_link_checker"],
    ),
    ("cloudflare", &["cloudflare:cloudflare"]),
    ("code-snippets", &["codesnippets:code_snippets", "code_snippets:code_snippets"]),
    (
        "duplicate-post",
        &["duplicate_post_project:duplicate_post", "copy-delete-posts:duplicate_post"],
    ),
    ("essential-addons-for-elementor-lite", &["wpdeveloper:essential_addons_for_elementor"]),
    ("forminator", &["incsub:forminator"]),
    ("google-analytics-for-wordpress", &["monsterinsights:monsterinsights"]),
    ("limit-login-attempts-reloaded", &["limitloginattempts:limit_login_attempts_reloaded"]),
    ("loginizer", &["loginizer:loginizer"]),
    ("mailchimp-for-wp", &["ibericode:mailchimp_for_wordpress"]),
    ("ninja-forms", &["ninjaforms:ninja_forms"]),
    ("popup-maker", &["code-atlantic:popup_maker"]),
    ("redirection", &["redirection_project:redirection", "redirection:redirection"]),
    ("revslider", &["themepunch:slider_revolution"]),
    ("seo-by-rank-math", &["rankmath:seo", "rankmath:seo_pro"]),
    ("shortpixel-image-optimiser", &["shortpixel:image_optimizer"]),
    ("sucuri-scanner", &["sucuri:security"]),
    ("tablepress", &["tablepress:tablepress"]),
    ("updraftplus", &["updraftplus:updraftplus"]),
    ("wordfence", &["wordfence:wordfence"]),
    ("wp-fastest-cache", &["wpfastestcache:wp_fastest_cache"]),
    ("wp-google-maps", &["codecabin:wp_go_maps", "wpgmaps:wp_go_maps"]),
    ("wp-mail-smtp", &["wpforms:wp_mail_smtp"]),
    ("wp-optimize", &["updraftplus:wp-optimize"]),
    ("wp-smushit", &["wpmudev:smush_image_compression_and_optimization"]),
    (
        "wp-statistics",
        &["wp-statistics:wp_statistics", "wp_statistics:wp_statistics", "veronalabs:wp_statistics"],
    ),
];

/// A progress tick, handed to the caller's closure before each package is
/// queried so a long unauthenticated run (~10 minutes) shows movement.
pub struct Progress {
    pub done: usize,
    pub total: usize,
    pub label: String,
}

/// The finished database and the numbers the settings screen reports.
pub struct BuildOutcome {
    pub json: String,
    pub cve_count: usize,
    pub covered: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    pub generated_at: String,
}

#[derive(Serialize)]
struct RangeOut {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Serialize)]
struct VulnOut {
    id: String,
    ecosystem: String,
    package: String,
    severity: String,
    versions: Vec<String>,
    ranges: Vec<RangeOut>,
}

struct Merged {
    severity: String,
    versions: BTreeSet<String>,
    ranges: Vec<RangeOut>,
}

/// Build the database. `baseline` is the active database's per-package counts,
/// the shrink guard; `on_progress` is called once per package. Errors are
/// human-readable, surfaced to the settings screen verbatim.
pub async fn build<F: FnMut(Progress)>(
    api_key: Option<String>,
    baseline: &BTreeMap<(String, String), usize>,
    mut on_progress: F,
) -> Result<BuildOutcome, String> {
    let client = reqwest::Client::builder()
        .user_agent("SLAP/0.1 (vulndb generator)")
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("could not start an HTTP client: {e}"))?;
    // NVD allows 5 requests / 30s without a key, 50 with. Pace conservatively.
    let delay = Duration::from_millis(if api_key.is_some() { 900 } else { 6500 });

    let mut targets: Vec<(&str, &str, &[&str])> = Vec::new();
    for (pkg, cands) in NPM {
        targets.push(("npm", pkg, cands));
    }
    for (pkg, cands) in WORDPRESS {
        targets.push(("wordpress", pkg, cands));
    }
    for (pkg, cands) in WP_PLUGINS {
        targets.push(("wordpress-plugin", pkg, cands));
    }
    let total = targets.len();

    let mut vulnerabilities: Vec<VulnOut> = Vec::new();
    let mut covered: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for eco in ["npm", "wordpress", "wordpress-plugin"] {
        covered.insert(eco.to_string(), Vec::new());
    }
    let mut degraded: Vec<String> = Vec::new();

    for (index, (eco, pkg, candidates)) in targets.iter().enumerate() {
        on_progress(Progress {
            done: index,
            total,
            label: (*pkg).to_string(),
        });
        let entries = collect_package(&client, api_key.as_deref(), eco, pkg, candidates, delay)
            .await
            .map_err(|e| format!("{eco}/{pkg}: {e}"))?;
        let before = baseline
            .get(&((*eco).to_string(), (*pkg).to_string()))
            .copied()
            .unwrap_or(0);
        if entries.len() < before {
            degraded.push(format!("{eco}/{pkg}: {} < {before}", entries.len()));
        }
        if !entries.is_empty() {
            covered.get_mut(*eco).unwrap().push((*pkg).to_string());
            vulnerabilities.extend(entries);
        }
    }

    if !degraded.is_empty() {
        return Err(format!(
            "Refusing to save a smaller database than the current one. These covered \
             packages came back with fewer CVEs, usually NVD rate-limiting; try again:\n  {}",
            degraded.join("\n  ")
        ));
    }

    for list in covered.values_mut() {
        list.sort();
        list.dedup();
    }
    vulnerabilities.sort_by(|a, b| {
        a.ecosystem
            .cmp(&b.ecosystem)
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.id.cmp(&b.id))
    });

    let cve_count = vulnerabilities.len();
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for v in &vulnerabilities {
        *by_severity.entry(v.severity.clone()).or_insert(0) += 1;
    }
    let generated_at = now_rfc3339();

    let db = serde_json::json!({
        "schema": 1,
        "generated_at": generated_at,
        "sources": {
            "npm": "NIST NVD",
            "wordpress": "NIST NVD",
            "wordpress-plugin": "NIST NVD",
        },
        "covered_packages": covered,
        "vulnerabilities": vulnerabilities,
    });
    let json = serde_json::to_string_pretty(&db)
        .map_err(|e| format!("could not serialise the database: {e}"))?
        + "\n";

    let covered_counts = {
        let mut m = BTreeMap::new();
        if let Some(obj) = db["covered_packages"].as_object() {
            for (eco, list) in obj {
                m.insert(eco.clone(), list.as_array().map(Vec::len).unwrap_or(0));
            }
        }
        m
    };

    on_progress(Progress {
        done: total,
        total,
        label: "done".to_string(),
    });

    Ok(BuildOutcome {
        json,
        cve_count,
        covered: covered_counts,
        by_severity,
        generated_at,
    })
}

/// All CVEs for one package across its candidate CPEs, a CVE seen under more
/// than one candidate merged into a single entry.
async fn collect_package(
    client: &reqwest::Client,
    api_key: Option<&str>,
    ecosystem: &str,
    package: &str,
    candidates: &[&str],
    delay: Duration,
) -> Result<Vec<VulnOut>, String> {
    let mut by_id: BTreeMap<String, Merged> = BTreeMap::new();
    for cpe in candidates {
        let Some((vendor, product)) = cpe.split_once(':') else {
            continue;
        };
        let vms = format!("cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*");
        let cves = fetch_all(client, api_key, &vms, delay).await?;
        for cve in &cves {
            let (versions, ranges) = extract(cve, vendor, product);
            if versions.is_empty() && ranges.is_empty() {
                continue;
            }
            let id = cve
                .get("id")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_string();
            if id.is_empty() {
                continue;
            }
            let entry = by_id.entry(id).or_insert_with(|| Merged {
                severity: severity_of(cve.get("metrics").unwrap_or(&Json::Null)),
                versions: BTreeSet::new(),
                ranges: Vec::new(),
            });
            entry.versions.extend(versions);
            entry.ranges.extend(ranges);
        }
        tokio_sleep(delay).await;
    }

    Ok(by_id
        .into_iter()
        .map(|(id, m)| VulnOut {
            id,
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            severity: m.severity,
            versions: m.versions.into_iter().collect(),
            ranges: dedupe_ranges(m.ranges),
        })
        .collect())
}

/// Every CVE affecting the CPE match string, across pages.
async fn fetch_all(
    client: &reqwest::Client,
    api_key: Option<&str>,
    vms: &str,
    delay: Duration,
) -> Result<Vec<Json>, String> {
    let mut index = 0usize;
    let mut out = Vec::new();
    loop {
        let page = nvd(client, api_key, vms, index).await?;
        if let Some(items) = page.get("vulnerabilities").and_then(Json::as_array) {
            for item in items {
                if let Some(cve) = item.get("cve") {
                    out.push(cve.clone());
                }
            }
        }
        let total = page.get("totalResults").and_then(Json::as_u64).unwrap_or(0) as usize;
        let per_page = page
            .get("resultsPerPage")
            .and_then(Json::as_u64)
            .unwrap_or(2000) as usize;
        index += per_page.max(1);
        if index >= total {
            return Ok(out);
        }
        tokio_sleep(delay).await;
    }
}

/// One NVD page, retrying its rate-limit (403/429) and any gateway/server 5xx,
/// plus a dropped connection, the same way the script does.
async fn nvd(
    client: &reqwest::Client,
    api_key: Option<&str>,
    vms: &str,
    start_index: usize,
) -> Result<Json, String> {
    let start = start_index.to_string();
    let query = [
        ("virtualMatchString", vms),
        ("resultsPerPage", "2000"),
        ("startIndex", start.as_str()),
    ];
    for attempt in 0..6u32 {
        let mut req = client
            .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
            .query(&query);
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return resp
                        .json::<Json>()
                        .await
                        .map_err(|e| format!("NVD returned unreadable JSON: {e}"));
                }
                let code = status.as_u16();
                if (code == 403 || code == 429 || code >= 500) && attempt < 5 {
                    tokio_sleep(Duration::from_secs(20 * (attempt as u64 + 1))).await;
                    continue;
                }
                return Err(format!("NVD responded {code}"));
            }
            Err(e) => {
                if attempt < 5 {
                    tokio_sleep(Duration::from_secs(20 * (attempt as u64 + 1))).await;
                    continue;
                }
                return Err(format!("could not reach NVD: {e}"));
            }
        }
    }
    Err("NVD did not respond after retries".to_string())
}

/// The versions and ranges a CVE names for one `vendor:product`. Only rows
/// whose vendor AND product match are kept.
fn extract(cve: &Json, vendor: &str, product: &str) -> (Vec<String>, Vec<RangeOut>) {
    let mut versions = BTreeSet::new();
    let mut ranges = Vec::new();
    let configs = cve.get("configurations").and_then(Json::as_array);
    for conf in configs.into_iter().flatten() {
        let nodes = conf.get("nodes").and_then(Json::as_array);
        for node in nodes.into_iter().flatten() {
            let matches = node.get("cpeMatch").and_then(Json::as_array);
            for m in matches.into_iter().flatten() {
                if m.get("vulnerable").and_then(Json::as_bool) != Some(true) {
                    continue;
                }
                let criteria = m.get("criteria").and_then(Json::as_str).unwrap_or("");
                let parts: Vec<&str> = criteria.split(':').collect();
                if parts.len() < 6 {
                    continue;
                }
                if parts[3] != vendor || parts[4] != product {
                    continue;
                }
                let str_field = |k: &str| m.get(k).and_then(Json::as_str).filter(|s| !s.is_empty());
                let start_incl = str_field("versionStartIncluding");
                let start_excl = str_field("versionStartExcluding");
                let end_incl = str_field("versionEndIncluding");
                let end_excl = str_field("versionEndExcluding");
                let has_range =
                    start_incl.is_some() || start_excl.is_some() || end_incl.is_some() || end_excl.is_some();
                if has_range {
                    ranges.push(RangeOut {
                        introduced: start_incl.or(start_excl).map(str::to_string),
                        fixed: end_excl.map(str::to_string),
                        last_affected: end_incl.map(str::to_string),
                    });
                } else {
                    let version = parts[5];
                    if !version.is_empty() && version != "*" && version != "-" {
                        versions.insert(version.replace('\\', ""));
                    }
                }
            }
        }
    }
    (versions.into_iter().collect(), ranges)
}

/// The CVSS base-severity word, read v3.1 -> v3.0 -> v2 (it lives in a
/// different place across the metric versions), lowercased.
fn severity_of(metrics: &Json) -> String {
    let word = |key: &str| -> Option<String> {
        let first = metrics.get(key)?.as_array()?.first()?;
        first
            .get("cvssData")
            .and_then(|d| d.get("baseSeverity"))
            .and_then(Json::as_str)
            .or_else(|| first.get("baseSeverity").and_then(Json::as_str))
            .map(|s| s.to_string())
    };
    word("cvssMetricV31")
        .or_else(|| word("cvssMetricV30"))
        .or_else(|| word("cvssMetricV2"))
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn dedupe_ranges(ranges: Vec<RangeOut>) -> Vec<RangeOut> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in ranges {
        let key = format!(
            "{}|{}|{}",
            r.introduced.as_deref().unwrap_or(""),
            r.fixed.as_deref().unwrap_or(""),
            r.last_affected.as_deref().unwrap_or("")
        );
        if seen.insert(key) {
            out.push(r);
        }
    }
    out
}

async fn tokio_sleep(d: Duration) {
    tokio::time::sleep(d).await;
}

/// The current UTC instant as `YYYY-MM-DDTHH:MM:SS+00:00`, full-precision so a
/// regeneration is always ordered after the embedded build it supersedes (see
/// `vulndb::activate_if_newer`, which compares these as strings). No datetime
/// dependency: it is civil-date arithmetic on the Unix timestamp.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}+00:00")
}

/// Civil date from a count of days since 1970-01-01 (Howard Hinnant's
/// algorithm, the inverse of `vulndb::days_from_civil`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cve() -> Json {
        // Shaped like a real NVD `cve`: one range row and two exact-version
        // rows for jquery:jquery, plus a row for a different product that must
        // be ignored, and an all-versions wildcard row that must be dropped.
        serde_json::json!({
            "id": "CVE-2011-4969",
            "metrics": { "cvssMetricV31": [ { "cvssData": { "baseSeverity": "MEDIUM" } } ] },
            "configurations": [ { "nodes": [ { "cpeMatch": [
                { "vulnerable": true, "criteria": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
                  "versionEndIncluding": "1.6.2" },
                { "vulnerable": true, "criteria": "cpe:2.3:a:jquery:jquery:1.6:*:*:*:*:*:*:*" },
                { "vulnerable": true, "criteria": "cpe:2.3:a:jquery:jquery:1.6.1:*:*:*:*:*:*:*" },
                { "vulnerable": true, "criteria": "cpe:2.3:a:someone:other:2.0:*:*:*:*:*:*:*" },
                { "vulnerable": true, "criteria": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*" }
            ] } ] } ]
        })
    }

    #[test]
    fn extract_keeps_matching_versions_and_ranges_and_drops_the_rest() {
        let cve = sample_cve();
        let (versions, ranges) = extract(&cve, "jquery", "jquery");
        assert_eq!(versions, vec!["1.6".to_string(), "1.6.1".to_string()]);
        assert_eq!(ranges.len(), 1, "one range row; the all-versions wildcard is dropped");
        assert_eq!(ranges[0].last_affected.as_deref(), Some("1.6.2"));
        assert!(ranges[0].fixed.is_none());
        // A product the CVE does not name yields nothing.
        let (v2, r2) = extract(&cve, "someone", "nonexistent");
        assert!(v2.is_empty() && r2.is_empty());
    }

    #[test]
    fn severity_reads_v31_then_falls_back() {
        let m = serde_json::json!({ "cvssMetricV31": [ { "cvssData": { "baseSeverity": "CRITICAL" } } ] });
        assert_eq!(severity_of(&m), "critical");
        let m = serde_json::json!({ "cvssMetricV2": [ { "baseSeverity": "HIGH" } ] });
        assert_eq!(severity_of(&m), "high", "falls back to v2 where the word sits at top level");
        assert_eq!(severity_of(&serde_json::json!({})), "unknown");
    }

    #[test]
    fn a_start_and_end_become_an_introduced_fixed_range() {
        let cve = serde_json::json!({
            "id": "CVE-2024-0001",
            "configurations": [ { "nodes": [ { "cpeMatch": [
                { "vulnerable": true, "criteria": "cpe:2.3:a:elementor:website_builder:*:*:*:*:*:wordpress:*:*",
                  "versionStartIncluding": "3.3.0", "versionEndExcluding": "3.18.2" }
            ] } ] } ]
        });
        let (versions, ranges) = extract(&cve, "elementor", "website_builder");
        assert!(versions.is_empty());
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].introduced.as_deref(), Some("3.3.0"));
        assert_eq!(ranges[0].fixed.as_deref(), Some("3.18.2"));
        assert!(ranges[0].last_affected.is_none());
    }

    #[test]
    fn the_timestamp_is_full_precision_rfc3339() {
        // Epoch 0 is the reference; the format must sort as a string.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        let now = now_rfc3339();
        assert_eq!(now.len(), 25, "YYYY-MM-DDTHH:MM:SS+00:00");
        assert!(now.ends_with("+00:00") && now.contains('T'));
    }

    #[test]
    fn the_maps_cover_the_expected_counts() {
        assert_eq!(NPM.len(), 15);
        assert_eq!(WP_PLUGINS.len(), 44);
        // Every candidate is a well-formed vendor:product pair.
        for (_, cands) in NPM.iter().chain(WP_PLUGINS).chain(WORDPRESS) {
            for c in *cands {
                assert!(c.split(':').count() == 2, "candidate {c} must be vendor:product");
            }
        }
    }
}
