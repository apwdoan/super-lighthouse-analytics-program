//! The offline vulnerability database and the matcher over it.
//!
//! The database is `desktop/data/vulndb.json`, embedded at compile time so
//! the app ships with it and the build-time refresh (CI) updates it in place.
//! It carries, per ecosystem, the packages it covers and the CVEs affecting
//! specific versions or version ranges, all sourced from the NIST NVD.
//!
//! The matcher's one hard rule: a version that
//! was only INFERRED (from a `?ver=` asset string) can never produce a
//! confirmed finding, and above all never a confirmed critical. A confidently
//! wrong critical in a client report is the worst thing this tool can print,
//! so the asymmetry is deliberate: an inferred hit is reported as "possible",
//! never "confirmed".

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, OnceLock, RwLock};

use serde::Deserialize;
use slap_core::schema::{obs, Observation, Value};

use crate::components::{Component, Confidence};

const VULNDB_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/vulndb.json"));

#[derive(Debug, Deserialize)]
struct Range {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Vuln {
    pub id: String,
    pub ecosystem: String,
    pub package: String,
    pub severity: String,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
struct RawDb {
    covered_packages: BTreeMap<String, Vec<String>>,
    generated_at: String,
    #[serde(default)]
    sources: BTreeMap<String, String>,
    vulnerabilities: Vec<Vuln>,
}

/// The parsed database: which packages each ecosystem covers, the CVEs indexed
/// by the package they affect, and the provenance a report has to show.
pub struct VulnDb {
    covered: BTreeMap<String, BTreeSet<String>>,
    generated_at: String,
    sources: BTreeMap<String, String>,
    by_package: HashMap<(String, String), Vec<Vuln>>,
}

/// The active database, behind a lock so the in-app regenerator can swap in a
/// freshly-built one without a restart. The embedded JSON is the compiled-in
/// baseline and a build input, so its parse failure is a build-time mistake,
/// not a runtime condition; `activate_if_newer` and `set_active_from_json` may
/// replace it later with a user-regenerated copy.
fn cell() -> &'static RwLock<Arc<VulnDb>> {
    static DB: OnceLock<RwLock<Arc<VulnDb>>> = OnceLock::new();
    DB.get_or_init(|| {
        RwLock::new(Arc::new(
            VulnDb::parse(VULNDB_JSON).expect("embedded vulndb.json parses"),
        ))
    })
}

/// A snapshot of the active database. Cloning the `Arc` is cheap and detaches
/// the caller from a concurrent swap, so an audit's matching always finishes
/// against one consistent database even if a regeneration lands mid-run.
pub fn db() -> Arc<VulnDb> {
    cell().read().expect("vulndb lock not poisoned").clone()
}

/// Replace the active database with one parsed from `json`. A parse failure
/// leaves the current database untouched. The regenerator calls this after it
/// writes the new file, so the next audit uses it with no restart.
pub fn set_active_from_json(json: &str) -> Result<(), serde_json::Error> {
    let parsed = VulnDb::parse(json)?;
    *cell().write().expect("vulndb lock not poisoned") = Arc::new(parsed);
    Ok(())
}

/// At startup, adopt the database at `path` if it parses and carries a newer
/// `generated_at` than the one currently active (the embedded baseline) —
/// the newer of the bundled and user copies wins, so a teammate who
/// refreshed keeps their fresher data, but a newer bundled build still
/// supersedes an older refresh. Returns whether it replaced the active db.
pub fn activate_if_newer(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(candidate) = VulnDb::parse(&text) else {
        return false;
    };
    // The timestamps are the same fixed RFC3339 shape, so a byte comparison
    // orders them correctly without a datetime dependency.
    let newer = candidate.generated_at.as_str() > db().generated_at();
    if newer {
        *cell().write().expect("vulndb lock not poisoned") = Arc::new(candidate);
    }
    newer
}

/// The per-(ecosystem, package) CVE counts of the active database. The
/// regenerator guards against this baseline so a rate-limited rebuild cannot
/// silently ship fewer advisories than the copy it would replace.
pub fn baseline_counts() -> BTreeMap<(String, String), usize> {
    let db = db();
    db.by_package
        .iter()
        .map(|((eco, pkg), vulns)| ((eco.clone(), pkg.clone()), vulns.len()))
        .collect()
}

impl VulnDb {
    fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let raw: RawDb = serde_json::from_str(json)?;
        let covered = raw
            .covered_packages
            .into_iter()
            .map(|(eco, pkgs)| (eco, pkgs.into_iter().collect()))
            .collect();
        let mut by_package: HashMap<(String, String), Vec<Vuln>> = HashMap::new();
        for v in raw.vulnerabilities {
            by_package
                .entry((v.ecosystem.clone(), v.package.clone()))
                .or_default()
                .push(v);
        }
        Ok(Self {
            covered,
            generated_at: raw.generated_at,
            sources: raw.sources,
            by_package,
        })
    }

    /// Whether the database can speak to this package at all. A detected
    /// component outside the covered set is "not checked", which the report
    /// states honestly rather than passing off as clean.
    pub fn covers(&self, ecosystem: &str, package: &str) -> bool {
        self.covered
            .get(ecosystem)
            .map(|set| set.contains(package))
            .unwrap_or(false)
    }

    /// The CVEs affecting a specific version of a package.
    pub fn matches(&self, ecosystem: &str, package: &str, version: &str) -> Vec<&Vuln> {
        let key = (ecosystem.to_string(), package.to_string());
        self.by_package
            .get(&key)
            .map(|vulns| vulns.iter().filter(|v| affects(v, version)).collect())
            .unwrap_or_default()
    }

    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }

    /// The distinct sources behind the data, e.g. "NIST NVD".
    pub fn sources_summary(&self) -> String {
        let distinct: BTreeSet<&str> = self.sources.values().map(String::as_str).collect();
        distinct.into_iter().collect::<Vec<_>>().join(", ")
    }

    /// The total number of CVEs across every covered package, for the settings
    /// readout of what the database currently holds.
    pub fn total_cves(&self) -> usize {
        self.by_package.values().map(Vec::len).sum()
    }

    /// How many packages each ecosystem covers (npm, wordpress,
    /// wordpress-plugin), for the same readout.
    pub fn covered_counts(&self) -> BTreeMap<String, usize> {
        self.covered
            .iter()
            .map(|(eco, set)| (eco.clone(), set.len()))
            .collect()
    }
}

/// Assess detected components against the database, producing the per-page
/// `vuln.*` observations. Observed versions can confirm; inferred versions can
/// only ever be "possible"; components the database does not cover are
/// reported as unchecked so their silence is not mistaken for a clean result.
pub fn assess(components: &[Component]) -> Vec<Observation> {
    let db = db();
    let mut confirmed: Vec<(&Vuln, String)> = Vec::new();
    let mut possible: Vec<(&Vuln, String)> = Vec::new();
    let mut unchecked: BTreeSet<String> = BTreeSet::new();

    for c in components {
        let Some(version) = c.version.as_deref() else {
            // No version means nothing to match; a bare detection is neither a
            // vulnerability nor an "unchecked" gap in the database.
            continue;
        };
        if !db.covers(&c.ecosystem, &c.package) {
            unchecked.insert(c.display.clone());
            continue;
        }
        for v in db.matches(&c.ecosystem, &c.package, version) {
            let detail = format!("{} {} ({})", c.display, version, v.id);
            match c.confidence {
                Confidence::Observed => confirmed.push((v, detail)),
                // The guard: an inferred version never confirms, so a critical
                // CVE on an inferred version is reported as possible, not
                // critical.
                Confidence::Inferred => possible.push((v, detail)),
            }
        }
    }

    let mut out = Vec::new();
    let push = |out: &mut Vec<Observation>, key: &str, value: Value| {
        if let Ok(o) = obs(key, value) {
            out.push(o);
        }
    };

    if !confirmed.is_empty() {
        let count = confirmed.len();
        let critical = confirmed
            .iter()
            .filter(|(v, _)| severity_rank(&v.severity) == 3)
            .count();
        let high = confirmed
            .iter()
            .filter(|(v, _)| severity_rank(&v.severity) == 2)
            .count();
        let medium = confirmed
            .iter()
            .filter(|(v, _)| severity_rank(&v.severity) == 1)
            .count();
        push(&mut out, "vuln.confirmed_count", Value::Num(count as f64));
        // All three severity buckets are emitted whenever anything confirmed,
        // including the zeros, so the rules that gate on `confirmed_critical <
        // 1` compare against a present value rather than an absent one.
        push(&mut out, "vuln.confirmed_critical", Value::Num(critical as f64));
        push(&mut out, "vuln.confirmed_high", Value::Num(high as f64));
        push(&mut out, "vuln.confirmed_medium", Value::Num(medium as f64));
        push(&mut out, "vuln.confirmed_ids", Value::from(join_ids(&confirmed)));
        push(
            &mut out,
            "vuln.confirmed_detail",
            Value::from(join_details(&confirmed)),
        );
    }

    if !possible.is_empty() {
        push(&mut out, "vuln.possible_count", Value::Num(possible.len() as f64));
        push(&mut out, "vuln.possible_ids", Value::from(join_ids(&possible)));
        push(
            &mut out,
            "vuln.possible_detail",
            Value::from(join_details(&possible)),
        );
    }

    if !unchecked.is_empty() {
        push(&mut out, "vuln.unchecked_count", Value::Num(unchecked.len() as f64));
        push(
            &mut out,
            "vuln.unchecked_detail",
            Value::from(unchecked.into_iter().collect::<Vec<_>>().join(", ")),
        );
    }

    out
}

/// The database's provenance, origin-scoped (it is the same DB for the whole
/// run). `now_unix` is passed in so the caller owns the clock.
pub fn db_metadata(now_unix: i64) -> Vec<Observation> {
    let db = db();
    let mut out = Vec::new();
    if let Ok(o) = obs("vuln.db_generated", Value::from(db.generated_at())) {
        out.push(o);
    }
    if let Some(generated) = rfc3339_to_unix(db.generated_at()) {
        let age_days = ((now_unix - generated).max(0)) / 86_400;
        if let Ok(o) = obs("vuln.db_age_days", Value::Num(age_days as f64)) {
            out.push(o);
        }
    }
    let sources = db.sources_summary();
    if !sources.is_empty() {
        if let Ok(o) = obs("vuln.db_sources", Value::from(sources)) {
            out.push(o);
        }
    }
    out
}

fn join_ids(hits: &[(&Vuln, String)]) -> String {
    let mut ids: Vec<&str> = hits.iter().map(|(v, _)| v.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    ids.join(", ")
}

fn join_details(hits: &[(&Vuln, String)]) -> String {
    let mut details: Vec<String> = hits.iter().map(|(_, d)| d.clone()).collect();
    details.sort_unstable();
    details.dedup();
    details.join("; ")
}

/// critical=3, high=2, medium=1, everything else (low/unknown)=0. The confirmed
/// findings only speak to the top three; a low-severity confirmed CVE still
/// counts toward `confirmed_count` and the detail, just no severity bucket.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 3,
        "high" => 2,
        "medium" | "moderate" => 1,
        _ => 0,
    }
}

/// Whether a CVE affects a concrete version, by exact list or by range.
fn affects(v: &Vuln, version: &str) -> bool {
    let ver = parse_version(version);
    if v
        .versions
        .iter()
        .any(|x| cmp_version(&ver, &parse_version(x)) == Ordering::Equal)
    {
        return true;
    }
    v.ranges.iter().any(|r| in_range(&ver, r))
}

fn in_range(ver: &[u64], r: &Range) -> bool {
    if let Some(introduced) = &r.introduced {
        if cmp_version(ver, &parse_version(introduced)) == Ordering::Less {
            return false;
        }
    }
    if let Some(fixed) = &r.fixed {
        // Affected up to but not including the fixed version.
        return cmp_version(ver, &parse_version(fixed)) == Ordering::Less;
    }
    if let Some(last) = &r.last_affected {
        // Affected up to and including last_affected.
        return cmp_version(ver, &parse_version(last)) != Ordering::Greater;
    }
    // A range with only `introduced` (or nothing) affects every version at or
    // after it, which for an open range is everything we could have detected.
    true
}

/// The leading dotted-numeric part of a version, pre-release suffixes dropped.
/// "3.0.0-rc.1" -> [3,0,0]; "1.6" -> [1,6]; "v2.1" -> [2,1].
fn parse_version(s: &str) -> Vec<u64> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let mut out = Vec::new();
    for part in s.split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        match digits.parse::<u64>() {
            Ok(n) => out.push(n),
            Err(_) => break,
        }
        // A part like "0-rc" contributed its leading digits; stop after it, the
        // pre-release tail is not part of the release ordering we compare on.
        if digits.len() != part.len() {
            break;
        }
    }
    out
}

/// Compare two parsed versions, zero-padding the shorter so 1.6 == 1.6.0.
fn cmp_version(a: &[u64], b: &[u64]) -> Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// Days-precision RFC3339 to a Unix timestamp: only the calendar date is used
/// (the DB is stamped once a day), which avoids a datetime dependency for what
/// is ultimately an "age in days" readout.
fn rfc3339_to_unix(s: &str) -> Option<i64> {
    let date = s.split('T').next()?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    Some(days_from_civil(year, month, day) * 86_400)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::{Component, Confidence};

    fn comp(eco: &str, pkg: &str, ver: &str, conf: Confidence) -> Component {
        Component {
            ecosystem: eco.into(),
            package: pkg.into(),
            display: pkg.into(),
            version: Some(ver.into()),
            confidence: conf,
        }
    }

    #[test]
    fn the_embedded_database_parses_and_covers_jquery() {
        let db = db();
        assert!(db.covers("npm", "jquery"));
        assert!(db.covers("wordpress-plugin", "woocommerce"));
        assert!(!db.covers("npm", "left-pad"));
        assert!(!db.generated_at().is_empty());
        assert!(db.sources_summary().contains("NVD"));
    }

    #[test]
    fn version_ranges_and_exact_lists_both_match() {
        let db = db();
        // CVE-2011-4969: jQuery before 1.6.3 (range last_affected 1.6.2 + exact
        // 1.6/1.6.1). 1.6.2 is in, 1.7 is out.
        assert!(!db.matches("npm", "jquery", "1.6.2").is_empty());
        assert!(db.matches("npm", "jquery", "3.6.0").iter().all(|v| v.id != "CVE-2011-4969"));
    }

    #[test]
    fn an_observed_version_confirms_but_an_inferred_one_is_only_possible() {
        // A jQuery old enough to have a known CVE.
        let observed = assess(&[comp("npm", "jquery", "1.6.2", Confidence::Observed)]);
        let ov: std::collections::HashMap<_, _> = observed
            .iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect();
        assert!(ov.contains_key("vuln.confirmed_count"), "observed confirms");
        assert!(!ov.contains_key("vuln.possible_count"));

        let inferred = assess(&[comp("npm", "jquery", "1.6.2", Confidence::Inferred)]);
        let iv: std::collections::HashMap<_, _> = inferred
            .iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect();
        assert!(iv.contains_key("vuln.possible_count"), "inferred is possible");
        assert!(
            !iv.contains_key("vuln.confirmed_count"),
            "an inferred version must never confirm"
        );
    }

    #[test]
    fn an_inferred_critical_never_prints_a_confirmed_critical() {
        // Whatever the severity of the matched CVEs, an inferred version's hits
        // are all funnelled to `possible`, so `confirmed_critical` is absent.
        let v: std::collections::HashMap<_, _> =
            assess(&[comp("npm", "jquery", "1.6.2", Confidence::Inferred)])
                .iter()
                .map(|o| (o.metric_key.to_string(), o.value()))
                .collect();
        assert!(!v.contains_key("vuln.confirmed_critical"));
    }

    #[test]
    fn a_detected_component_outside_the_database_is_unchecked() {
        let v: std::collections::HashMap<_, _> =
            assess(&[comp("npm", "some-obscure-lib", "1.0.0", Confidence::Observed)])
                .iter()
                .map(|o| (o.metric_key.to_string(), o.value()))
                .collect();
        assert_eq!(v.get("vuln.unchecked_count"), Some(&Value::Num(1.0)));
        assert!(!v.contains_key("vuln.confirmed_count"));
    }

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(cmp_version(&parse_version("1.6"), &parse_version("1.6.0")), Ordering::Equal);
        assert_eq!(cmp_version(&parse_version("1.6.2"), &parse_version("1.6.3")), Ordering::Less);
        assert_eq!(cmp_version(&parse_version("3.0.0-rc.1"), &parse_version("3.0.0")), Ordering::Equal);
        assert_eq!(cmp_version(&parse_version("2.10"), &parse_version("2.9")), Ordering::Greater);
    }

    #[test]
    fn civil_date_matches_known_epoch_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(rfc3339_to_unix("1970-01-02T00:00:00+00:00"), Some(86_400));
    }

    /// The observations only matter if the shipped rules fire on them. This
    /// guards the whole contract, including the reason the severity buckets are
    /// emitted as explicit zeros: the confirmed-high/medium rules gate on
    /// `confirmed_critical < 1`, and a missing metric fails every comparison.
    #[test]
    fn the_findings_engine_fires_the_vuln_rules_these_observations_target() {
        use slap_core::findings::FindingsEngine;
        let engine = FindingsEngine::load(None).expect("embedded rules load");
        let fire = |components: &[Component]| -> Vec<String> {
            let values: std::collections::HashMap<String, Value> = assess(components)
                .iter()
                .map(|o| (o.metric_key.to_string(), o.value()))
                .collect();
            engine
                .run(&values)
                .unwrap()
                .into_iter()
                .map(|f| f.rule_id)
                .collect()
        };

        let confirmed = fire(&[comp("npm", "jquery", "1.6.2", Confidence::Observed)]);
        assert!(
            confirmed.iter().any(|id| id.starts_with("vuln-confirmed")),
            "an observed vulnerable version fires a confirmed rule, got {confirmed:?}"
        );

        let possible = fire(&[comp("npm", "jquery", "1.6.2", Confidence::Inferred)]);
        assert!(
            possible.iter().any(|id| id == "vuln-possible"),
            "an inferred version fires vuln-possible, got {possible:?}"
        );
        assert!(
            !possible.iter().any(|id| id.starts_with("vuln-confirmed")),
            "an inferred version must never fire a confirmed rule"
        );

        let unchecked = fire(&[comp("npm", "left-pad", "1.0.0", Confidence::Observed)]);
        assert!(
            unchecked.iter().any(|id| id == "vuln-not-checked"),
            "a component outside the database fires vuln-not-checked, got {unchecked:?}"
        );
    }
}
