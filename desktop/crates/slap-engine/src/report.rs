//! The client-facing report: a stored run rendered to standalone HTML, and
//! (through the shell) to PDF.
//!
//! It reads like the Lighthouse report a client already knows: category
//! gauges in Lighthouse's three bands, the metrics grid with Lighthouse's
//! rating shapes, audits grouped the way Lighthouse groups them, and its
//! runtime-settings footer. Around that sits what SLAP adds: the verdict
//! first, findings grouped by rule across pages, a cross-page view of every
//! page Lighthouse measured, security and software.
//!
//! The model is assembled straight from the stored run (the observations,
//! findings and pages the app persists) plus the compact per-page Lighthouse
//! summary written beside the database when each page was measured. Every
//! stored value is formatted through `schema::format_value` or, for
//! Lighthouse's own metrics, Lighthouse's own display conventions, so a
//! number in the report is a number from the database.
//!
//! A status never relies on colour alone: every gauge, metric and audit
//! carries Lighthouse's rating shape, and every finding badge and status cell
//! prints its word.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value as Json};
use slap_core::rusqlite::Connection;
use slap_core::schema::{format_value, metric_registry, Value};
use slap_core::storage;

const REPORT_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../templates/report/report.css"
));

const REPORT_TMPL: &str = include_str!("report.html.jinja");

/// Render a run to a standalone HTML document.
pub fn render_html(conn: &Connection, run_id: i64) -> Result<String, String> {
    let model = build_model(conn, run_id)?;
    let mut env = minijinja::Environment::new();
    env.add_template("report.css", REPORT_CSS)
        .map_err(|e| format!("report.css template: {e}"))?;
    env.add_template("report", REPORT_TMPL)
        .map_err(|e| format!("report template: {e}"))?;
    let tmpl = env.get_template("report").map_err(|e| e.to_string())?;
    tmpl.render(minijinja::Value::from_serialize(&model))
        .map_err(|e| e.to_string())
}

/// One observation's stored value, plus where it came from.
struct Ob {
    num: Option<f64>,
    text: Option<String>,
    source: String,
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


// ---------------------------------------------------------------------------
// Lighthouse's visual language: bands, gauges, metric display and ratings
// ---------------------------------------------------------------------------

/// The four categories, in Lighthouse's order: observation key, the id the
/// summary uses, and the label Lighthouse prints.
const LH_CATEGORIES: [(&str, &str, &str); 4] = [
    ("lh.score.performance", "performance", "Performance"),
    ("lh.score.accessibility", "accessibility", "Accessibility"),
    ("lh.score.best_practices", "best-practices", "Best Practices"),
    ("lh.score.seo", "seo", "SEO"),
];

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
            })
        }
        None => json!({ "label": label, "score": Json::Null, "rating": "none", "dash": "0 351.86" }),
    }
}

/// The five scored metrics: observation key, Lighthouse's name, and its
/// scoring control points on mobile and on desktop, as `(p10, median)`. A
/// value at or under p10 scores 0.9 (pass) and at or under the median scores
/// 0.5 (average), so the two points ARE the rating bands, with no curve
/// arithmetic needed. Values from Lighthouse's metric audits.
/// `(p10, median)` scoring control points for one metric.
type ControlPoints = (f64, f64);

const LH_METRICS: [(&str, &str, ControlPoints, ControlPoints); 5] = [
    ("lh.fcp", "First Contentful Paint", (1800.0, 3000.0), (934.0, 1600.0)),
    ("lh.lcp", "Largest Contentful Paint", (2500.0, 4000.0), (1200.0, 2400.0)),
    ("lh.tbt", "Total Blocking Time", (200.0, 600.0), (150.0, 350.0)),
    ("lh.cls", "Cumulative Layout Shift", (0.1, 0.25), (0.1, 0.25)),
    ("lh.speed_index", "Speed Index", (3387.0, 5800.0), (1311.0, 2300.0)),
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
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
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
        .filter_map(|(key, title, mobile, desk)| {
            let v = *values.get(*key)?;
            let spread = match *key {
                "lh.lcp" => values.get("lh.lcp.spread").copied(),
                "lh.tbt" => values.get("lh.tbt.spread").copied(),
                _ => None,
            }
            .filter(|s| *s > 0.0)
            .map(|s| format!("±{}", lh_display(key, s / 2.0)));
            Some(json!({
                "key": key,
                "title": title,
                "display": lh_display(key, v),
                "rating": metric_rating(v, if desktop { *desk } else { *mobile }),
                "spread": spread,
            }))
        })
        .collect()
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

/// One category of a page's summary, shaped for the template: Lighthouse's
/// groups with their failing (and, when `informative`, informative) audits,
/// capped per category with the remainder counted.
fn category_view(cat: &Json, score: Option<f64>, label: &str, informative: bool, cap: usize) -> Json {
    let mut shown = 0usize;
    let mut hidden = 0usize;
    let mut groups = Vec::new();
    for g in cat["groups"].as_array().into_iter().flatten() {
        let mut audits = Vec::new();
        for a in g["audits"].as_array().into_iter().flatten() {
            let rating = a["rating"].as_str().unwrap_or("");
            if rating == "informative" && !informative {
                continue;
            }
            if shown >= cap {
                hidden += 1;
                continue;
            }
            shown += 1;
            audits.push(a.clone());
        }
        if !audits.is_empty() {
            groups.push(json!({ "title": g["title"], "audits": audits }));
        }
    }
    json!({
        "id": cat["id"],
        "label": label,
        "gauge": gauge(label, score),
        "groups": groups,
        "hidden": hidden,
        "passed": cat["passed"],
        "manual": cat["manual"],
        "not_applicable": cat["not_applicable"],
    })
}

/// Everything a Lighthouse-style section for one page needs.
#[allow(clippy::too_many_arguments)]
fn page_lighthouse_view(
    path: &str,
    template: &str,
    values: &HashMap<String, f64>,
    summary: Option<&Json>,
    desktop: bool,
    informative: bool,
    cap: usize,
    reasons: Vec<String>,
) -> Json {
    let gauges: Vec<Json> = LH_CATEGORIES
        .iter()
        .map(|(key, _, label)| gauge(label, values.get(*key).copied()))
        .collect();
    let categories: Vec<Json> = LH_CATEGORIES
        .iter()
        .filter_map(|(key, id, label)| {
            let cat = summary?["categories"]
                .as_array()?
                .iter()
                .find(|c| c["id"] == *id)?;
            Some(category_view(cat, values.get(*key).copied(), label, informative, cap))
        })
        .collect();
    json!({
        "path": path,
        "template": template,
        "reasons": reasons,
        "gauges": gauges,
        "metrics": metrics_grid(values, desktop),
        "categories": categories,
        "has_summary": summary.is_some(),
        "runs": values.get("lh.runs").map(|r| *r as i64),
        "perf_spread": values.get("lh.score.performance.spread").copied().filter(|s| *s > 0.0),
        "warnings": summary.map(|s| s["warnings"].clone()).unwrap_or(Json::Null),
    })
}

/// A score cell for the inventory: Lighthouse's shape, then the number.
fn score_cell(score: Option<f64>) -> Json {
    match score {
        Some(v) => json!({ "text": format!("{}", v.round() as i64), "rating": band(v) }),
        None => json!({ "text": Json::Null, "rating": "none" }),
    }
}

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
    // the appendix; the origin collectors (TLS, CrUX, discovery, vuln DB,
    // probe) were persisted onto the home page for exactly this reason.
    let mut home: BTreeMap<String, Ob> = BTreeMap::new();
    // Every page's numeric Lighthouse values, by page id: scores, metric
    // medians and spreads. What the inventory, the cross-page view and each
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
                    source: str_of(o, "source").unwrap_or("").to_string(),
                },
            );
        }
    }

    let fmt = |key: &str| -> Option<String> { home.get(key).map(|o| format_value(key, Some(&o.value()))) };
    let num = |key: &str| -> Option<f64> { home.get(key).and_then(|o| o.num) };

    // --- verdict ---
    let cwv = [
        ("crux.lcp.p75", "crux.lcp.good", "LCP", "Largest Contentful Paint", 2500.0, 4000.0),
        ("crux.inp.p75", "crux.inp.good", "INP", "Interaction to Next Paint", 200.0, 500.0),
        ("crux.cls.p75", "crux.cls.good", "CLS", "Cumulative Layout Shift", 0.1, 0.25),
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
            "threshold": format!("Good \u{2264} {}", format_value(key, Some(&Value::Num(good)))),
            "good_share": num(good_key).map(|g| format!("{:.0}% of visits good", g * 100.0)),
        }));
    }
    let has_field = !tiles.is_empty();
    let passes = has_field && all_good;

    let (flag_class, flag_word) = if !has_field {
        ("unknown", "No real-user data")
    } else if passes {
        ("good", "Passing Core Web Vitals")
    } else {
        ("poor", "Failing Core Web Vitals")
    };
    let (headline, explanation) = verdict_prose(has_field, passes, &hostname);

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
    let page_count = pages.len();
    let mut significant = Vec::new();
    let mut minor = Vec::new();
    let mut counts = json!({"critical":0,"high":0,"medium":0,"low":0,"info":0});
    for rule in &order {
        let (f, urls) = &groups[rule];
        let sev = str_of(f, "severity").unwrap_or("info");
        let current = counts.get(sev).and_then(Json::as_i64).unwrap_or(0);
        counts[sev] = json!(current + 1);
        // A finding whose evidence is entirely origin-scoped (the TLS
        // certificate, the CrUX record, the run's machine stability) is about
        // the site, not the home page its observations happen to be stored
        // on. "1 of 20 pages" would understate it twentyfold.
        let origin_only = evidence_is_origin_scoped(f);
        let is_sitewide = (urls.len() == page_count || origin_only) && page_count > 1;
        let scope_text = if page_count <= 1 {
            String::new()
        } else if origin_only {
            "Site-wide".to_string()
        } else if is_sitewide {
            format!("All {page_count} pages")
        } else if urls.len() == 1 {
            short_path(&urls[0])
        } else {
            format!("{} of {} pages", urls.len(), page_count)
        };
        let impact_text = num_of(f, "impact_ms")
            .filter(|ms| *ms > 0.0)
            .map(|ms| format_value("lh.lcp", Some(&Value::Num(ms))));
        let card = json!({
            "status": severity_class(sev),
            "severity_word": severity_word(sev),
            "title": str_of(f, "title").unwrap_or(""),
            "detail": str_of(f, "detail").unwrap_or(""),
            "remediation": str_of(f, "remediation"),
            "wp_rocket_setting": str_of(f, "wp_rocket_setting"),
            "effort_label": effort_label(str_of(f, "effort")),
            "impact_text": impact_text,
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
    let total_findings = order.len();

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

    // Which rules each page carries, to explain why a page earns a section,
    // and each page's findings, indexed once: a 2,000-page run has tens of
    // thousands of finding rows.
    let mut rule_pages: HashMap<String, HashSet<String>> = HashMap::new();
    let mut findings_by_url: HashMap<&str, Vec<&Json>> = HashMap::new();
    for f in &findings {
        let url = str_of(f, "url").unwrap_or("");
        rule_pages
            .entry(str_of(f, "rule_id").unwrap_or("").to_string())
            .or_default()
            .insert(url.to_string());
        findings_by_url.entry(url).or_default().push(f);
    }

    // The inventory: every page, every category score, the three lab
    // metrics that most often explain a score.
    let page_rows: Vec<Json> = pages
        .iter()
        .map(|p| {
            let url = str_of(p, "url").unwrap_or("");
            let v = values_of(p);
            let metric = |key: &str| -> Json {
                let Some(x) = v.get(key).copied() else { return Json::Null };
                let (_, _, mobile, desk) = LH_METRICS.iter().find(|m| m.0 == key).unwrap();
                json!({ "text": lh_display(key, x), "rating": metric_rating(x, if desktop { *desk } else { *mobile }) })
            };
            let failed = v.get("lh.runs") == Some(&0.0);
            json!({
                "path": short_path(url),
                "template": str_of(p, "template_class").unwrap_or("page"),
                "measured": v.contains_key("lh.score.performance"),
                "lh_failed": failed,
                "scores": LH_CATEGORIES.iter().map(|(k, _, _)| score_cell(v.get(*k).copied())).collect::<Vec<_>>(),
                "lcp": metric("lh.lcp"),
                "tbt": metric("lh.tbt"),
                "cls": metric("lh.cls"),
                "findings": num_of(p, "finding_count").unwrap_or(0.0) as i64,
                "urgent": num_of(p, "urgent_count").unwrap_or(0.0) as i64,
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
                str_of(p, "template_class").unwrap_or("home"),
                &v,
                summaries.get(&page_id_of(p)),
                desktop,
                true,
                usize::MAX,
                Vec::new(),
            )
        })
    });

    // Across every measured page: each category's median and how the pages
    // fall into Lighthouse's three bands.
    let distribution: Vec<Json> = LH_CATEGORIES
        .iter()
        .filter_map(|(key, _, label)| {
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

    // The Lighthouse audits that fail on the most pages: the cross-page view
    // only an every-page run can give. One line per audit, with its reach.
    // (category id, audit id) -> (title, category label, pages, savings, any fail)
    type Reach = (String, String, usize, Vec<f64>, bool);
    let mut common: HashMap<(String, String), Reach> = HashMap::new();
    for summary in summaries.values() {
        for cat in summary["categories"].as_array().into_iter().flatten() {
            let cat_label = LH_CATEGORIES
                .iter()
                .find(|c| cat["id"] == c.1)
                .map(|c| c.2)
                .unwrap_or("");
            for g in cat["groups"].as_array().into_iter().flatten() {
                for a in g["audits"].as_array().into_iter().flatten() {
                    let rating = a["rating"].as_str().unwrap_or("");
                    if rating != "fail" && rating != "average" {
                        continue;
                    }
                    let entry = common
                        .entry((cat["id"].as_str().unwrap_or("").to_string(), a["id"].as_str().unwrap_or("").to_string()))
                        .or_insert_with(|| (a["title"].as_str().unwrap_or("").to_string(), cat_label.to_string(), 0, Vec::new(), false));
                    entry.2 += 1;
                    if let Some(ms) = a["savings_ms"].as_f64() {
                        entry.3.push(ms);
                    }
                    entry.4 |= rating == "fail";
                }
            }
        }
    }
    let summarised = summaries.len();
    let mut common: Vec<Json> = common
        .into_values()
        .map(|(title, category, pages_hit, mut savings, any_fail)| {
            let saving = median_of(&mut savings).filter(|ms| *ms > 0.0);
            json!({
                "title": title,
                "category": category,
                "pages": pages_hit,
                "of": summarised,
                "rating": if any_fail { "fail" } else { "average" },
                "saving": saving.map(|ms| format!("{} ms", group_thousands(ms.round() as i64))),
                "saving_ms": saving.unwrap_or(0.0),
            })
        })
        .collect();
    common.sort_by(|a, b| {
        b["pages"].as_u64().cmp(&a["pages"].as_u64()).then(
            b["saving_ms"]
                .as_f64()
                .partial_cmp(&a["saving_ms"].as_f64())
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    let common_total = common.len();
    common.truncate(15);

    let scope = run["lh_scope"].as_str().and_then(slap_core::schema::LighthouseScope::parse);

    // Which other pages earn a Lighthouse section of their own. Everything
    // in full would make an every-page PDF hundreds of pages long and bury
    // the pages that matter, so a page gets one when it is an outlier (well
    // below the site's median, or failing a category the site passes) or
    // carries a finding most pages do not. With only a handful measured
    // (the sampled default), every measured page gets one.
    // By key, never by position: a category no page has a score for is
    // absent from the distribution, and positions would then shift.
    let cat_medians: HashMap<String, f64> = distribution
        .iter()
        .filter_map(|d| Some((d["key"].as_str()?.to_string(), d["median"].as_f64()?)))
        .collect();
    let perf_median = cat_medians.get("lh.score.performance").copied();
    let half = (page_count / 2).max(1);
    let mut candidates: Vec<(i32, f64, Json)> = Vec::new();
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
                reasons.push(format!("Performance {} against a site median of {}", perf.round(), m.round()));
                weight += 3;
            }
        }
        for (key, _, label) in LH_CATEGORIES.iter().skip(1) {
            if let (Some(score), Some(m)) = (v.get(*key), cat_medians.get(*key)) {
                if band(*score) == "fail" && band(*m) != "fail" {
                    reasons.push(format!("{label} {} where the site is {}", score.round(), m.round()));
                    weight += 2;
                }
            }
        }
        let specific: Vec<String> = findings_by_url
            .get(url)
            .into_iter()
            .flatten()
            .filter(|f| matches!(str_of(f, "severity"), Some("critical" | "high" | "medium")))
            .filter(|f| rule_pages.get(str_of(f, "rule_id").unwrap_or("")).map_or(0, |s| s.len()) < half)
            .filter_map(|f| str_of(f, "title").map(str::to_string))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if !specific.is_empty() {
            reasons.push(format!(
                "{} issue{} found on few other pages",
                specific.len(),
                if specific.len() == 1 { "" } else { "s" }
            ));
            weight += 2;
        }
        if reasons.is_empty() && measured.len() > 6 {
            continue;
        }
        if reasons.is_empty() && scope == Some(slap_core::schema::LighthouseScope::Sampled) {
            reasons.push(format!(
                "Representative of the {} template",
                str_of(p, "template_class").unwrap_or("page")
            ));
        }
        let view = page_lighthouse_view(
            &short_path(url),
            str_of(p, "template_class").unwrap_or("page"),
            &v,
            summaries.get(&page_id_of(p)),
            desktop,
            false,
            6,
            reasons,
        );
        candidates.push((weight, perf, view));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)));
    const PAGE_SECTIONS: usize = 25;
    let more_pages = candidates.len().saturating_sub(PAGE_SECTIONS);
    let page_sections: Vec<Json> = candidates.into_iter().take(PAGE_SECTIONS).map(|c| c.2).collect();

    // What was measured, said plainly: the claim a reader must not have to infer.
    let loaded = pages.iter().filter(|p| !p["final_url"].is_null()).count();
    let coverage = if measured.is_empty() {
        None
    } else {
        let failed_note = if lh_failed > 0 {
            format!(" Lighthouse could not measure {lh_failed}.")
        } else {
            String::new()
        };
        Some(match scope {
            Some(slap_core::schema::LighthouseScope::EveryPage) if measured.len() == loaded => {
                format!("All {} discovered pages were measured with Lighthouse.", measured.len())
            }
            Some(slap_core::schema::LighthouseScope::EveryPage) => format!(
                "{} of {} discovered pages were measured with Lighthouse.{failed_note}",
                measured.len(),
                loaded
            ),
            Some(slap_core::schema::LighthouseScope::Sampled) => format!(
                "{} of {} pages were measured with Lighthouse: one per template, the templates covering the most pages first.{failed_note}",
                measured.len(),
                loaded
            ),
            None => format!("{} of {} pages were measured with Lighthouse.{failed_note}", measured.len(), loaded),
        })
    };
    let cap_note = match (num("discovery.found"), num("discovery.dropped")) {
        (Some(found), Some(dropped)) if dropped > 0.0 => Some(format!(
            "Discovery found {} pages; the per-site cap of {} left {} of them out of this audit.",
            found as i64,
            (found - dropped) as i64,
            dropped as i64
        )),
        _ => None,
    };
    let runtime = home_page
        .and_then(|p| summaries.get(&page_id_of(p)))
        .or_else(|| summaries.values().next())
        .map(|s| s["runtime"].clone());

    // Each home gauge carries its own site median, matched by category.
    let mut home_lh = home_lh;
    if measured.len() > 1 {
        if let Some(gauges) = home_lh.as_mut().and_then(|h| h["gauges"].as_array_mut()) {
            for (g, (key, _, _)) in gauges.iter_mut().zip(LH_CATEGORIES.iter()) {
                if let Some(m) = cat_medians.get(*key) {
                    g["site_median"] = json!(m.round() as i64);
                }
            }
        }
    }
    let lighthouse = json!({
        "home": home_lh,
        "measured": measured.len(),
        "multi": measured.len() > 1,
        "distribution": distribution,
        "common": common,
        "common_more": common_total.saturating_sub(15),
        "summarised": summarised,
        "pages": page_sections,
        "more_pages": more_pages,
        // Few pages measured: every one has a section, gated or not.
        "pages_all": measured.len() <= 6,
        "coverage": coverage,
        "cap_note": cap_note,
        "scope_label": scope.map(|s| s.label()),
        "runtime": runtime,
        "drift": num("lh.run.benchmark_drift").map(|d| format!("{:.0}%", d * 100.0)),
        "benchmark_range": match (num("lh.run.benchmark_min"), num("lh.run.benchmark_max")) {
            (Some(a), Some(b)) => Some(format!("{} to {}", a.round(), b.round())),
            _ => None,
        },
    });

    // --- software detected (components + vulnerabilities) ---
    let software = home.contains_key("component.count").then(|| {
        json!({
            "detected": fmt("component.detected"),
            "count": num("component.count").unwrap_or(0.0) as i64,
            "observed": num("component.observed_count").unwrap_or(0.0) as i64,
            "inferred": num("component.inferred_count").unwrap_or(0.0) as i64,
            "confirmed": num("vuln.confirmed_count").map(|n| n as i64),
            "possible": num("vuln.possible_count").map(|n| n as i64),
            "unchecked": num("vuln.unchecked_count").map(|n| n as i64),
            "db_generated": fmt("vuln.db_generated").map(|s| s.chars().take(10).collect::<String>()),
            "db_age": num("vuln.db_age_days").map(|n| n as i64),
            "db_sources": fmt("vuln.db_sources"),
        })
    });

    // --- security ---
    let tls_row = |key: &str, label: &str| -> Option<Json> {
        fmt(key).map(|value| {
            let status = match key {
                "tls.valid" => {
                    if num(key) == Some(1.0) {
                        Some(("good", "Valid"))
                    } else {
                        Some(("poor", "Invalid"))
                    }
                }
                _ => None,
            };
            json!({
                "label": label, "value": value,
                "status": status.map(|s| s.0), "status_word": status.map(|s| s.1),
            })
        })
    };
    let tls: Vec<Json> = [
        ("tls.valid", "Certificate valid"),
        ("tls.issuer", "Issuer"),
        ("tls.subject", "Subject"),
        ("tls.days_to_expiry", "Days to expiry"),
        ("tls.protocol", "Protocol"),
        ("tls.cipher", "Cipher"),
    ]
    .into_iter()
    .filter_map(|(k, l)| tls_row(k, l))
    .collect();

    let header_specs = [
        ("sec.hsts", "Strict-Transport-Security"),
        ("sec.csp", "Content-Security-Policy"),
        ("sec.x_content_type_options", "X-Content-Type-Options"),
        ("sec.x_frame_options", "X-Frame-Options"),
    ];
    let headers: Vec<Json> = header_specs
        .iter()
        .filter_map(|(k, l)| {
            fmt(k).map(|value| json!({ "label": l, "value": value, "status": "good", "status_word": "Set" }))
        })
        .collect();
    let headers_present = headers.len();
    let cookies: Vec<Json> = [
        ("sec.cookies_total", "Cookies set"),
        ("sec.cookies_insecure", "Without Secure"),
        ("sec.cookies_no_httponly", "Without HttpOnly"),
        ("sec.cookies_no_samesite", "Without SameSite"),
    ]
    .into_iter()
    .filter_map(|(k, l)| fmt(k).map(|value| json!({ "label": l, "value": value })))
    .collect();

    // --- appendix: every measurement, formatted ---
    let mut appendix: Vec<Json> = home
        .iter()
        .map(|(key, ob)| {
            let label = metric_registry()
                .get(key.as_str())
                .map(|m| m.label)
                .unwrap_or(key.as_str());
            json!({
                "label": label,
                "value": format_value(key, Some(&ob.value())),
                "source": ob.source,
                "metric_key": key,
            })
        })
        .collect();
    appendix.sort_by(|a, b| a["metric_key"].as_str().cmp(&b["metric_key"].as_str()));

    // --- provenance + tech + branding ---
    let provenance = json!({
        "run_id": run_id,
        "batch_id": str_of(&run, "batch_id").unwrap_or(""),
        "slap_version": str_of(&run, "slap_version").unwrap_or(""),
        "schema_version": num_of(&run, "schema_version").unwrap_or(0.0) as i64,
        "lighthouse_version": str_of(&run, "lh_version"),
        "chrome_version": str_of(&run, "chrome_version"),
        "throttling_profile": str_of(&run, "throttling_profile"),
    });
    let wp_rocket = if num("wprocket.present") == Some(1.0) {
        Some(fmt("wprocket.version").unwrap_or_else(|| "detected".into()))
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

    let branding = json!({
        "company_name": settings.branding.get("company_name"),
        "accent": settings.branding.get("accent"),
        "logo_data_uri": settings.branding.get("logo_data_uri"),
    });

    let generated_at = str_of(&run, "started_at").unwrap_or("").replace('T', " ");

    Ok(json!({
        "hostname": hostname,
        "generated_at": generated_at,
        "run_id": run_id,
        "branding": branding,
        // A report-content switch (Settings screen): whether findings carry
        // the "In WP Rocket" remediation line. Detection in the tech section
        // is unaffected by it.
        "show_wp_rocket": settings.wp_rocket_suggestions,
        "verdict": {
            "flag_class": flag_class, "flag_word": flag_word,
            "headline": headline, "explanation": explanation,
            "has_field": has_field, "tiles": tiles,
        },
        "total_findings": total_findings,
        "severity_counts": counts,
        "is_multipage": page_count > 1,
        "significant": significant,
        "minor": minor,
        "pages": page_rows,
        "lh": lighthouse,
        "software": software,
        "security": {
            "headers_present": headers_present,
            "headers_expected": header_specs.len(),
            "tls": tls, "headers": headers, "cookies": cookies,
        },
        "appendix": appendix,
        "provenance": provenance,
        "tech": tech,
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

fn verdict_prose(has_field: bool, passes: bool, hostname: &str) -> (String, String) {
    if !has_field {
        (
            format!("No real-user data is available for {hostname} yet."),
            "Google has not recorded enough real visits to this site to report its \
             Core Web Vitals. The figures below are our own measurements, which \
             stand in until field data accumulates."
                .to_string(),
        )
    } else if passes {
        (
            "This site passes Core Web Vitals for real visitors.".to_string(),
            "Every Core Web Vital is within Google's \"good\" threshold at the 75th \
             percentile of real visits over the last 28 days. The findings below are \
             smaller improvements and hygiene, not a failing grade."
                .to_string(),
        )
    } else {
        (
            "This site is failing Core Web Vitals for real visitors.".to_string(),
            "At least one Core Web Vital is outside Google's \"good\" threshold for \
             real visitors, which can affect both experience and search ranking. The \
             issues to address first are listed below."
                .to_string(),
        )
    }
}

fn effort_label(effort: Option<&str>) -> Option<String> {
    match effort? {
        "low" => Some("Low effort".into()),
        "medium" => Some("Moderate effort".into()),
        "high" => Some("Significant effort".into()),
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
        let lcp = LH_METRICS[1].2;
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

    #[test]
    fn the_masthead_renders_the_configured_brand_name_and_logo() {
        // Also guards that the whole template still parses and renders.
        let mut env = minijinja::Environment::new();
        env.add_template("report.css", REPORT_CSS).unwrap();
        env.add_template("report", REPORT_TMPL).unwrap();
        let tmpl = env.get_template("report").unwrap();
        let base = |branding: Json| -> Json {
            json!({
                "hostname": "example.com", "generated_at": "2026-01-01 00:00", "run_id": 1,
                "branding": branding,
                "verdict": {"flag_class":"unknown","flag_word":"No data","headline":"h","explanation":"e","has_field":false,"tiles":[],"scores":[]},
                "total_findings": 0, "severity_counts": {"critical":0,"high":0,"medium":0,"low":0,"info":0},
                "is_multipage": false, "significant": [], "minor": [], "pages": [], "software": Json::Null,
                "security": {"headers_present":0,"headers_expected":4,"tls":[],"headers":[],"cookies":[]},
                "appendix": [], "tech": {},
                "provenance": {"run_id":1,"batch_id":"b","slap_version":"0.1.0","schema_version":1},
            })
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
    }

    #[test]
    fn wp_rocket_suggestion_shows_only_when_enabled() {
        // The "In WP Rocket" fix line follows the show_wp_rocket flag; the
        // plain fix advice is always shown. Also proves no empty .fix block is
        // left when the WP Rocket setting is a finding sole fix and it is off.
        let mut env = minijinja::Environment::new();
        env.add_template("report.css", REPORT_CSS).unwrap();
        env.add_template("report", REPORT_TMPL).unwrap();
        let tmpl = env.get_template("report").unwrap();
        let model = |show: bool, remediation: Json| -> Json {
            json!({
                "hostname": "example.com", "generated_at": "2026-01-01 00:00", "run_id": 1,
                "branding": {"company_name": Json::Null, "logo_data_uri": Json::Null},
                "show_wp_rocket": show,
                "verdict": {"flag_class":"poor","flag_word":"Failing","headline":"h","explanation":"e","has_field":false,"tiles":[],"scores":[]},
                "total_findings": 1, "severity_counts": {"critical":0,"high":1,"medium":0,"low":0,"info":0},
                "is_multipage": false,
                "significant": [{
                    "status":"serious","severity_word":"High","title":"Slow images","detail":"d",
                    "remediation": remediation, "wp_rocket_setting":"Enable LazyLoad for images",
                    "effort_label": Json::Null, "impact_text": Json::Null, "scope_text":"",
                    "is_sitewide": false, "page_count": 1, "pages": []
                }],
                "minor": [], "pages": [], "software": Json::Null,
                "security": {"headers_present":0,"headers_expected":4,"tls":[],"headers":[],"cookies":[]},
                "appendix": [], "tech": {},
                "provenance": {"run_id":1,"batch_id":"b","slap_version":"0.1.0","schema_version":1},
            })
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
    }
}
