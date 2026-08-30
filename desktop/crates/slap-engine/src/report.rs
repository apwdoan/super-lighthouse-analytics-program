//! The client-facing report: a stored run rendered to standalone HTML, and
//! (through the shell) to PDF. Ported from the Python `templates/report/`.
//!
//! It reuses that era's stylesheet, `report.css`, verbatim, so the look is
//! unchanged; what is rebuilt here is the model. Rather than reconstruct the
//! Python report-model builder field for field (its source did not survive the
//! rewrite), the model is assembled straight from the stored run — the same
//! observations, findings and pages the app already persists — and every value
//! is formatted through `schema::format_value`, so a byte in the report is a
//! byte from the database.
//!
//! One discipline carried over: a status colour never stands alone. Every
//! severity badge and every metric tile also prints its status WORD, because
//! two steps of the palette sit too close to separate by hue.

use std::collections::BTreeMap;

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
    let mut perf_by_url: BTreeMap<String, f64> = BTreeMap::new();
    for o in &observations {
        let key = str_of(o, "metric_key").unwrap_or("");
        let url = str_of(o, "url").unwrap_or("");
        if key == "lh.score.performance" {
            if let Some(n) = num_of(o, "numeric_value") {
                perf_by_url.insert(url.to_string(), n);
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
        ("crux.lcp.p75", "LCP", "Largest Contentful Paint", 2500.0, 4000.0),
        ("crux.inp.p75", "INP", "Interaction to Next Paint", 200.0, 500.0),
        ("crux.cls.p75", "CLS", "Cumulative Layout Shift", 0.1, 0.25),
    ];
    let mut tiles = Vec::new();
    let mut all_good = true;
    for (key, label, caption, good, poor) in cwv {
        let Some(v) = num(key) else { continue };
        let (status, status_word) = cwv_status(v, good, poor);
        if status != "good" {
            all_good = false;
        }
        tiles.push(json!({
            "label": label,
            "caption": caption,
            "value": fmt(key).unwrap_or_default(),
            "status": status,
            "status_word": status_word,
            "meter_pct": (meter_pct(v, good, poor) * 10.0).round() / 10.0,
            "threshold": format!("Good \u{2264} {}", format_value(key, Some(&Value::Num(good)))),
        }));
    }
    let has_field = !tiles.is_empty();
    let passes = has_field && all_good;

    let mut scores = Vec::new();
    for (key, label) in [
        ("lh.score.performance", "Performance"),
        ("lh.score.accessibility", "Accessibility"),
        ("lh.score.best_practices", "Best practices"),
        ("lh.score.seo", "SEO"),
    ] {
        if let Some(v) = num(key) {
            let (status, word) = if v >= 90.0 {
                ("good", "Good")
            } else if v >= 50.0 {
                ("needs-improvement", "Needs work")
            } else {
                ("poor", "Poor")
            };
            scores.push(json!({ "value": v.round() as i64, "label": label, "status": status, "status_word": word }));
        }
    }

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
        let is_sitewide = urls.len() == page_count && page_count > 1;
        let scope_text = if page_count <= 1 {
            String::new()
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

    // --- page inventory ---
    let page_rows: Vec<Json> = pages
        .iter()
        .map(|p| {
            let url = str_of(p, "url").unwrap_or("");
            let perf = perf_by_url.get(url).copied();
            let (status, score_text) = match perf {
                Some(v) if v >= 90.0 => ("good", format!("{}", v.round() as i64)),
                Some(v) if v >= 50.0 => ("needs-improvement", format!("{}", v.round() as i64)),
                Some(v) => ("poor", format!("{}", v.round() as i64)),
                None => ("muted", String::new()),
            };
            json!({
                "path": short_path(url),
                "template": str_of(p, "template_class").unwrap_or("page"),
                "measured": perf.is_some(),
                "status": status,
                "score_text": score_text,
                "findings": num_of(p, "finding_count").unwrap_or(0.0) as i64,
                "urgent": num_of(p, "urgent_count").unwrap_or(0.0) as i64,
            })
        })
        .collect();

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

    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
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
            "has_field": has_field, "tiles": tiles, "scores": scores,
        },
        "total_findings": total_findings,
        "severity_counts": counts,
        "is_multipage": page_count > 1,
        "significant": significant,
        "minor": minor,
        "pages": page_rows,
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
