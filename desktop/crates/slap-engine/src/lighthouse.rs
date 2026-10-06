//! The Lighthouse runner: drives the Node worker as a subprocess, takes the
//! median of N runs, and records the spread. The worker itself
//! (`worker/worker.js`) is carried over unchanged.
//!
//! Why a subprocess and not a Rust Lighthouse: Lighthouse is Node-only, and
//! the language boundary the roadmap drew ("Node owns everything that touches
//! a browser") survives the rewrite. The worker is deliberately dumb: it
//! reads one job on stdin, writes one `{ok, lhr, meta}` envelope on stdout,
//! and exits. Everything downstream of "what did Chrome measure" is here.
//!
//! Two disciplines carried over:
//! - **Median of N, spread recorded.** A single run is noise; the median goes
//!   in the report and the spread beside it, so a wide spread is visible.
//! - **benchmarkIndex captured every run.** It is Lighthouse's own CPU
//!   measure of the machine taking the measurement; a value that sags mid
//!   batch is direct evidence of the contention that silently inflates TBT.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use slap_core::schema::{obs, Observation, Value, LIGHTHOUSE_OPPORTUNITIES};

const CATEGORY_KEYS: &[(&str, &str)] = &[
    ("performance", "lh.score.performance"),
    ("accessibility", "lh.score.accessibility"),
    ("best-practices", "lh.score.best_practices"),
    ("seo", "lh.score.seo"),
];

const METRIC_AUDITS: &[(&str, &str)] = &[
    ("largest-contentful-paint", "lh.lcp"),
    ("first-contentful-paint", "lh.fcp"),
    ("total-blocking-time", "lh.tbt"),
    ("cumulative-layout-shift", "lh.cls"),
    ("speed-index", "lh.speed_index"),
    ("interactive", "lh.tti"),
    ("server-response-time", "lh.server_response"),
    ("total-byte-weight", "lh.total_bytes"),
    ("bootup-time", "lh.bootup_time"),
    ("mainthread-work-breakdown", "lh.mainthread_work"),
    ("dom-size-insight", "lh.dom_elements"),
];

const SPREAD_KEYS: &[(&str, &str)] = &[
    ("lh.lcp", "lh.lcp.spread"),
    ("lh.tbt", "lh.tbt.spread"),
    ("lh.score.performance", "lh.score.performance.spread"),
    ("lh.benchmark_index", "lh.benchmark_index.spread"),
];

/// Estimated milliseconds saved by fixing an audit. Lighthouse 13 insight
/// audits report `metricSavings: {FCP, LCP, INP}`; classic diagnostics use
/// `details.overallSavingsMs` or a millisecond `numericValue`. Reading the
/// wrong one yields None everywhere and rules that never fire. An insight
/// with no metricSavings has nothing to offer and must NOT fall back to
/// numericValue: for dom-size-insight that is an element count, and
/// "9000ms saving" would be nonsense.
fn audit_savings(audit: &Json, audit_id: &str) -> Option<f64> {
    if let Some(savings) = audit.get("metricSavings").and_then(|s| s.as_object()) {
        let max = savings
            .values()
            .filter_map(|v| v.as_f64())
            .fold(None, |acc: Option<f64>, v| {
                Some(acc.map_or(v, |a| a.max(v)))
            });
        if let Some(m) = max {
            return Some(m);
        }
    }
    if audit_id.ends_with("-insight") {
        return None;
    }
    if let Some(overall) = audit
        .get("details")
        .and_then(|d| d.get("overallSavingsMs"))
        .and_then(|v| v.as_f64())
    {
        return Some(overall);
    }
    if audit.get("numericUnit").and_then(|u| u.as_str()) == Some("millisecond") {
        if let Some(v) = audit.get("numericValue").and_then(|v| v.as_f64()) {
            return Some(v);
        }
    }
    None
}

/// Pure: one LHR to `{metric_key: numeric_value}`. Opportunities are emitted
/// only when the saving is positive, so a rule firing on `gt: 0` means a
/// genuine quantified saving rather than an audit that merely ran.
pub fn extract_values(lhr: &Json) -> HashMap<String, f64> {
    let mut values = HashMap::new();
    let audits = &lhr["audits"];

    for (category_id, key) in CATEGORY_KEYS {
        if let Some(score) = lhr["categories"][*category_id]["score"].as_f64() {
            values.insert(key.to_string(), (score * 100.0).round());
        }
    }
    for (audit_id, key) in METRIC_AUDITS {
        if let Some(v) = audits[*audit_id]
            .get("numericValue")
            .and_then(|v| v.as_f64())
        {
            values.insert(key.to_string(), v);
        }
    }
    for (audit_id, suffix, _label) in LIGHTHOUSE_OPPORTUNITIES {
        let audit = &audits[*audit_id];
        if audit.is_null() {
            continue;
        }
        if let Some(saving) = audit_savings(audit, audit_id) {
            if saving > 0.0 {
                values.insert(format!("lh.opp.{suffix}"), (saving * 10.0).round() / 10.0);
            }
        }
    }
    if let Some(benchmark) = lhr["environment"]["benchmarkIndex"].as_f64() {
        values.insert(
            "lh.benchmark_index".to_string(),
            (benchmark * 10.0).round() / 10.0,
        );
    }
    values
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = xs.len();
    if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    }
}

/// Median across runs, plus the spread for the metrics that matter. A metric
/// present in only some runs is aggregated over the runs that have it, not
/// treated as zero.
pub fn aggregate(runs: &[HashMap<String, f64>], meta: Option<&Json>) -> Vec<Observation> {
    if runs.is_empty() {
        return Vec::new();
    }
    let mut keys: Vec<String> = runs.iter().flat_map(|r| r.keys().cloned()).collect();
    keys.sort();
    keys.dedup();

    let spread_map: HashMap<&str, &str> = SPREAD_KEYS.iter().copied().collect();
    let mut out = Vec::new();
    for key in &keys {
        let present: Vec<f64> = runs.iter().filter_map(|r| r.get(key).copied()).collect();
        if present.is_empty() {
            continue;
        }
        let mut m = median(present.clone());
        // Scores and element counts are integers; don't render 91.5.
        if key.starts_with("lh.score.") || key == "lh.dom_elements" {
            m = m.round();
        } else {
            m = (m * 10.0).round() / 10.0;
        }
        if let Ok(o) = obs(key, Value::Num(m)) {
            out.push(o);
        }
        if let Some(spread_key) = spread_map.get(key.as_str()) {
            if present.len() > 1 {
                let spread = present.iter().cloned().fold(f64::MIN, f64::max)
                    - present.iter().cloned().fold(f64::MAX, f64::min);
                if let Ok(o) = obs(spread_key, Value::Num((spread * 10.0).round() / 10.0)) {
                    out.push(o);
                }
            }
        }
    }
    out.push(obs("lh.runs", Value::Num(runs.len() as f64)).unwrap());
    if let Some(meta) = meta {
        if let Some(profile) = meta["throttlingProfile"].as_str() {
            out.push(obs("lh.throttling_profile", Value::from(profile)).unwrap());
        }
        if let Some(form) = meta["formFactor"].as_str() {
            out.push(obs("lh.form_factor", Value::from(form)).unwrap());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LighthouseConfig {
    pub runs: usize,
    pub form_factor: String,
    pub node_path: String,
    /// The directory holding `worker.js` and its `node_modules`.
    pub worker_dir: PathBuf,
    /// The Chrome/Chromium executable. Resolved by `resolve_chrome` when None.
    pub chrome_path: Option<PathBuf>,
    pub timeout_secs: u64,
}

impl Default for LighthouseConfig {
    fn default() -> Self {
        Self {
            runs: 3,
            form_factor: "mobile".into(),
            node_path: "node".into(),
            worker_dir: PathBuf::from("worker"),
            chrome_path: None,
            timeout_secs: 150,
        }
    }
}

/// The one envelope the worker emits, found by scanning stdout for a JSON
/// object carrying `ok` (diagnostics go to stderr, so stdout is parseable,
/// but a stray line must not defeat the parse).
fn parse_envelope(stdout: &str) -> Option<Json> {
    for line in stdout.lines().rev() {
        let line = line.trim();
        if line.starts_with('{') {
            if let Ok(json) = serde_json::from_str::<Json>(line) {
                if json.get("ok").is_some() {
                    return Some(json);
                }
            }
        }
    }
    None
}

/// One Lighthouse run against a URL. Returns the extracted values, the run
/// meta (version, chrome, benchmarkIndex, throttling profile), and the raw
/// LHR, which the caller summarises once and may keep.
pub async fn run_once(
    url: &str,
    cfg: &LighthouseConfig,
) -> Result<(HashMap<String, f64>, Json, Json), String> {
    use tokio::io::AsyncWriteExt;

    // Plain paths: Node cannot start a script from a Windows verbatim path,
    // the kind Tauri's resource folder comes as (see `spawn`).
    let worker_dir = crate::spawn::plain(&cfg.worker_dir);
    let worker_js = worker_dir.join("worker.js");
    if !worker_js.exists() {
        return Err(format!("worker.js not found at {}", worker_js.display()));
    }
    let chrome = match &cfg.chrome_path {
        Some(p) => p.clone(),
        None => resolve_chrome()
            .ok_or_else(|| "no Chrome/Chromium found; set a chrome path".to_string())?,
    };

    let job = serde_json::json!({
        "url": url,
        "formFactor": cfg.form_factor,
        "categories": ["performance", "accessibility", "best-practices", "seo"],
    });

    // No console window per run on Windows (see `spawn`).
    let mut command = crate::spawn::tokio_command(crate::spawn::plain(&cfg.node_path));
    command
        .arg(&worker_js)
        .env("CHROME_PATH", crate::spawn::plain(&chrome))
        .current_dir(&worker_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start node: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(job.to_string().as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stdin.shutdown().await.ok();
    }
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(cfg.timeout_secs),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| "lighthouse run timed out".to_string())?
    .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope = parse_envelope(&stdout).ok_or_else(|| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!(
            "no envelope from worker; stderr: {}",
            stderr.trim().chars().take(300).collect::<String>()
        )
    })?;

    if envelope["ok"].as_bool() != Some(true) {
        let code = envelope["code"].as_str().unwrap_or("unknown");
        let error = envelope["error"].as_str().unwrap_or("");
        return Err(format!(
            "lighthouse {code}: {}",
            error.chars().take(200).collect::<String>()
        ));
    }
    let mut envelope = envelope;
    let lhr = envelope["lhr"].take();
    let values = extract_values(&lhr);
    Ok((values, envelope["meta"].take(), lhr))
}

/// Everything one page's browser audit produced: the aggregated observations
/// (median of N with spread), the meta of the first successful run (for
/// provenance), and the median run's LHR plus its compact summary.
///
/// "The median run" is the run whose performance score is the median: the
/// metric values in the observations are per-metric medians, which can come
/// from different runs, so the audit list shown beside them comes from the
/// run that is most representative overall rather than from whichever ran
/// first.
#[derive(Debug, Default)]
pub struct PageMeasurement {
    pub observations: Vec<Observation>,
    pub meta: Option<Json>,
    pub summary: Option<Json>,
    pub lhr: Option<Json>,
    pub runs_ok: usize,
    pub error: Option<String>,
}

impl PageMeasurement {
    pub fn performance(&self) -> Option<f64> {
        self.observations
            .iter()
            .find(|o| o.metric_key == "lh.score.performance")
            .and_then(|o| o.numeric_value)
    }
}

/// Index of the run whose performance score is the median. Runs without a
/// score sort last, so they are only chosen when nothing has one.
pub fn median_run_index(runs: &[HashMap<String, f64>]) -> Option<usize> {
    if runs.is_empty() {
        return None;
    }
    let mut order: Vec<usize> = (0..runs.len()).collect();
    order.sort_by(|a, b| {
        let sa = runs[*a].get("lh.score.performance").copied();
        let sb = runs[*b].get("lh.score.performance").copied();
        match (sa, sb) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    let scored = runs
        .iter()
        .filter(|r| r.contains_key("lh.score.performance"))
        .count();
    let pick = if scored > 0 { (scored - 1) / 2 } else { 0 };
    Some(order[pick])
}

/// Run Lighthouse `cfg.runs` times against a URL and aggregate the median,
/// keeping the median run's report. An empty `runs_ok` means every run
/// failed; the observations then still record that the audit was attempted
/// (`lh.runs = 0`) and why, so the report can say "failed", not "skipped".
pub async fn measure_page(url: &str, cfg: &LighthouseConfig) -> PageMeasurement {
    let mut runs = Vec::new();
    let mut lhrs = Vec::new();
    let mut meta = None;
    let mut last_error = None;
    for _ in 0..cfg.runs.max(1) {
        match run_once(url, cfg).await {
            Ok((values, run_meta, lhr)) => {
                if meta.is_none() {
                    meta = Some(run_meta);
                }
                runs.push(values);
                lhrs.push(lhr);
            }
            Err(e) => last_error = Some(e),
        }
    }
    if runs.is_empty() {
        let mut out = vec![obs("lh.runs", Value::Num(0.0)).unwrap()];
        if let Some(e) = &last_error {
            if let Ok(o) = obs("lh.throttling_profile", Value::from(format!("failed: {e}"))) {
                out.push(o);
            }
        }
        return PageMeasurement {
            observations: out,
            error: last_error.or_else(|| Some("no run succeeded".into())),
            ..Default::default()
        };
    }
    let median = median_run_index(&runs).unwrap_or(0);
    let lhr = lhrs.swap_remove(median);
    PageMeasurement {
        observations: aggregate(&runs, meta.as_ref()),
        summary: Some(summarize_lhr(&lhr)),
        lhr: Some(lhr),
        meta,
        runs_ok: runs.len(),
        error: None,
    }
}

/// Run Lighthouse `cfg.runs` times against a URL and aggregate the median.
/// Returns the observations plus the meta from the first successful run (for
/// run provenance). An empty result means every run failed.
pub async fn run_median(url: &str, cfg: &LighthouseConfig) -> (Vec<Observation>, Option<Json>) {
    let m = measure_page(url, cfg).await;
    (m.observations, m.meta)
}

/// Ask the worker which Lighthouse and which Chrome it will measure with,
/// without measuring anything. Chrome's user-agent string carries a REDUCED
/// version (`141.0.0.0`), so an LHR cannot tell two builds of one major apart;
/// the probe asks the browser directly (`141.0.7390.37`). That precision is
/// what lets a resumed run prove it is still being measured by the same
/// engine it started with.
pub async fn probe(cfg: &LighthouseConfig) -> Result<Json, String> {
    let worker_dir = crate::spawn::plain(&cfg.worker_dir);
    let worker_js = worker_dir.join("worker.js");
    if !worker_js.exists() {
        return Err(format!("worker.js not found at {}", worker_js.display()));
    }
    let chrome = match &cfg.chrome_path {
        Some(p) => p.clone(),
        None => resolve_chrome()
            .ok_or_else(|| "no Chrome/Chromium found; set a chrome path".to_string())?,
    };
    // Generous: the first Chrome launch after an install or a reboot can be
    // slow on Windows, and a probe that times out leaves the run with only the
    // reduced version from the user agent.
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(cfg.timeout_secs.max(120)),
        crate::spawn::tokio_command(crate::spawn::plain(&cfg.node_path))
            .arg(&worker_js)
            .arg("--probe")
            .env("CHROME_PATH", crate::spawn::plain(&chrome))
            .current_dir(&worker_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| "the Lighthouse probe timed out".to_string())?
    .map_err(|e| format!("could not start node: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope = parse_envelope(&stdout).ok_or_else(|| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!(
            "no envelope from the probe; stderr: {}",
            stderr.trim().chars().take(300).collect::<String>()
        )
    })?;
    if envelope["ok"].as_bool() != Some(true) {
        return Err(format!(
            "probe failed: {}",
            envelope["error"].as_str().unwrap_or("unknown")
        ));
    }
    Ok(envelope["meta"].clone())
}

// ---------------------------------------------------------------------------
// The compact per-page summary the client report renders from
// ---------------------------------------------------------------------------

/// Lighthouse's own rating bands, applied to a 0-1 audit score: 0.9 and up
/// passes, 0.5 and up is average, below that fails. The same bands colour the
/// category gauges (90 / 50 on the 0-100 scale).
pub fn rating_for_score(score: f64) -> &'static str {
    if score >= 0.9 {
        "pass"
    } else if score >= 0.5 {
        "average"
    } else {
        "fail"
    }
}

/// An audit description with its markdown links reduced to their text and
/// the trailing "Learn more" link dropped. The report is a document, often
/// printed, and a sentence of bracketed URLs is noise in it.
pub fn plain_description(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        // A link is `[text](url)`: the first `]` must be followed at once by
        // `(`, and the `(` must close. Anything else is a literal bracket.
        let link = after.find(']').and_then(|close| {
            let tail = &after[close + 1..];
            if !tail.starts_with('(') {
                return None;
            }
            tail.find(')').map(|end| (close, close + 1 + end + 1))
        });
        match link {
            Some((close, consumed)) => {
                let link_text = &after[..close];
                if !link_text.to_ascii_lowercase().starts_with("learn ") {
                    out.push_str(link_text);
                }
                rest = &after[consumed..];
            }
            None => {
                out.push('[');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    // A dropped "Learn more" link leaves a dangling full stop or space.
    let mut cleaned = out.trim().to_string();
    loop {
        let before = cleaned.len();
        if cleaned.ends_with(" .") || cleaned.ends_with("..") {
            cleaned.pop();
        }
        cleaned = cleaned.trim_end().to_string();
        if cleaned.len() == before {
            break;
        }
    }
    cleaned
}

/// Whether Lighthouse itself would file an audit under "Passed audits".
/// Mirrors the report renderer's `showAsPassed`: manual and not-applicable
/// are counted separately, informative and error never pass, everything
/// else passes at a score of 0.9.
fn audit_passes(audit: &Json) -> bool {
    match audit["scoreDisplayMode"].as_str().unwrap_or("") {
        "informative" | "error" => false,
        _ => audit["score"].as_f64().map(|s| s >= 0.9).unwrap_or(false),
    }
}

fn audit_entry(id: &str, audit: &Json) -> Json {
    let mode = audit["scoreDisplayMode"].as_str().unwrap_or("");
    let score = audit["score"].as_f64();
    let rating = match (mode, score) {
        ("informative", _) | ("error", _) | (_, None) => "informative",
        (_, Some(s)) => rating_for_score(s),
    };
    let savings_ms = audit
        .get("metricSavings")
        .and_then(|s| s.as_object())
        .and_then(|s| s.values().filter_map(|v| v.as_f64()).reduce(f64::max))
        .filter(|ms| *ms > 0.0)
        .or_else(|| audit["details"]["overallSavingsMs"].as_f64().filter(|ms| *ms > 0.0));
    let savings_bytes = audit["details"]["overallSavingsBytes"]
        .as_f64()
        .filter(|b| *b > 0.0);
    let description = plain_description(audit["description"].as_str().unwrap_or(""));
    serde_json::json!({
        "id": id,
        "title": audit["title"].as_str().unwrap_or(id),
        "description": description,
        "display": audit["displayValue"].as_str().unwrap_or("").replace('\u{a0}', " "),
        "score": score,
        "rating": rating,
        "savings_ms": savings_ms.map(|v| v.round()),
        "savings_bytes": savings_bytes.map(|v| v.round()),
    })
}

/// The device, network and CPU the run emulated, in Lighthouse's own words
/// where it has them. This is the "runtime settings" footer of a Lighthouse
/// report, and what makes a number reproducible by someone else.
fn runtime_settings(lhr: &Json) -> Json {
    let cs = &lhr["configSettings"];
    let form = cs["formFactor"].as_str().unwrap_or("mobile");
    let method = cs["throttlingMethod"].as_str().unwrap_or("simulate");
    let t = &cs["throttling"];
    let rtt = t["rttMs"].as_f64().unwrap_or(0.0);
    let kbps = t["throughputKbps"].as_f64().unwrap_or(0.0);
    let cpu = t["cpuSlowdownMultiplier"].as_f64().unwrap_or(1.0);
    let simulated = if method == "simulate" { " (simulated)" } else { "" };
    let network = if form == "mobile" && (rtt - 150.0).abs() < 0.5 && (kbps - 1638.4).abs() < 1.0 {
        format!("Slow 4G throttling{simulated}")
    } else if rtt == 0.0 && kbps == 0.0 {
        "No throttling".to_string()
    } else {
        format!("{rtt:.0} ms RTT, {kbps:.0} Kbps{simulated}")
    };
    let device = if form == "desktop" {
        "Emulated desktop".to_string()
    } else {
        "Emulated Moto G Power".to_string()
    };
    let screen = &cs["screenEmulation"];
    let viewport = match (screen["width"].as_f64(), screen["height"].as_f64()) {
        (Some(w), Some(h)) => Some(format!(
            "{w:.0}x{h:.0}, DPR {}",
            screen["deviceScaleFactor"].as_f64().unwrap_or(1.0)
        )),
        _ => None,
    };
    let host_ua = lhr["environment"]["hostUserAgent"].as_str().unwrap_or("");
    let browser = host_ua
        .split_whitespace()
        .find(|part| part.starts_with("HeadlessChrome/") || part.starts_with("Chrome/"))
        .map(|s| s.replace('/', " "));
    serde_json::json!({
        "device": device,
        "network": network,
        "cpu": if cpu > 1.0 { format!("{cpu:.0}x slowdown{simulated}") } else { "No CPU throttling".into() },
        "viewport": viewport,
        "browser": browser,
        "benchmark_index": lhr["environment"]["benchmarkIndex"].as_f64(),
        "lighthouse_version": lhr["lighthouseVersion"].as_str(),
        "fetch_time": lhr["fetchTime"].as_str(),
    })
}

/// Reduce an LHR (~4MB) to what the client report shows (a few KB): every
/// category's failing and informative audits, grouped as Lighthouse groups
/// them, with how many passed, need a manual check, or did not apply; the
/// five scored metrics with Lighthouse's own rating; and the runtime
/// settings. Extracted once, when the page is measured, so a report never
/// re-parses a raw LHR and works even when raw LHRs are not kept.
pub fn summarize_lhr(lhr: &Json) -> Json {
    let audits = &lhr["audits"];
    let groups = &lhr["categoryGroups"];
    let mut categories = Vec::new();
    for (category_id, _key) in CATEGORY_KEYS {
        let cat = &lhr["categories"][*category_id];
        if cat.is_null() {
            continue;
        }
        let mut group_order: Vec<String> = Vec::new();
        let mut grouped: HashMap<String, Vec<Json>> = HashMap::new();
        let (mut passed, mut manual, mut not_applicable) = (0usize, 0usize, 0usize);
        for aref in cat["auditRefs"].as_array().into_iter().flatten() {
            let id = aref["id"].as_str().unwrap_or("");
            let group = aref["group"].as_str().unwrap_or("");
            if group == "hidden" || (*category_id == "performance" && group == "metrics") {
                continue;
            }
            let audit = &audits[id];
            if audit.is_null() {
                continue;
            }
            match audit["scoreDisplayMode"].as_str().unwrap_or("") {
                "manual" => {
                    manual += 1;
                    continue;
                }
                "notApplicable" => {
                    not_applicable += 1;
                    continue;
                }
                _ => {}
            }
            if audit_passes(audit) {
                passed += 1;
                continue;
            }
            let key = if group.is_empty() { "other" } else { group }.to_string();
            if !grouped.contains_key(&key) {
                group_order.push(key.clone());
            }
            grouped.entry(key).or_default().push(audit_entry(id, audit));
        }
        let rank = |r: &str| match r {
            "fail" => 0,
            "average" => 1,
            _ => 2,
        };
        let mut group_list = Vec::new();
        for key in group_order {
            let mut items = grouped.remove(&key).unwrap_or_default();
            items.sort_by(|a, b| {
                let ra = rank(a["rating"].as_str().unwrap_or(""));
                let rb = rank(b["rating"].as_str().unwrap_or(""));
                let sa = a["savings_ms"].as_f64().unwrap_or(0.0);
                let sb = b["savings_ms"].as_f64().unwrap_or(0.0);
                ra.cmp(&rb)
                    .then(sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal))
            });
            let title = groups[&key]["title"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| if key == "other" { "Other".into() } else { key.clone() });
            group_list.push(serde_json::json!({ "id": key, "title": title, "audits": items }));
        }
        categories.push(serde_json::json!({
            "id": category_id,
            "title": cat["title"].as_str().unwrap_or(category_id),
            "score": cat["score"].as_f64().map(|s| (s * 100.0).round()),
            "groups": group_list,
            "passed": passed,
            "manual": manual,
            "not_applicable": not_applicable,
        }));
    }
    let mut metrics = Vec::new();
    for id in [
        "first-contentful-paint",
        "largest-contentful-paint",
        "total-blocking-time",
        "cumulative-layout-shift",
        "speed-index",
    ] {
        let a = &audits[id];
        if a.is_null() {
            continue;
        }
        metrics.push(serde_json::json!({
            "id": id,
            "title": a["title"].as_str().unwrap_or(id),
            "display": a["displayValue"].as_str().unwrap_or("").replace('\u{a0}', " "),
            "rating": a["score"].as_f64().map(rating_for_score).unwrap_or("informative"),
        }));
    }
    serde_json::json!({
        "v": 1,
        "final_url": lhr["finalDisplayedUrl"].as_str().or(lhr["finalUrl"].as_str()),
        "categories": categories,
        "metrics": metrics,
        "runtime": runtime_settings(lhr),
        "warnings": lhr["runWarnings"].as_array().map(|w| w.iter().filter_map(|x| x.as_str()).map(plain_description).collect::<Vec<_>>()).unwrap_or_default(),
    })
}

/// Find a Chrome/Chromium executable: the CHROME_PATH environment first, then
/// a pinned copy in app data, then the usual install locations. The pinned
/// first-run download (Chrome for Testing) is `ensure_pinned_chromium`.
pub fn resolve_chrome() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CHROME_PATH") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Some(pinned) = pinned_chromium_path() {
        if pinned.exists() {
            return Some(pinned);
        }
    }
    let candidates: &[&str] = if cfg!(windows) {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    } else {
        &[
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/snap/bin/chromium",
        ]
    };
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

/// Where a pinned Chrome for Testing would live in app data. Follows the
/// configured data directory so a relocated install keeps Chromium beside its
/// database; falls back to the default location if the config cannot be read.
fn pinned_chromium_path() -> Option<PathBuf> {
    let base = slap_core::settings::Settings::load(None)
        .map(|s| s.data_dir)
        .unwrap_or_else(|_| slap_core::paths::default_data_dir());
    let dir = base.join("chromium");
    let exe = if cfg!(windows) {
        dir.join("chrome.exe")
    } else if cfg!(target_os = "macos") {
        dir.join("Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing")
    } else {
        dir.join("chrome")
    };
    Some(exe)
}

/// Platform tag for the Chrome for Testing download API.
fn cft_platform() -> &'static str {
    if cfg!(windows) {
        "win64"
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "mac-arm64"
        } else {
            "mac-x64"
        }
    } else {
        "linux64"
    }
}

/// Resolve Chrome for the app: an already-installed/pinned one, else fetch
/// Chrome for Testing. Builds its own HTTP client so the shell need not
/// depend on reqwest.
pub async fn resolve_or_fetch_chrome() -> Result<PathBuf, String> {
    if let Some(p) = resolve_chrome() {
        return Ok(p);
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| e.to_string())?;
    ensure_pinned_chromium(&client).await
}

/// Ensure a pinned Chromium exists, downloading Chrome for Testing on first
/// run. Returns the executable path. Verified in production; in the sandbox
/// the CHROME_PATH branch is used instead (the CfT CDN is outside the egress
/// allowlist).
pub async fn ensure_pinned_chromium(client: &reqwest::Client) -> Result<PathBuf, String> {
    if let Some(existing) = pinned_chromium_path() {
        if existing.exists() {
            return Ok(existing);
        }
    }
    let dir = slap_core::paths::default_data_dir().join("chromium");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // The stable channel's download URLs for every platform.
    let index: Json = client
        .get("https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let downloads = &index["channels"]["Stable"]["downloads"]["chrome"];
    let platform = cft_platform();
    let url = downloads
        .as_array()
        .and_then(|arr| arr.iter().find(|d| d["platform"] == platform))
        .and_then(|d| d["url"].as_str())
        .ok_or_else(|| format!("no Chrome for Testing build for {platform}"))?;

    let zip = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;
    unzip_into(&zip, &dir).map_err(|e| format!("unzip failed: {e}"))?;

    pinned_chromium_path()
        .filter(|p| p.exists())
        .ok_or_else(|| "Chromium not found after extraction".to_string())
}

/// Extract a Chrome for Testing zip, flattening the single top-level
/// `chrome-<platform>/` directory into `dir` so the executable lands where
/// `pinned_chromium_path` expects it. Unix mode bits are preserved so the
/// executable stays executable.
fn unzip_into(bytes: &[u8], dir: &Path) -> std::io::Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        // Drop the leading `chrome-<platform>/` component.
        let stripped: PathBuf = name.components().skip(1).collect();
        if stripped.as_os_str().is_empty() {
            continue;
        }
        let out = dir.join(&stripped);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut file)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn fixture_lhr() -> Json {
        let gz = include_bytes!("../fixtures/slow-lhr.json.gz");
        let mut s = String::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_string(&mut s)
            .unwrap();
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn extract_pulls_scores_metrics_and_opportunities_from_a_real_lhr() {
        let values = extract_values(&fixture_lhr());
        // Category scores are 0-100 integers.
        let perf = values["lh.score.performance"];
        assert!(
            (0.0..=100.0).contains(&perf) && perf.fract() == 0.0,
            "perf score {perf}"
        );
        // The slowsite fixture has real lab metrics.
        assert!(values["lh.lcp"] > 0.0, "LCP present");
        assert!(values.contains_key("lh.tbt"));
        assert_eq!(values["lh.benchmark_index"], 1516.0);
        // At least one opportunity fired with a positive saving.
        assert!(
            values.keys().any(|k| k.starts_with("lh.opp.")),
            "an opportunity fired: {:?}",
            values
                .keys()
                .filter(|k| k.starts_with("lh.opp"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_dom_size_insight_does_not_become_a_millisecond_saving() {
        // dom-size-insight's numericValue is an element count, not ms; with no
        // metricSavings it must yield None, not a bogus saving.
        let audit = serde_json::json!({ "numericValue": 9000, "numericUnit": "element" });
        assert_eq!(audit_savings(&audit, "dom-size-insight"), None);
        // A classic diagnostic with overallSavingsMs is read.
        let classic = serde_json::json!({ "details": { "overallSavingsMs": 1200 } });
        assert_eq!(audit_savings(&classic, "uses-long-cache-ttl"), Some(1200.0));
        // An insight WITH metricSavings takes the max.
        let insight = serde_json::json!({ "metricSavings": { "LCP": 800, "FCP": 300 } });
        assert_eq!(
            audit_savings(&insight, "render-blocking-insight"),
            Some(800.0)
        );
    }

    #[test]
    fn median_and_spread_across_runs() {
        let runs = vec![
            HashMap::from([
                ("lh.lcp".to_string(), 4000.0),
                ("lh.score.performance".to_string(), 40.0),
            ]),
            HashMap::from([
                ("lh.lcp".to_string(), 4400.0),
                ("lh.score.performance".to_string(), 44.0),
            ]),
            HashMap::from([
                ("lh.lcp".to_string(), 4200.0),
                ("lh.score.performance".to_string(), 42.0),
            ]),
        ];
        let v: HashMap<String, Value> = aggregate(&runs, None)
            .into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect();
        assert_eq!(v["lh.lcp"], Value::Num(4200.0), "median of 4000/4200/4400");
        assert_eq!(v["lh.lcp.spread"], Value::Num(400.0), "max - min");
        assert_eq!(v["lh.score.performance"], Value::Num(42.0));
        assert_eq!(v["lh.runs"], Value::Num(3.0));
    }

    #[test]
    fn the_summary_carries_failing_audits_grouped_as_lighthouse_groups_them() {
        let summary = summarize_lhr(&fixture_lhr());
        let cats = summary["categories"].as_array().unwrap();
        assert_eq!(cats.len(), 4, "four categories");
        let perf = &cats[0];
        assert_eq!(perf["id"], "performance");
        assert_eq!(perf["score"], 63.0);
        // The slowsite fixture's worst insight leads its group: image delivery
        // saves 4s of LCP and fails outright.
        let insights = perf["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == "insights")
            .expect("an insights group");
        assert_eq!(insights["title"], "Insights");
        let first = &insights["audits"][0];
        assert_eq!(first["rating"], "fail");
        assert!(first["savings_ms"].as_f64().unwrap() >= 2000.0, "{first}");
        // Metrics never appear as audits; they have their own grid.
        assert!(!perf["groups"].as_array().unwrap().iter().any(|g| g["id"] == "metrics"));
        let metrics = summary["metrics"].as_array().unwrap();
        assert_eq!(metrics.len(), 5);
        assert_eq!(metrics[1]["id"], "largest-contentful-paint");
        assert_eq!(metrics[1]["rating"], "fail");
        assert_eq!(metrics[1]["display"], "9.5 s", "non-breaking space normalised");

        // SEO: the one failing audit is there; the passes are only counted.
        let seo = cats.iter().find(|c| c["id"] == "seo").unwrap();
        let failing: Vec<&str> = seo["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["audits"].as_array().unwrap().iter())
            .filter(|a| a["rating"] == "fail")
            .map(|a| a["id"].as_str().unwrap())
            .collect();
        assert_eq!(failing, vec!["meta-description"]);
        assert!(seo["passed"].as_u64().unwrap() >= 6);
        assert_eq!(seo["manual"], 1);

        // Runtime settings in Lighthouse's own words.
        assert_eq!(summary["runtime"]["network"], "Slow 4G throttling (simulated)");
        assert_eq!(summary["runtime"]["cpu"], "4x slowdown (simulated)");
        assert_eq!(summary["runtime"]["benchmark_index"], 1516.0);

        // Small enough to keep for every page of a 2,000-page batch.
        let bytes = summary.to_string().len();
        assert!(bytes < 40_000, "summary is {bytes} bytes");
    }

    #[test]
    fn descriptions_lose_their_links_but_keep_their_words() {
        assert_eq!(
            plain_description(
                "Low-contrast text is hard to read. [Learn how to provide sufficient color contrast](https://x)."
            ),
            "Low-contrast text is hard to read."
        );
        assert_eq!(
            plain_description("These numbers don't [directly affect](https://x) the score."),
            "These numbers don't directly affect the score."
        );
        assert_eq!(plain_description("No links [here] at all."), "No links [here] at all.");
    }

    #[test]
    fn the_median_run_is_the_one_with_the_median_score() {
        let run = |score: f64| HashMap::from([("lh.score.performance".to_string(), score)]);
        assert_eq!(median_run_index(&[run(40.0), run(90.0), run(60.0)]), Some(2));
        assert_eq!(median_run_index(&[run(70.0)]), Some(0));
        // Two runs: the lower of the two, never a run that has no score.
        assert_eq!(median_run_index(&[HashMap::new(), run(50.0), run(80.0)]), Some(1));
        assert_eq!(median_run_index(&[]), None);
    }

    #[test]
    fn envelope_is_found_despite_stderr_noise_on_stdout() {
        let stdout = "some log line\n{\"ok\":true,\"lhr\":{},\"meta\":{}}\n";
        let env = parse_envelope(stdout).unwrap();
        assert_eq!(env["ok"], Json::Bool(true));
    }
}
