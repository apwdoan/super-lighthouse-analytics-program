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

/// One Lighthouse run against a URL. Returns the extracted values and the run
/// meta (version, chrome, benchmarkIndex, throttling profile).
pub async fn run_once(
    url: &str,
    cfg: &LighthouseConfig,
) -> Result<(HashMap<String, f64>, Json), String> {
    use tokio::io::AsyncWriteExt;

    let worker_js = cfg.worker_dir.join("worker.js");
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

    let mut command = tokio::process::Command::new(&cfg.node_path);
    command
        .arg(&worker_js)
        .env("CHROME_PATH", &chrome)
        .current_dir(&cfg.worker_dir)
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
    let values = extract_values(&envelope["lhr"]);
    Ok((values, envelope["meta"].clone()))
}

/// Run Lighthouse `cfg.runs` times against a URL and aggregate the median.
/// Returns the observations plus the meta from the first successful run (for
/// run provenance). An empty result means every run failed.
pub async fn run_median(url: &str, cfg: &LighthouseConfig) -> (Vec<Observation>, Option<Json>) {
    let mut runs = Vec::new();
    let mut meta = None;
    let mut last_error = None;
    for _ in 0..cfg.runs.max(1) {
        match run_once(url, cfg).await {
            Ok((values, run_meta)) => {
                if meta.is_none() {
                    meta = Some(run_meta);
                }
                runs.push(values);
            }
            Err(e) => last_error = Some(e),
        }
    }
    if runs.is_empty() {
        // Record the reason so the report can say the browser audit was
        // attempted and failed, not that it was never run.
        let mut out = vec![obs("lh.runs", Value::Num(0.0)).unwrap()];
        if let Some(e) = last_error {
            if let Ok(o) = obs("lh.throttling_profile", Value::from(format!("failed: {e}"))) {
                out.push(o);
            }
        }
        return (out, None);
    }
    (aggregate(&runs, meta.as_ref()), meta)
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
    fn envelope_is_found_despite_stderr_noise_on_stdout() {
        let stdout = "some log line\n{\"ok\":true,\"lhr\":{},\"meta\":{}}\n";
        let env = parse_envelope(stdout).unwrap();
        assert_eq!(env["ok"], Json::Bool(true));
    }
}
