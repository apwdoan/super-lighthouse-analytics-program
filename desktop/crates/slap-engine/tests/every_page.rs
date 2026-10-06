//! Every-page Lighthouse, Stop, and resume, end to end through the real
//! batch runner, the real database, and a real subprocess.
//!
//! The subprocess is a stand-in worker: a few lines of Node that speak the
//! worker's protocol (`--probe`, one job on stdin, one envelope on stdout) and
//! answer with the recorded slowsite LHR. That keeps the test fast and
//! offline while exercising everything the engine owns: the queue order, the
//! global Lighthouse cap, per-page checkpoints and artifacts, run-level
//! benchmark drift, provenance, Stop, and resume (including the refusal to
//! resume under a different Chrome). Skipped, loudly, where Node is absent.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use slap_core::events::{CancelToken, Event};
use slap_core::schema::{LighthouseScope, Value};
use slap_core::storage;

const PATHS: &[&str] = &[
    "/",
    "/about",
    "/contact",
    "/blog/one",
    "/blog/two",
    "/blog/three",
    "/product/a",
    "/product/b",
];

/// A site with a robots.txt, a sitemap listing `PATHS`, and a page for each.
///
/// A thread per connection and `Connection: close` on every response, so the
/// fixture never makes a pooled client race a keep-alive connection the
/// server is closing (tiny_http's single response loop did, now and then,
/// and dropped a page).
fn start_site() -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let sitemap_base = base.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let sitemap_base = sitemap_base.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                let mut line = String::new();
                while reader.read_line(&mut line).map(|n| n > 2).unwrap_or(false) {
                    line.clear();
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body, kind) = if path == "/robots.txt" {
                    (200, format!("User-agent: *\nSitemap: {sitemap_base}/sitemap.xml\n"), "text/plain")
                } else if path == "/sitemap.xml" {
                    let urls: String = PATHS
                        .iter()
                        .map(|p| format!("<url><loc>{sitemap_base}{p}</loc></url>"))
                        .collect();
                    (200, format!("<urlset>{urls}</urlset>"), "application/xml")
                } else if PATHS.contains(&path.as_str()) {
                    (
                        200,
                        format!("<!doctype html><html><head><title>{path}</title></head><body><h1>{path}</h1></body></html>"),
                        "text/html; charset=utf-8",
                    )
                } else {
                    (404, "not found".to_string(), "text/plain")
                };
                let head_only = request_line.starts_with("HEAD");
                let response = format!(
                    "HTTP/1.1 {status} {}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    if status == 200 { "OK" } else { "Not Found" },
                    body.len(),
                    if head_only { "" } else { &body }
                );
                let mut stream = &stream;
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    format!("{base}/")
}

const FAKE_WORKER: &str = r#"
const fs = require("fs");
const lhVersion = process.env.FAKE_LH_VERSION || "13.4.1";
const chromeVersion = process.env.FAKE_CHROME_VERSION || "141.0.7390.37";
if (process.argv.includes("--probe")) {
  process.stdout.write(JSON.stringify({ ok: true, meta: { lighthouseVersion: lhVersion, chromeVersion } }) + "\n");
  process.exit(0);
}
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (raw += c));
process.stdin.on("end", () => {
  const job = JSON.parse(raw);
  const lhr = JSON.parse(fs.readFileSync(process.env.FAKE_LHR, "utf8"));
  delete lhr.fullPageScreenshot;
  lhr.finalDisplayedUrl = job.url;
  lhr.requestedUrl = job.url;
  // Blog pages were measured on a machine that had slowed down: the drift
  // a long batch produces when a laptop throttles.
  lhr.environment.benchmarkIndex = job.url.includes("/blog/") ? 900 : 1500;
  lhr.categories.performance.score = job.url.includes("/product/") ? 0.41 : 0.63;
  // The about page measures differently every time, as a page on a busy
  // server does, so its runs never agree and it gets all three. Its runs of
  // one measurement are taken in turn, so a count per URL tells them apart.
  if (job.url.endsWith("/about") && process.env.FAKE_COUNT_DIR) {
    fs.mkdirSync(process.env.FAKE_COUNT_DIR, { recursive: true });
    const counter = require("path").join(process.env.FAKE_COUNT_DIR, Buffer.from(job.url).toString("hex"));
    fs.appendFileSync(counter, "x");
    const n = fs.readFileSync(counter, "utf8").length;
    lhr.categories.performance.score = [0.55, 0.7, 0.63][(n - 1) % 3];
  }
  setTimeout(() => {
    process.stdout.write(JSON.stringify({
      ok: true,
      lhr,
      meta: {
        lighthouseVersion: lhVersion,
        chromeVersion: "141.0.0.0",
        throttlingProfile: "mobile/simulate/lh13-default",
        benchmarkIndex: lhr.environment.benchmarkIndex,
      },
    }) + "\n");
  }, Number(process.env.FAKE_DELAY_MS || 60));
});
"#;

fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn config(worker_dir: &Path, artifacts: &Path, scope: LighthouseScope) -> slap_engine::EngineConfig {
    slap_engine::EngineConfig {
        user_agent: "SLAP-test".into(),
        max_redirects: 5,
        max_body_bytes: 1_000_000,
        concurrency: 4,
        timeout_secs: 10,
        crux_api_key: None,
        crux_rate_per_second: 2.0,
        lighthouse: Some(slap_engine::lighthouse::LighthouseConfig {
            runs: 3,
            form_factor: "mobile".into(),
            node_path: "node".into(),
            worker_dir: worker_dir.to_path_buf(),
            chrome_path: Some("/nonexistent/chrome".into()),
            timeout_secs: 30,
        }),
        discovery: slap_engine::discovery::DiscoveryConfig::default(),
        lighthouse_pages: 3,
        lighthouse_scope: scope,
        lighthouse_concurrency: 2,
        lighthouse_runs: 3,
        artifact_dir: Some(artifacts.to_path_buf()),
        keep_lhr: true,
        probe: slap_engine::run::ProbeSettings::default(),
    }
}

fn value(conn: &slap_core::rusqlite::Connection, page_id: i64, key: &str) -> Option<Value> {
    storage::observations_as_dict(conn, page_id).unwrap().remove(key)
}

fn count_obs(conn: &slap_core::rusqlite::Connection, run_id: i64, key: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM observation o JOIN page p ON p.id = o.page_id \
         WHERE p.run_id = ? AND o.metric_key = ?",
        slap_core::rusqlite::params![run_id, key],
        |row| row.get(0),
    )
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn every_page_stop_and_resume() {
    if !node_available() {
        eprintln!("SKIPPED: node is not on PATH, so the stand-in worker cannot run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let worker_dir = dir.path().join("worker");
    std::fs::create_dir_all(&worker_dir).unwrap();
    std::fs::write(worker_dir.join("worker.js"), FAKE_WORKER).unwrap();
    let mut lhr = String::new();
    flate2::read::GzDecoder::new(&include_bytes!("../fixtures/slow-lhr.json.gz")[..])
        .read_to_string(&mut lhr)
        .unwrap();
    let lhr_path = dir.path().join("lhr.json");
    std::fs::write(&lhr_path, lhr).unwrap();
    std::env::set_var("FAKE_LHR", &lhr_path);
    std::env::set_var("FAKE_COUNT_DIR", dir.path().join("counts"));
    std::env::remove_var("FAKE_CHROME_VERSION");
    let artifacts = dir.path().join("artifacts");
    let conn = storage::open_db(&dir.path().join("slap.sqlite3")).unwrap();

    // ------------------------------------------------------------------
    // 1. Every page of two sites, under one global cap of 2.
    // ------------------------------------------------------------------
    let site_a = start_site();
    let site_b = start_site();
    let cfg = config(&worker_dir, &artifacts, LighthouseScope::EveryPage);
    let in_chrome = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let events = Mutex::new(Vec::new());
    let summary = slap_engine::run_batch(&conn, &[site_a.clone(), site_b.clone()], &cfg, |e: Event| {
        match &e {
            Event::PageStarted { .. } => {
                let now = in_chrome.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
            }
            Event::PageFinished { .. } => {
                in_chrome.fetch_sub(1, Ordering::SeqCst);
            }
            _ => {}
        }
        events.lock().unwrap().push(e);
    })
    .await
    .unwrap();

    assert_eq!(summary.succeeded, 2, "{summary:?}");
    assert_eq!(summary.interrupted, 0);
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "the Lighthouse cap is global across sites: peak {}",
        peak.load(Ordering::SeqCst)
    );
    assert!(peak.load(Ordering::SeqCst) >= 2, "and it is actually used");

    for r in &summary.runs {
        let run_id = r.run_id.unwrap();
        let run = storage::get_run(&conn, run_id).unwrap().unwrap();
        assert_eq!(run["status"], "completed");
        assert_eq!(run["lh_scope"], "every_page", "coverage recorded on the run");
        assert!(run["requested_url"].as_str().unwrap().starts_with("http://127.0.0.1"));
        // The probe's precise build, not the user agent's reduced one.
        assert_eq!(run["chrome_version"], "141.0.7390.37");
        assert_eq!(run["lh_version"], "13.4.1");

        let pages = storage::run_pages(&conn, run_id).unwrap();
        assert_eq!(pages.len(), PATHS.len());
        assert_eq!(r.lighthouse_planned, PATHS.len());
        assert_eq!(r.lighthouse_done, PATHS.len());
        for p in &pages {
            let id = p["id"].as_i64().unwrap();
            assert_eq!(p["audit_depth"], "full", "{}", p["url"]);
            // Runs that agree stop at two, since a third could only land the
            // median between them; the about page's never agree.
            if p["url"].as_str().unwrap().ends_with("/about") {
                assert_eq!(value(&conn, id, "lh.runs"), Some(Value::Num(3.0)));
                assert_eq!(value(&conn, id, "lh.score.performance"), Some(Value::Num(63.0)), "55, 70, 63");
                assert_eq!(value(&conn, id, "lh.score.performance.spread"), Some(Value::Num(15.0)));
            } else {
                assert_eq!(value(&conn, id, "lh.runs"), Some(Value::Num(2.0)), "{}", p["url"]);
            }
        }
        // Inventory order is discovery order, home first.
        assert!(pages[0]["url"].as_str().unwrap().ends_with('/'));
        assert!(pages[1]["url"].as_str().unwrap().ends_with("/about"));

        // A summary for every page, and the raw LHR because keep_lhr is on.
        let arts = storage::get_artifacts(&conn, run_id).unwrap();
        let kinds = |k: &str| arts.iter().filter(|a| a["kind"] == k).count();
        assert_eq!(kinds("lh-summary"), PATHS.len());
        assert_eq!(kinds("lhr"), PATHS.len());
        for a in &arts {
            assert!(Path::new(a["path"].as_str().unwrap()).exists());
        }

        // Run-level coverage and drift, on the home page.
        let home = storage::home_page_id(&conn, run_id).unwrap().unwrap();
        assert_eq!(value(&conn, home, "lh.run.pages_measured"), Some(Value::Num(8.0)));
        assert_eq!(value(&conn, home, "lh.run.benchmark_min"), Some(Value::Num(900.0)));
        assert_eq!(value(&conn, home, "lh.run.benchmark_max"), Some(Value::Num(1500.0)));
        assert_eq!(
            value(&conn, home, "lh.run.scope"),
            Some(Value::Text("Every discovered page".into()))
        );
        let rules: Vec<String> = storage::get_findings(&conn, run_id)
            .unwrap()
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap().to_string())
            .collect();
        assert!(rules.contains(&"lh-benchmark-drift".to_string()), "{rules:?}");
        assert!(rules.contains(&"lh-contended-measurement".to_string()), "blog pages ran slow");
    }

    // Planned before measured, and the representatives first: after home,
    // the first pages into Chrome cover distinct templates.
    let events = events.into_inner().unwrap();
    let first_started = events
        .iter()
        .position(|e| matches!(e, Event::PageStarted { .. }))
        .unwrap();
    assert!(events[..first_started]
        .iter()
        .any(|e| matches!(e, Event::PagesPlanned { lighthouse_pages: 8, .. })));

    // ------------------------------------------------------------------
    // 2. Stop after three pages, then resume: nothing measured twice.
    // ------------------------------------------------------------------
    let cancel = CancelToken::new();
    let finished = AtomicUsize::new(0);
    let summary = slap_engine::run_batch_controlled(&conn, std::slice::from_ref(&site_a), &cfg, &cancel, |e: Event| {
        if matches!(e, Event::PageFinished { .. }) && finished.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
            cancel.cancel();
        }
    })
    .await
    .unwrap();
    assert_eq!(summary.interrupted, 1, "{summary:?}");
    let run_id = summary.runs[0].run_id.unwrap();
    let run = storage::get_run(&conn, run_id).unwrap().unwrap();
    assert_eq!(run["status"], "running", "stopped, not failed: resumable");
    let done_before = count_obs(&conn, run_id, "lh.runs");
    assert!((3..8).contains(&done_before), "{done_before} pages measured before Stop");
    assert!(storage::get_findings(&conn, run_id).unwrap().is_empty(), "not finalised");
    let unfinished = storage::unfinished_runs(&conn).unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0]["lh_done"], done_before);

    let restarted = AtomicUsize::new(0);
    let resumed = slap_engine::resume_runs(&conn, &[run_id], &cfg, &CancelToken::new(), |e: Event| {
        if matches!(e, Event::PageStarted { .. }) {
            restarted.fetch_add(1, Ordering::SeqCst);
        }
    })
    .await
    .unwrap();
    assert_eq!(resumed.succeeded, 1, "{resumed:?}");
    assert_eq!(resumed.runs[0].run_id, Some(run_id), "resumed in place");
    assert_eq!(
        restarted.load(Ordering::SeqCst) as i64,
        8 - done_before,
        "only the unmeasured pages went back into Chrome"
    );
    assert_eq!(count_obs(&conn, run_id, "lh.runs"), 8, "one result per page, none twice");
    let run = storage::get_run(&conn, run_id).unwrap().unwrap();
    assert_eq!(run["status"], "completed");
    assert!(!storage::get_findings(&conn, run_id).unwrap().is_empty());
    assert!(storage::unfinished_runs(&conn).unwrap().is_empty());

    // ------------------------------------------------------------------
    // 3. A different Chrome since the Stop: a new run, never a mixed one.
    // ------------------------------------------------------------------
    let cancel = CancelToken::new();
    let finished = AtomicUsize::new(0);
    let summary = slap_engine::run_batch_controlled(&conn, std::slice::from_ref(&site_b), &cfg, &cancel, |e: Event| {
        if matches!(e, Event::PageFinished { .. }) && finished.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
            cancel.cancel();
        }
    })
    .await
    .unwrap();
    let old_run = summary.runs[0].run_id.unwrap();
    std::env::set_var("FAKE_CHROME_VERSION", "142.0.7444.59");
    let resumed = slap_engine::resume_runs(&conn, &[old_run], &cfg, &CancelToken::new(), |_| {})
        .await
        .unwrap();
    std::env::remove_var("FAKE_CHROME_VERSION");
    let old = storage::get_run(&conn, old_run).unwrap().unwrap();
    assert_eq!(old["status"], "cancelled");
    assert!(
        old["error"].as_str().unwrap().contains("Chrome changed from 141.0.7390.37 to 142.0.7444.59"),
        "{}",
        old["error"]
    );
    let new_run = resumed.runs[0].run_id.unwrap();
    assert_ne!(new_run, old_run);
    let new = storage::get_run(&conn, new_run).unwrap().unwrap();
    assert_eq!(new["status"], "completed");
    assert_eq!(new["batch_id"], old["batch_id"], "the site stays in its batch");
    assert_eq!(new["chrome_version"], "142.0.7444.59");
    assert_eq!(count_obs(&conn, new_run, "lh.runs"), 8);

    // ------------------------------------------------------------------
    // 4. Sampled mode is unchanged: one per template, budget of 3.
    // ------------------------------------------------------------------
    let cfg = config(&worker_dir, &artifacts, LighthouseScope::Sampled);
    let summary = slap_engine::run_batch(&conn, std::slice::from_ref(&site_a), &cfg, |_| {}).await.unwrap();
    let run_id = summary.runs[0].run_id.unwrap();
    assert_eq!(storage::get_run(&conn, run_id).unwrap().unwrap()["lh_scope"], "sampled");
    let depths: HashMap<String, String> = storage::run_pages(&conn, run_id)
        .unwrap()
        .iter()
        .map(|p| (p["url"].as_str().unwrap().to_string(), p["audit_depth"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(depths.values().filter(|d| *d == "full").count(), 3);
    assert_eq!(count_obs(&conn, run_id, "lh.runs"), 3);
    let home = storage::home_page_id(&conn, run_id).unwrap().unwrap();
    assert_eq!(
        value(&conn, home, "lh.run.scope"),
        Some(Value::Text("One page per template".into()))
    );

    // And the report renders every one of these runs, in Lighthouse's
    // visual language and in plain words, saying what was tested.
    let html = slap_engine::report::render_html(&conn, new_run).unwrap();
    assert!(html.contains("All 8 pages found on the site were tested."));
    assert!(html.contains("Across the site"));
    assert!(html.contains("class=\"gauge average"), "the home page's 63 is an average gauge");
    assert!(
        html.contains("Images are bigger than they need to be"),
        "audits come from the stored summaries, retitled as the problem they describe"
    );
    assert!(html.contains("Most common problems"));
    // Seven pages agreed after two tests and the about page took three: the
    // report says so, rather than claiming three for every page.
    assert!(html.contains("Each page tested was loaded 2 or 3 times with Google Lighthouse"));
    assert!(html.contains("Testing stops early on a page whose first tests already agree to within 2 points"));
    assert!(html.contains("(the average of 2 tests)"), "the home page's two tests agreed");
    assert!(html.contains("2 or 3, middle result used"));
    // Product pages score 41 against a typical 63: outliers, so they have a
    // section; the page table still lists every page.
    assert!(html.contains("Performance 41 (typical page: 63)"));
    assert!(html.contains("/product/a") && html.contains("/blog/three"));
    // The drift finding describes the test machine, not the site: a note on
    // the results rather than something to fix.
    assert!(html.contains("Notes on these results"));
    assert!(
        html.contains("The testing computer&#x27;s speed changed")
            || html.contains("The testing computer's speed changed")
    );
    let sampled = slap_engine::report::render_html(&conn, run_id).unwrap();
    assert!(sampled.contains("3 of 8 pages were tested: one of each type of page"));
}
