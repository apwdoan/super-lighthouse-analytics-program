//! Dev-only: audit URLs into a fresh database and print one line per run.
//!
//!     cargo run --example audit_urls -- <db> <url>...
//!
//! Lighthouse is off unless `SLAP_WORKER_DIR` points at an installed worker
//! (`desktop/worker` after `npm install`); then `CHROME_PATH` picks the
//! browser, `SLAP_LH_SCOPE` (`sampled` | `every_page`) the coverage, and
//! `SLAP_ARTIFACT_DIR` where per-page summaries and LHRs are written.
//! `SLAP_PAGES_PER_SITE` raises the discovery cap from its dev default of 6.
use slap_core::storage;
use slap_engine::{run_batch, EngineConfig};
fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("db path");
    let urls: Vec<String> = args.collect();
    let _ = std::fs::remove_file(&path);
    let conn = storage::open_db(std::path::Path::new(&path)).unwrap();
    let mut settings = slap_core::settings::Settings::default();
    settings.discovery.pages_per_site = std::env::var("SLAP_PAGES_PER_SITE")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(6);
    if let Ok(k) = std::env::var("CRUX_API_KEY") {
        settings.collector.crux_api_key = Some(k);
    }
    let mut cfg = EngineConfig::from_settings(&settings);
    if let Ok(dir) = std::env::var("SLAP_WORKER_DIR") {
        cfg.lighthouse = Some(slap_engine::lighthouse::LighthouseConfig {
            worker_dir: dir.into(),
            chrome_path: std::env::var_os("CHROME_PATH").map(Into::into),
            ..Default::default()
        });
        if let Some(scope) = std::env::var("SLAP_LH_SCOPE")
            .ok()
            .and_then(|s| slap_core::schema::LighthouseScope::parse(&s))
        {
            cfg.lighthouse_scope = scope;
        }
        if let Ok(dir) = std::env::var("SLAP_ARTIFACT_DIR") {
            cfg.artifact_dir = Some(dir.into());
        }
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt
        .block_on(run_batch(&conn, &urls, &cfg, |e| {
            if std::env::var_os("SLAP_VERBOSE").is_some() {
                eprintln!("{}", e.message());
            }
        }))
        .unwrap();
    for r in &summary.runs {
        println!(
            "{:<20} run={} ok={} pages={} obs={} findings={} lighthouse={}/{}",
            r.hostname,
            r.run_id.unwrap_or(0),
            r.ok,
            r.pages,
            r.observations,
            r.findings,
            r.lighthouse_done,
            r.lighthouse_planned
        );
    }
    println!("{}/{} succeeded", summary.succeeded, summary.total);
}
