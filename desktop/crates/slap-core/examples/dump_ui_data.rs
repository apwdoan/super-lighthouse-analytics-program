//! Dump the JSON the shell's read commands return for the seeded database,
//! so the UI can be rendered against real data shapes without a live window.
//!
//! The composition here mirrors `src-tauri/src/commands.rs` deliberately: if
//! the two drift, the rendered screenshots stop matching the app, which is
//! the signal to re-sync them. Run:
//!   cargo run -p slap-core --example dump_ui_data -- /tmp/slap-demo.sqlite3

use serde_json::json;
use slap_core::storage;

const TREND_METRICS: &[&str] = &["lh.score.performance", "crux.lcp.p75", "lh.lcp"];

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/slap-demo.sqlite3".into());
    let conn = storage::open_db(std::path::Path::new(&path)).unwrap();

    let sites = storage::list_sites(&conn, 500).unwrap();
    let first_site = sites[0]["id"].as_i64().unwrap();

    // site_overview(first_site)
    let runs = storage::site_runs(&conn, first_site, 100).unwrap();
    let latest = runs
        .iter()
        .find(|r| r["status"] == "completed")
        .and_then(|r| r["id"].as_i64());
    let overview = json!({
        "site": storage::get_site(&conn, first_site).unwrap(),
        "runs": runs,
        "trend": storage::site_metric_history(&conn, first_site, TREND_METRICS, 60).unwrap(),
        "latest_run_id": latest,
        "findings": storage::get_findings(&conn, latest.unwrap()).unwrap(),
    });

    // run_report(latest)
    let run_id = latest.unwrap();
    let report = json!({
        "run": storage::get_run(&conn, run_id).unwrap(),
        "pages": storage::run_pages(&conn, run_id).unwrap(),
        "findings": storage::get_findings(&conn, run_id).unwrap(),
        "observations": storage::get_observations(&conn, run_id).unwrap(),
    });

    let bundle = json!({
        "list_sites": sites,
        "site_overview": overview,
        "run_report": report,
        "findings_across_sites": storage::findings_across_sites(&conn, 200).unwrap(),
        "app_status": {
            "name": "SLAP", "version": "0.1.0", "core_version": "0.1.0",
            "webview": "WebKitGTK 2.52.3", "data_dir": "/home/you/.local/share/slap",
            "db_path": path, "rules_loaded": 63,
        },
        "ids": { "site": first_site, "run": run_id },
    });
    println!("{}", serde_json::to_string(&bundle).unwrap());
}
