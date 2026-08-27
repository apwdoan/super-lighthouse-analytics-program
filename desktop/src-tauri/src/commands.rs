//! The IPC surface: storage reads the UI calls, over one managed database
//! connection.
//!
//! Every command is a thin adapter. The queries live in `slap_core::storage`
//! (tested there); these functions lock the connection, call one, and hand
//! back the JSON the storage layer already produces. Business logic that grew
//! in here would be logic the core's tests do not cover, so it does not grow
//! here.
//!
//! The connection is opened once at startup and shared behind a mutex. A
//! rusqlite `Connection` is not `Sync`, and the reads are sub-millisecond, so
//! a mutex is both necessary and cheap; nothing holds it across an await
//! because these are not async.

use std::sync::Mutex;

use serde_json::{json, Value as Json};
use slap_core::storage;
use tauri::State;

/// The database, or the reason it could not be opened. A data app whose
/// database will not open still has to render, and telling the user why beats
/// a blank window, so the failure is carried as state rather than aborting
/// startup.
pub enum Db {
    Open(slap_core::rusqlite::Connection),
    Broken(String),
}

pub struct AppState {
    pub db: Mutex<Db>,
}

impl AppState {
    pub fn open(path: &std::path::Path) -> Self {
        let db = match storage::open_db(path) {
            Ok(conn) => Db::Open(conn),
            Err(error) => Db::Broken(format!("could not open {}: {error}", path.display())),
        };
        Self { db: Mutex::new(db) }
    }
}

/// Lock the connection and hand it to a query, or surface the open error.
fn with_conn<T>(
    state: &State<'_, AppState>,
    query: impl FnOnce(&slap_core::rusqlite::Connection) -> slap_core::rusqlite::Result<T>,
) -> Result<T, String> {
    let guard = state
        .db
        .lock()
        .map_err(|_| "database lock poisoned".to_string())?;
    match &*guard {
        Db::Broken(reason) => Err(reason.clone()),
        Db::Open(conn) => query(conn).map_err(|error| error.to_string()),
    }
}

/// The trend metrics a site page charts: the lab performance score and the
/// field + lab LCP. Kept in one place so the command and any future export
/// agree on what "the trend" is.
const TREND_METRICS: &[&str] = &["lh.score.performance", "crux.lcp.p75", "lh.lcp"];

#[tauri::command]
pub fn list_sites(state: State<'_, AppState>) -> Result<Json, String> {
    with_conn(&state, |conn| storage::list_sites(conn, 500)).map(Json::from)
}

/// One site: its record, its run history, the trend series, and the open
/// findings from its most recent completed run. Composed here rather than in
/// five round trips from the front end.
#[tauri::command]
pub fn site_overview(state: State<'_, AppState>, site_id: i64) -> Result<Json, String> {
    with_conn(&state, |conn| {
        let site = storage::get_site(conn, site_id)?;
        let runs = storage::site_runs(conn, site_id, 100)?;
        let trend = storage::site_metric_history(conn, site_id, TREND_METRICS, 60)?;
        // The latest completed run anchors the findings panel; a failed run
        // has no meaningful findings and must not stand in for one.
        let latest_completed = runs
            .iter()
            .find(|run| run["status"] == "completed")
            .and_then(|run| run["id"].as_i64());
        let findings = match latest_completed {
            Some(run_id) => storage::get_findings(conn, run_id)?,
            None => Vec::new(),
        };
        Ok(json!({
            "site": site,
            "runs": runs,
            "trend": trend,
            "latest_run_id": latest_completed,
            "findings": findings,
        }))
    })
}

/// One run as the client would see it: the run row, its pages, its findings
/// (severity-ordered by the query), and the raw observations behind them.
#[tauri::command]
pub fn run_report(state: State<'_, AppState>, run_id: i64) -> Result<Json, String> {
    with_conn(&state, |conn| {
        Ok(json!({
            "run": storage::get_run(conn, run_id)?,
            "pages": storage::run_pages(conn, run_id)?,
            "findings": storage::get_findings(conn, run_id)?,
            "observations": storage::get_observations(conn, run_id)?,
        }))
    })
}

#[tauri::command]
pub fn findings_across_sites(state: State<'_, AppState>) -> Result<Json, String> {
    with_conn(&state, |conn| storage::findings_across_sites(conn, 200)).map(Json::from)
}

/// What the Sites screen shows when the database has no completed runs yet:
/// enough to tell "brand new" from "something is wrong".
#[tauri::command]
pub fn library_status(state: State<'_, AppState>) -> Result<Json, String> {
    with_conn(&state, |conn| {
        Ok(json!({
            "sites_with_history": storage::count_sites_with_a_completed_run(conn)?,
        }))
    })
}

/// Run a no-browser audit of the given URLs and return a summary.
///
/// The work happens on a dedicated thread with its own current-thread
/// runtime, for two reasons: reqwest needs a runtime, and a fresh thread
/// avoids any "cannot block inside a runtime" hazard if Tauri ever dispatches
/// this on a runtime thread. It uses its OWN database connection, not the
/// managed read connection: WAL lets the audit write while the UI keeps
/// reading, and keeping the writer separate means the read lock is never held
/// across the network.
///
/// Progress is emitted to the window as `slap://progress` events as it goes;
/// the return value is the whole summary for the composer to act on.
///
/// When `lighthouse` is set, the browser audit runs on a sample of pages: the
/// bundled Node worker drives a Chromium the app fetches on first run. If the
/// prerequisites are missing (no Node, no worker resources), the audit fails
/// with a specific reason rather than silently skipping the lab run.
#[tauri::command]
pub fn start_audit(
    app: tauri::AppHandle,
    urls: Vec<String>,
    lighthouse: bool,
) -> Result<Json, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(run_audit_blocking(app, urls, lighthouse));
    });
    rx.recv()
        .map_err(|_| "the audit thread stopped unexpectedly".to_string())?
}

/// Locate the bundled Lighthouse worker directory (holds `worker.js` and its
/// `node_modules`). In an installed app it is a bundled resource; in a dev
/// run it is `desktop/worker` beside the crate.
fn worker_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    if let Ok(res) = app.path().resource_dir() {
        let candidate = res.join("worker");
        if candidate.join("worker.js").exists() {
            return Some(candidate);
        }
    }
    // Dev fallback: the repo's worker directory.
    let dev = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../worker");
    dev.join("worker.js").exists().then_some(dev)
}

fn run_audit_blocking(
    app: tauri::AppHandle,
    urls: Vec<String>,
    lighthouse: bool,
) -> Result<Json, String> {
    use tauri::Emitter;

    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    let mut cfg = slap_engine::EngineConfig::from_settings(&settings);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let conn = storage::open_db(&settings.db_path).map_err(|e| e.to_string())?;

    if lighthouse {
        let dir = worker_dir(&app).ok_or_else(|| {
            "Lighthouse needs its bundled worker, which is missing from this \
             install. Reinstall SLAP, or uncheck Lighthouse."
                .to_string()
        })?;
        // The pinned Chromium: use one already present, or fetch Chrome for
        // Testing on first run. This can take a minute the first time.
        let chrome = runtime
            .block_on(slap_engine::lighthouse::resolve_or_fetch_chrome())
            .map_err(|e| format!("could not obtain Chromium for Lighthouse: {e}"))?;
        cfg.lighthouse = Some(slap_engine::lighthouse::LighthouseConfig {
            runs: 3,
            form_factor: "mobile".into(),
            node_path: "node".into(),
            worker_dir: dir,
            chrome_path: Some(chrome),
            timeout_secs: cfg.timeout_secs.max(150),
        });
    }

    let summary = runtime.block_on(slap_engine::run_batch(&conn, &urls, &cfg, |event| {
        // A dropped event must not fail the audit; the summary is the source
        // of truth and the events are a live convenience.
        let _ = app.emit("slap://progress", &event);
    }))?;
    serde_json::to_value(summary).map_err(|e| e.to_string())
}
