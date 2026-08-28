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

/// Permanently remove a site the user added, and all of its history: its runs
/// (which cascade to pages, observations, findings and artifacts) and the
/// origin's cached CrUX history. Opens its own writer connection (like the
/// audit) so the delete never contends the managed read lock, and unlinks the
/// artifact files after the rows are gone. The UI confirms before calling this.
#[tauri::command]
pub fn delete_site(site_id: i64) -> Result<Json, String> {
    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    let mut conn = storage::open_db(&settings.db_path).map_err(|e| e.to_string())?;
    let (runs, artifacts) =
        storage::delete_site(&mut conn, site_id).map_err(|e| e.to_string())?;
    for path in &artifacts {
        let _ = std::fs::remove_file(path);
    }
    Ok(json!({ "runs_removed": runs, "artifacts_removed": artifacts.len() }))
}

/// The configuration the Settings screen shows. The CrUX key's VALUE is never
/// returned, only whether one is in effect and whether it comes from the
/// environment (which overrides config.toml).
#[tauri::command]
pub fn get_settings() -> Result<Json, String> {
    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    let env_key = std::env::var("CRUX_API_KEY").ok().filter(|k| !k.is_empty());
    let has_key = settings
        .collector
        .crux_api_key
        .as_ref()
        .map(|k| !k.is_empty())
        .unwrap_or(false);
    let brand_name = settings
        .branding
        .get("company_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let brand_logo_set = settings
        .branding
        .get("logo_data_uri")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    Ok(json!({
        "crux_key_set": has_key,
        "crux_key_from_env": env_key.is_some(),
        "data_dir": settings.data_dir.display().to_string(),
        "db_path": settings.db_path.display().to_string(),
        // When SLAP_DB is set it pins the database location regardless of the
        // configured data directory, so the Settings screen says so.
        "db_from_env": std::env::var_os("SLAP_DB").is_some(),
        "brand_name": brand_name,
        "brand_logo_set": brand_logo_set,
    }))
}

/// Save the CrUX API key to `[collector] crux_api_key` in config.toml, or clear
/// it when given an empty string. An environment variable, if set, still
/// overrides this at load time. The key value is written, never logged or
/// returned.
#[tauri::command]
pub fn set_crux_key(key: String) -> Result<Json, String> {
    use slap_core::settings::{save_setting, SettingValue};
    let trimmed = key.trim();
    let value = (!trimmed.is_empty()).then(|| SettingValue::Str(trimmed.to_string()));
    let saved = value.is_some();
    let path = save_setting("crux_api_key", value, Some("collector"), None)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "saved": saved, "config": path.display().to_string() }))
}

/// Save (or clear, when empty) the brand name shown at the top of exported
/// reports. Stored in `[branding] company_name`.
#[tauri::command]
pub fn set_brand_name(name: String) -> Result<Json, String> {
    use slap_core::settings::{save_setting, SettingValue};
    let trimmed = name.trim();
    let value = (!trimmed.is_empty()).then(|| SettingValue::Str(trimmed.to_string()));
    let saved = value.is_some();
    save_setting("company_name", value, Some("branding"), None).map_err(|e| e.to_string())?;
    Ok(json!({ "saved": saved }))
}

/// Pick an image and store it as the report logo. The image is embedded in the
/// report, so it is base64-encoded into a data: URI and saved in
/// `[branding] logo_data_uri`. Async so the native picker never blocks the main
/// thread. Returns `{changed:false}` if the user cancelled.
#[tauri::command]
pub async fn set_brand_logo(app: tauri::AppHandle) -> Result<Json, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Choose a logo image for reports")
        .add_filter("Image", &["png", "jpg", "jpeg", "gif", "webp", "svg"])
        .pick_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(json!({ "changed": false }));
    };

    // The logo is embedded in every report, so keep it small.
    const MAX_BYTES: usize = 1_000_000;
    let bytes = std::fs::read(&path).map_err(|e| format!("could not read the image: {e}"))?;
    if bytes.len() > MAX_BYTES {
        return Err(format!(
            "That image is {:.1} MB. Please choose a logo under 1 MB.",
            bytes.len() as f64 / 1_000_000.0
        ));
    }
    let mime = match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        _ => return Err("Please choose a PNG, JPEG, GIF, WebP or SVG image.".to_string()),
    };
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let data_uri = format!("data:{mime};base64,{encoded}");
    slap_core::settings::save_setting(
        "logo_data_uri",
        Some(slap_core::settings::SettingValue::Str(data_uri)),
        Some("branding"),
        None,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({ "changed": true }))
}

/// Remove the report logo (`[branding] logo_data_uri`).
#[tauri::command]
pub fn clear_brand_logo() -> Result<Json, String> {
    slap_core::settings::save_setting("logo_data_uri", None, Some("branding"), None)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "changed": true }))
}

/// A sibling path formed by appending a suffix to a full file name, e.g. the
/// `-wal`/`-shm` companions SQLite keeps beside the database. Unlike
/// `with_extension`, this appends rather than replacing the extension.
fn sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Open the OS folder picker so the user can choose where SLAP keeps its data.
/// Returns the chosen folder, or `None` if cancelled. Async so the native
/// dialog never blocks the main thread (see `report_pdf` for why that matters).
#[tauri::command]
pub async fn pick_data_dir(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let start = slap_core::settings::Settings::load(None)
        .map(|s| s.data_dir)
        .unwrap_or_else(|_| slap_core::paths::default_data_dir());
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Choose a folder for SLAP's database and files")
        .set_directory(&start)
        .pick_folder(move |path| {
            let _ = tx.send(path);
        });
    Ok(rx
        .await
        .ok()
        .flatten()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string()))
}

/// Relocate the database and the app's saved files to `new_dir`, moving the
/// existing data there and switching the live database over without a restart.
///
/// Safety: the database is copied (not renamed) and the copy is opened and
/// verified before anything is switched or deleted; the new location is written
/// to config.toml before the live connection is swapped; the old database is
/// removed only once the new one is live. If any step fails, the old data and
/// configuration are left exactly as they were.
#[tauri::command]
pub fn set_data_dir(state: State<'_, AppState>, new_dir: String) -> Result<Json, String> {
    let new_dir = std::path::PathBuf::from(new_dir.trim());
    if new_dir.as_os_str().is_empty() {
        return Err("No folder was chosen.".to_string());
    }
    if std::env::var_os("SLAP_DB").is_some() {
        return Err("The database location is currently fixed by the SLAP_DB environment \
                    variable. Unset it to change the location here."
            .to_string());
    }

    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    let old_dir = settings.data_dir.clone();
    let old_db = settings.db_path.clone();
    let new_db = new_dir.join(format!("{}.sqlite3", slap_core::paths::DIRNAME));

    if new_db == old_db {
        return Ok(json!({ "changed": false, "data_dir": new_dir.display().to_string() }));
    }
    std::fs::create_dir_all(&new_dir)
        .map_err(|e| format!("cannot create {}: {e}", new_dir.display()))?;
    if new_db.exists() {
        return Err(format!(
            "a SLAP database already exists at {}. Choose an empty folder, or move that \
             file aside first.",
            new_db.display()
        ));
    }

    // 1. Flush the WAL into the main file so a plain file copy is complete.
    {
        let guard = state
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        if let Db::Open(conn) = &*guard {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }
    // 2. Copy the database; the original is kept until the copy is verified.
    if old_db.exists() {
        std::fs::copy(&old_db, &new_db)
            .map_err(|e| format!("could not copy the database: {e}"))?;
    }
    // 3. Verify the copy opens; this connection becomes the live one.
    let new_conn = match storage::open_db(&new_db) {
        Ok(conn) => conn,
        Err(e) => {
            let _ = std::fs::remove_file(&new_db);
            return Err(format!(
                "the copied database did not open ({e}); nothing was changed"
            ));
        }
    };
    // 4. Record the new location so a later restart resolves here too.
    if let Err(e) = slap_core::settings::save_setting(
        "data_dir",
        Some(slap_core::settings::SettingValue::Str(new_dir.display().to_string())),
        None,
        None,
    ) {
        let _ = std::fs::remove_file(&new_db);
        return Err(format!(
            "could not save the new location: {e}; nothing was changed"
        ));
    }
    // 5. Switch the live connection over.
    {
        let mut guard = state
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        *guard = Db::Open(new_conn);
    }
    // 6. Move the pinned Chromium and any other saved folders beside the new
    //    database. Best effort: Chromium re-downloads if this cannot be done
    //    (for example across drives), and the other folders are usually empty.
    for sub in ["chromium", "artifacts", "reports"] {
        let from = old_dir.join(sub);
        let to = new_dir.join(sub);
        if from.is_dir() && !to.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    // 7. The old database is now superseded by the verified, live copy.
    let _ = std::fs::remove_file(&old_db);
    let _ = std::fs::remove_file(sidecar(&old_db, "-wal"));
    let _ = std::fs::remove_file(sidecar(&old_db, "-shm"));

    Ok(json!({
        "changed": true,
        "data_dir": new_dir.display().to_string(),
        "db_path": new_db.display().to_string(),
    }))
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
/// A fresh writer connection for the report commands. They write their own
/// files, so they use their own connection rather than the managed read one.
fn report_conn() -> Result<slap_core::rusqlite::Connection, String> {
    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    storage::open_db(&settings.db_path).map_err(|e| e.to_string())
}

/// The file name suggested in the Save dialog for a run's report: host and run
/// id, sanitised so it is a legal name on every platform. Not a location: the
/// user chooses where the file goes.
fn report_filename(
    conn: &slap_core::rusqlite::Connection,
    run_id: i64,
    ext: &str,
) -> Result<String, String> {
    let run = storage::get_run(conn, run_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("run {run_id} not found"))?;
    let host = run["hostname"].as_str().unwrap_or("site");
    let safe: String = host
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    Ok(format!("{safe}-run{run_id}.{ext}"))
}

/// Ask the user where to save, through the OS "Save As" dialog, seeded with a
/// sensible file name and an extension filter. `None` means the user cancelled
/// (or the dialog could not be shown). Async and non-blocking: the plugin shows
/// the dialog on the main thread and the result is awaited here, so the calling
/// command must never itself block the main thread (both report commands are
/// `async` for exactly this reason). Blocking here deadlocks the dialog.
async fn ask_save_path(
    app: &tauri::AppHandle,
    file_name: &str,
    filter_label: &str,
    extensions: &[&str],
) -> Option<std::path::PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(file_name)
        .add_filter(filter_label, extensions)
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    rx.await.ok().flatten().and_then(|path| path.into_path().ok())
}

/// Render a run's client report to a standalone HTML file at a location the
/// user picks in the Save dialog. Returns the chosen path, or `None` if the
/// user cancelled. Async so the native dialog runs without blocking the main
/// thread. Fast otherwise: no browser needed.
#[tauri::command]
pub async fn report_html(app: tauri::AppHandle, run_id: i64) -> Result<Option<String>, String> {
    let name = {
        let conn = report_conn()?;
        report_filename(&conn, run_id, "html")?
    };
    let Some(dest) = ask_save_path(&app, &name, "HTML page", &["html"]).await else {
        return Ok(None);
    };
    let html = {
        let conn = report_conn()?;
        slap_engine::report::render_html(&conn, run_id)?
    };
    std::fs::write(&dest, html).map_err(|e| e.to_string())?;
    Ok(Some(dest.display().to_string()))
}

/// Render a run's client report to PDF at a location the user picks in the Save
/// dialog, using the pinned Chromium the app manages for Lighthouse (fetched on
/// first use if absent). Returns the chosen path, or `None` if the user
/// cancelled. Async: the dialog is awaited (never blocking the main thread) and
/// the Chromium print runs on a blocking task so it cannot stall the runtime.
#[tauri::command]
pub async fn report_pdf(app: tauri::AppHandle, run_id: i64) -> Result<Option<String>, String> {
    let name = {
        let conn = report_conn()?;
        report_filename(&conn, run_id, "pdf")?
    };
    // Ask before rendering: cancelling should cost nothing, and the PDF path is
    // heavy (a Chromium print, and possibly a first-run Chromium fetch).
    let Some(out) = ask_save_path(&app, &name, "PDF document", &["pdf"]).await else {
        return Ok(None);
    };
    let html = {
        let conn = report_conn()?;
        slap_engine::report::render_html(&conn, run_id)?
    };

    let tmp = std::env::temp_dir().join(format!("slap-report-{run_id}.html"));
    std::fs::write(&tmp, &html).map_err(|e| e.to_string())?;

    let chrome = slap_engine::lighthouse::resolve_or_fetch_chrome()
        .await
        .map_err(|e| format!("could not obtain Chromium for the PDF: {e}"))?;

    // The Chromium print is a blocking subprocess; run it on a blocking task so
    // it never stalls the async runtime. The temp HTML is cleaned up there too.
    let out_arg = out.clone();
    let status = tokio::task::spawn_blocking(move || {
        let status = std::process::Command::new(&chrome)
            .args([
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--no-pdf-header-footer",
            ])
            .arg(format!("--print-to-pdf={}", out_arg.display()))
            .arg(format!("file://{}", tmp.display()))
            .status();
        let _ = std::fs::remove_file(&tmp);
        status
    })
    .await
    .map_err(|e| format!("the PDF task did not finish: {e}"))?
    .map_err(|e| format!("could not run Chromium: {e}"))?;

    if !status.success() {
        return Err("Chromium did not produce the PDF".to_string());
    }
    Ok(Some(out.display().to_string()))
}

#[tauri::command]
pub fn start_audit(
    app: tauri::AppHandle,
    urls: Vec<String>,
    lighthouse: bool,
    probe: bool,
) -> Result<Json, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(run_audit_blocking(app, urls, lighthouse, probe));
    });
    rx.recv()
        .map_err(|_| "the audit thread stopped unexpectedly".to_string())?
}

/// The bare host of a URL, matching how the engine keys a site. Used to mark
/// exactly the hosts in this batch as authorised for probing when the user
/// checks the box: authorization is per-host and never leaks to other sites.
fn host_of(url: &str) -> Option<String> {
    let after = url.split("://").nth(1).unwrap_or(url);
    let host_port = after.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_port.rsplit('@').next().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Locate the bundled Lighthouse worker directory (holds `worker.js` and its
/// `node_modules`). In an installed app it is a bundled resource; in a dev
/// run it is `desktop/worker` beside the crate.
fn worker_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    if let Ok(res) = app.path().resource_dir() {
        // The `../worker/**/*` resource glob preserves the tree but escapes the
        // parent-dir `..` to `_up_`, so the worker lands at
        // `<resources>/_up_/worker`. The bare `worker` candidates cover other
        // bundlers/layouts; the first that has worker.js wins.
        for candidate in [
            res.join("_up_").join("worker"),
            res.join("worker"),
            res.join("worker").join("worker"),
        ] {
            if candidate.join("worker.js").exists() {
                return Some(candidate);
            }
        }
    }
    // Dev fallback: the repo's worker directory beside the crate.
    let dev = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../worker");
    dev.join("worker.js").exists().then_some(dev)
}

/// The bundled Node runtime, if the app shipped one. Tauri places an
/// `externalBin` beside the main executable with the target triple stripped, so
/// a self-contained install has `slap-node[.exe]` next to the binary. Named
/// `slap-node` rather than `node` so a Linux package never collides with a
/// system Node. Returns None when the app was built without the bundled
/// runtime, in which case Lighthouse falls back to `node` on PATH.
fn bundled_node() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) { "slap-node.exe" } else { "slap-node" };
    let candidate = exe.parent()?.join(name);
    candidate.exists().then(|| candidate.display().to_string())
}

fn run_audit_blocking(
    app: tauri::AppHandle,
    urls: Vec<String>,
    lighthouse: bool,
    probe: bool,
) -> Result<Json, String> {
    use tauri::Emitter;

    let settings = slap_core::settings::Settings::load(None).unwrap_or_default();
    let mut cfg = slap_engine::EngineConfig::from_settings(&settings);

    if probe {
        // The user affirmed authorization for this batch in the composer.
        // Enable probing and authorise exactly these hosts, nothing else.
        cfg.probe.enabled = true;
        cfg.probe.authorised_hosts = urls.iter().filter_map(|u| host_of(u)).collect();
    }
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
            node_path: bundled_node().unwrap_or_else(|| "node".into()),
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
