//! The SLAP shell, shared by every target. Desktop `main()` and the mobile
//! entry point both land in [`run`]; what differs per platform stays in the
//! callers, which is why this library holds no `--self-check` parsing (a
//! CLI is a desktop concept) and no window chrome decisions.
//!
//! On phones the app is a companion viewer: audits can never run there,
//! because Lighthouse requires Node plus a full Chrome, and neither exists
//! on iOS or Android. The core compiles for both regardless (storage,
//! schema, rules), which is exactly what a viewer needs: read the history,
//! render the findings, never pretend to measure.

pub mod commands;
pub mod selfcheck;

use commands::AppState;

#[derive(serde::Serialize)]
pub struct AppStatus {
    name: &'static str,
    version: &'static str,
    core_version: &'static str,
    webview: Option<String>,
    data_dir: String,
    db_path: String,
    rules_loaded: usize,
}

/// Everything the diagnostics view shows. Kept even now that real screens
/// exist: it is the first thing to check when an install misbehaves.
#[tauri::command]
fn app_status() -> AppStatus {
    AppStatus {
        name: "SLAP",
        version: env!("CARGO_PKG_VERSION"),
        core_version: slap_core::version(),
        webview: tauri::webview_version().ok(),
        data_dir: slap_core::paths::default_data_dir().display().to_string(),
        db_path: slap_core::paths::db_path().display().to_string(),
        rules_loaded: slap_core::findings::FindingsEngine::load(None)
            .map(|engine| engine.rules.len())
            .unwrap_or(0),
    }
}

/// Where the app's database lives, honouring config.toml and the SLAP_DB
/// override. Settings resolution can fail on a malformed config; the path
/// contract can't, so fall back to it rather than refusing to start over a
/// bad TOML file.
fn resolve_db_path() -> std::path::PathBuf {
    match slap_core::settings::Settings::load(None) {
        Ok(settings) => settings.db_path,
        Err(_) => slap_core::paths::db_path(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::open(&resolve_db_path()))
        .invoke_handler(tauri::generate_handler![
            app_status,
            commands::list_sites,
            commands::site_overview,
            commands::run_report,
            commands::findings_across_sites,
            commands::library_status,
            commands::start_audit,
            commands::report_html,
            commands::report_pdf,
            commands::delete_site,
            commands::get_settings,
            commands::set_crux_key,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the SLAP window");
}
