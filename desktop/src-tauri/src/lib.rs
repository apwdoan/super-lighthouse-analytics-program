//! The SLAP shell: the window, the IPC command surface, and the startup that
//! wires them to the core and the audit engine. It is a library so the command
//! modules stay unit-testable and the entry point stays trivial — the binary
//! (`main()`) parses `--self-check`, calling this library's [`selfcheck`], and
//! otherwise just calls [`run`]. Window chrome and CLI concerns stay in the
//! binary, not here.

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

pub fn run() {
    // Adopt a user-regenerated database if it is newer than the embedded
    // baseline, so a refresh from a previous session is active from launch.
    // Best effort: a malformed config or missing file just keeps the embedded
    // database, which is exactly the fallback we want.
    if let Ok(settings) = slap_core::settings::Settings::load(None) {
        slap_engine::vulndb::activate_if_newer(&settings.vulndb_path);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
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
            commands::pick_data_dir,
            commands::set_data_dir,
            commands::set_brand_name,
            commands::set_brand_logo,
            commands::clear_brand_logo,
            commands::set_nvd_key,
            commands::set_wp_rocket_suggestions,
            commands::vulndb_info,
            commands::regenerate_vulndb,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the SLAP window");
}
