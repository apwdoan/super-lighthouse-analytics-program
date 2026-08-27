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

pub mod selfcheck;

#[derive(serde::Serialize)]
pub struct AppStatus {
    name: &'static str,
    version: &'static str,
    core_version: &'static str,
    webview: Option<String>,
    data_dir: String,
    db_path: String,
    using_legacy_data: bool,
    rules_loaded: usize,
}

/// Everything the phase-0 UI shows. One command, so the IPC seam is
/// exercised end to end from the first build on every platform.
#[tauri::command]
fn app_status() -> AppStatus {
    AppStatus {
        name: "SLAP",
        version: env!("CARGO_PKG_VERSION"),
        core_version: slap_core::version(),
        webview: tauri::webview_version().ok(),
        data_dir: slap_core::paths::default_data_dir().display().to_string(),
        db_path: slap_core::paths::db_path().display().to_string(),
        using_legacy_data: slap_core::paths::using_legacy_data_dir(),
        rules_loaded: slap_core::findings::FindingsEngine::load(None)
            .map(|engine| engine.rules.len())
            .unwrap_or(0),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_status])
        .run(tauri::generate_context!())
        .expect("error while running the SLAP window");
}
