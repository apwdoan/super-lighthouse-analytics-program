//! The SLAP desktop shell.
//!
//! `windows_subsystem = "windows"` means no console window on double-click,
//! which is right for the app and famously wrong for everything else: the
//! Python bundle's whole `streams.py` saga started here (PowerShell does
//! not wait for a GUI-subsystem process, and a double-clicked one has no
//! stdout). The lessons are baked in below rather than relearned:
//! self-check writes through handles that may be invalid without
//! panicking, and CI pipes the process so it gets real handles and a real
//! exit code.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod selfcheck;

#[derive(serde::Serialize)]
struct AppStatus {
    name: &'static str,
    version: &'static str,
    core_version: &'static str,
    webview: Option<String>,
    data_dir: String,
    db_path: String,
    using_legacy_data: bool,
}

/// Everything the phase-0 UI shows. One command, so the IPC seam is
/// exercised end to end from the first build.
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
    }
}

fn main() {
    // Before any window: `SLAP --self-check` is how CI proves a built
    // artifact actually runs on the machine that built it, the practice
    // the Python bundle arrived at after shipping a build that only
    // worked in the environment that made it.
    if std::env::args().skip(1).any(|arg| arg == "--self-check") {
        std::process::exit(selfcheck::run());
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_status])
        .run(tauri::generate_context!())
        .expect("error while running the SLAP window");
}
