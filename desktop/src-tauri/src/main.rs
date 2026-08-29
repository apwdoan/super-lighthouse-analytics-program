//! The desktop binary: argument handling, then the shared shell.
//!
//! `windows_subsystem = "windows"` means no console window on double-click,
//! which is right for the app and famously wrong for everything else: the
//! Python bundle's whole `streams.py` saga started here (PowerShell does
//! not wait for a GUI-subsystem process, and a double-clicked one has no
//! stdout). The lessons are baked into `selfcheck` rather than relearned:
//! it writes through handles that may be invalid without panicking, and CI
//! pipes the process so it gets real handles and a real exit code.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Before any window: `SLAP --self-check` is how CI proves a built
    // artifact actually runs on the machine that built it, the practice
    // the Python bundle arrived at after shipping a build that only worked
    // in the environment that made it.
    if std::env::args().skip(1).any(|arg| arg == "--self-check") {
        std::process::exit(slap_desktop_lib::selfcheck::run());
    }
    slap_desktop_lib::run()
}
