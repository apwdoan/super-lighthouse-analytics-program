//! `--self-check`: prove this build runs, on the machine it was built on.
//!
//! The app-level slice adds what the core cannot know: whether the OS
//! webview this binary will render into actually exists. On Windows that
//! is WebView2, on macOS WKWebView, on Linux webkit2gtk; a machine without
//! one would launch the process and show nothing, which is exactly the
//! class of failure self-checks exist to catch before a teammate does.

use std::io::Write;

/// Write a line without panicking. `println!` panics when the write fails,
/// and in a windows-subsystem process launched bare from a shell, stdout
/// is an invalid handle: the check would die reporting its own success.
/// A previous build's web-server crash under Explorer was this exact shape.
fn say(line: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

#[cfg(windows)]
fn attach_parent_console() {
    // Best effort, for a developer typing `slap-desktop --self-check` in a
    // terminal: borrow the parent's console so the output lands somewhere.
    // CI never needs this because it pipes, which supplies real handles.
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_parent_console() {}

fn check_webview() -> slap_core::selfcheck::Check {
    match tauri::webview_version() {
        Ok(version) => slap_core::selfcheck::Check {
            name: "webview runtime",
            ok: true,
            detail: version,
        },
        Err(error) => slap_core::selfcheck::Check {
            name: "webview runtime",
            ok: false,
            detail: format!("no usable system webview: {error}"),
        },
    }
}

pub fn run() -> i32 {
    attach_parent_console();
    say(&format!(
        "SLAP desktop {} (core {}) self-check",
        env!("CARGO_PKG_VERSION"),
        slap_core::version()
    ));

    let mut checks = slap_core::selfcheck::run_core_checks();
    checks.push(check_webview());

    let mut failed = 0;
    for check in &checks {
        say(&check.to_string());
        if !check.ok {
            failed += 1;
        }
    }

    if failed == 0 {
        say("self-check: ok");
        0
    } else {
        say(&format!("self-check: {failed} check(s) failed"));
        1
    }
}
