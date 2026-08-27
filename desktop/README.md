# SLAP desktop (Tauri rewrite)

The native shell that will replace the PyInstaller bundle. It lives side by
side with the Python app: nothing outside `desktop/` depends on it, and the
Python bundle keeps shipping until this app passes the same self-check and
real-audit bar. The full plan, the architecture decisions, and the phase
sequence live in the project doc `claude/tauri-rewrite.md`.

## Layout

    desktop/
      crates/slap-core/   the core: everything that is not a window and
                          not a browser. Never depends on tauri (a test
                          enforces it, the way the Python AST test keeps
                          src/slap/ free of UI imports).
      src-tauri/          the shell: window, IPC commands, packaging.
      ui/                 static frontend, no build step, no bundler.

## Building

    cd desktop
    cargo test -p slap-core         # the core's tests
    cargo build                     # the app binary
    ./target/debug/slap-desktop --self-check

Bundles (installers) are produced by the Tauri CLI, which CI installs via
npm; locally: `npx --yes @tauri-apps/cli@^2 build`. Linux needs the
webkit2gtk/gtk dev packages first (see `.github/workflows/desktop.yml` for
the exact list).

## Rules that port over from the Python app

- **The core imports no UI framework.** Front ends are clients of
  `slap-core`, never the other way around.
- **Same database, same paths.** While the two apps coexist they resolve
  the identical SQLite file, legacy `salp` fallback and `SLAP_DB`/`SALP_DB`
  overrides included (`crates/slap-core/src/paths.rs` is a line-for-line
  port of `src/slap/config.py`). WAL makes the sharing safe.
- **Check the thing the real code path does, not a proxy for it.**
  `--self-check` opens a real database and reads the real webview version;
  CI runs it on every built artifact, piped on Windows because PowerShell
  does not wait for a GUI-subsystem process.
- **Node owns everything that touches a browser.** Lighthouse (and later
  PDF export) stay in a Node sidecar; Rust owns everything else. The
  worker protocol is unchanged from `src/slap/node_worker/worker.js`.
