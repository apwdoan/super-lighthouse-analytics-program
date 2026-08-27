# SLAP desktop and mobile (Tauri rewrite)

The native shell that will replace the PyInstaller bundle, plus the phone
viewer built from the same codebase. It lives side by side with the Python
app: nothing outside `desktop/` depends on it, and the Python bundle keeps
shipping until this app passes the same self-check and real-audit bar. The
full plan, the architecture decisions, and the phase sequence live in the
project doc `claude/tauri-rewrite.md`.

## Layout

    desktop/
      crates/slap-core/   the core: everything that is not a window and
                          not a browser. Never depends on tauri (a test
                          enforces it, the way the Python AST test keeps
                          src/slap/ free of UI imports). Ported so far:
                          paths, schema + metric registry, storage,
                          settings, events, the findings engine.
      src-tauri/          the shell. A library (`run()`) shared by every
                          target: the desktop binary is a thin main() over
                          it, and the mobile entry point is the same
                          function behind `#[tauri::mobile_entry_point]`.
      ui/                 static frontend, no build step, no bundler.

## Building

    cd desktop
    cargo test -p slap-core         # the core's tests
    cargo build                     # the desktop binary
    ./target/debug/slap-desktop --self-check

Bundles (installers) are produced by the Tauri CLI, which CI installs via
npm; locally: `npx --yes @tauri-apps/cli@^2 build`. Linux needs the
webkit2gtk/gtk dev packages first (see `.github/workflows/desktop.yml` for
the exact list).

### Cross-app harnesses

Two test harnesses prove the side-by-side contract against the REAL Python
app rather than our idea of it. Both are env-gated no-ops in CI:

    # storage: Python writes a database, the port reads and extends it
    SLAP_COMPAT_DB=/tmp/compat.sqlite3 cargo test -p slap-core --test python_compat

    # findings: both engines, same observations, identical rendered output
    SLAP_DIFF_JSON=/tmp/diff.json cargo test -p slap-core --test python_compat

The Python-side seed scripts live in the session notes; the harness file
(`crates/slap-core/tests/python_compat.rs`) documents the expected shapes.

## Mobile

Tauri 2 builds iOS and Android apps from this same crate. On phones SLAP
is a **companion viewer**: audits can never run there, because Lighthouse
requires Node plus a full Chrome and neither exists on a phone OS. The
core compiles for both targets regardless (storage, schema, rules), which
is what a viewer needs: read history, render findings, never pretend to
measure. How audit data reaches a phone starts file-based (an exported
site pack opened on the device); anything fancier is a later decision.

`src-tauri/gen/` (the per-platform projects `tauri android init` and
`tauri ios init` generate) stays untracked while the app is pre-release;
CI regenerates it per run. `.github/workflows/android.yml` is the
experimental Android lane (dispatch-only, debug APK). iOS needs a macOS
runner plus Xcode and follows once the Android lane proves out.

## Rules that port over from the Python app

- **The core imports no UI framework.** Front ends are clients of
  `slap-core`, never the other way around.
- **Same database, same paths.** While the two apps coexist they resolve
  the identical SQLite file, legacy `salp` fallback and `SLAP_DB`/`SALP_DB`
  overrides included (`crates/slap-core/src/paths.rs` is a line-for-line
  port of `src/slap/config.py`). WAL makes the sharing safe. Proven both
  directions by the compat harness above.
- **Rules are data, and there is exactly one rules file.** The engine
  embeds `src/slap/findings/rules.yaml` from the repo root at compile
  time; both apps interpret the same bytes. The engine differential proves
  they agree finding-for-finding, rendered text included.
- **Check the thing the real code path does, not a proxy for it.**
  `--self-check` runs a real storage roundtrip and loads the real rules;
  CI runs it on every built artifact, piped on Windows because PowerShell
  does not wait for a GUI-subsystem process.
- **Node owns everything that touches a browser.** Lighthouse (and later
  PDF export) stay in a Node sidecar; Rust owns everything else. The
  worker protocol is unchanged from `src/slap/node_worker/worker.js`.
