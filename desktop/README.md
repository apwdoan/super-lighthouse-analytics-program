# SLAP desktop and mobile (Tauri)

The SLAP app: a Rust core in a Tauri shell, with iOS/Android viewer targets
built from the same crate. This replaced the Python + PyInstaller app on
2026-08-27. The plan, the architecture decisions, and the phase status live
in the project doc `claude/tauri-rewrite.md`.

## Layout

    desktop/
      crates/slap-core/   the core: everything that is not a window and
                          not a browser. Never depends on tauri (a test
                          enforces it). Ported so far: paths, schema +
                          metric registry, storage, settings, events, the
                          findings engine.
      crates/slap-core/rules/rules.yaml
                          the findings rules, unchanged from the Python
                          app; embedded at compile time, overridable via
                          `rules_path` in config.toml.
      src-tauri/          the shell. A library (`run()`) shared by every
                          target: the desktop binary is a thin main() over
                          it, and the mobile entry point is the same
                          function behind `#[tauri::mobile_entry_point]`.
      ui/                 static frontend, no build step, no bundler.
      worker/             the Lighthouse Node worker (worker.js), carried
                          over verbatim; now driven as a subprocess by
                          slap-engine's Lighthouse runner. `npm install`
                          here recreates its node_modules (required before
                          a Lighthouse run, and before a distributable that
                          bundles the worker).
      data/vulndb.json    the committed offline vulnerability database.
      templates/report/   the Jinja2 report templates, for the minijinja
                          render phase.
      fixtures/           the slowsite fixture and its recorded LHR, for
                          Lighthouse and report testing without a network.

## Building

    cd desktop
    cargo test -p slap-core         # the core's tests
    cargo build                     # the desktop binary
    ./target/debug/slap-desktop --self-check

Release bundles come from the Tauri CLI, which CI installs via npm;
locally: `npx --yes @tauri-apps/cli@^2 build`. Linux needs the
webkit2gtk/gtk dev packages first (see `.github/workflows/desktop.yml` for
the exact list). CI (`desktop.yml`) builds Windows, macOS arm64, macOS
Intel, and Linux on dispatch and on `v*` tags, runs `--self-check` on
every artifact it builds, and uploads the bundles.

### Lighthouse in a distributable

A Lighthouse run needs three things at runtime: Node on PATH, the worker's
`node_modules` (from `npm install` in `desktop/worker/`), and a pinned
Chrome for Testing (the app fetches and sha256-checks one on first run, so
nothing to ship). In a dev build or on a machine that has the repo, the
app finds `desktop/worker/` beside the build and no bundling is needed. To
put Lighthouse in an installer for machines without the repo, bundle the
worker into the app's resources: run `npm install` in `desktop/worker/`,
then add to `src-tauri/tauri.conf.json` under `bundle`:

    "resources": { "../worker": "worker" }

`commands.rs::worker_dir` looks in the bundled resource dir first and falls
back to `desktop/worker/`. The default config leaves the worker unbundled
to keep the installer small (a few MB rather than ~160MB); a non-bundled
installer still audits everything except Lighthouse, and runs Lighthouse
fine from a dev/source checkout.

## Mobile

Tauri 2 builds iOS and Android apps from this same crate. On phones SLAP
is a **companion viewer**: audits can never run there, because Lighthouse
requires Node plus a full Chrome and neither exists on a phone OS. Audit
data reaches a phone file-based first (an exported site pack); anything
fancier is a later decision. `src-tauri/gen/` stays untracked while
pre-release; CI regenerates it. `.github/workflows/android.yml` is the
experimental Android lane (dispatch-only, debug APK). iOS needs a macOS
runner plus Xcode and follows once the Android lane proves out.

## Rules carried over from the Python app

- **The core imports no UI framework.** Front ends are clients of
  `slap-core`, never the other way around.
- **Same database, same paths.** Every existing install's history was
  written by the Python app; this app resolves the identical SQLite file
  (`slap/slap.sqlite3`, `SLAP_DB` override included) and opens it with the
  identical DDL. Cross-app compatibility was proven in both directions
  before the retirement (`crates/slap-core/tests/python_compat.rs` records
  how). The pre-rename SALP fallbacks (the old `salp/` data directory and
  the `SALP_DB` env var) have been removed.
- **Rules are data.** The engine embeds `rules/rules.yaml`, byte-for-byte
  the Python app's file; the engine differential proved the two
  interpreters agreed finding-for-finding, rendered text included.
- **Check the thing the real code path does, not a proxy for it.**
  `--self-check` runs a real storage roundtrip and loads the real rules;
  CI runs it on every built artifact, piped on Windows because PowerShell
  does not wait for a GUI-subsystem process.
- **Node owns everything that touches a browser.** Lighthouse (and later
  PDF export) live in the Node sidecar under `worker/`; Rust owns
  everything else.
