# SLAP desktop (Tauri)

The SLAP app: a Rust core in a Tauri shell, a cross-platform desktop app for
Windows, macOS, and Linux. The architecture decisions and phase history live
in the project docs under `docs/`.

## Layout

    desktop/
      crates/slap-core/   the core: everything that is not a window and
                          not a browser. Never depends on tauri (a test
                          enforces it). Ported so far: paths, schema +
                          metric registry, storage, settings, events, the
                          findings engine.
      crates/slap-core/rules/rules.yaml
                          the findings rules, unchanged since the app
                          first shipped them; embedded at compile time,
                          overridable via `rules_path` in config.toml.
      src-tauri/          the shell. A library (`run()`) with the desktop
                          binary a thin main() over it; the IPC command
                          modules live here and stay unit-testable.
      ui/                 static frontend, no build step, no bundler.
      worker/             the Lighthouse Node worker (worker.js), carried
                          over verbatim; now driven as a subprocess by
                          slap-engine's Lighthouse runner. `npm install`
                          here recreates its node_modules (required before
                          a Lighthouse run, and before a distributable that
                          bundles the worker).
      data/vulndb.json    the committed offline vulnerability database,
                          embedded by slap-engine's `vulndb` matcher at
                          build time (CI refreshes it).
      templates/report/   report.css, the client report's stylesheet, in
                          Lighthouse's visual language; inlined by the
                          `report` module's minijinja render.
      fixtures/           the slowsite fixture and its recorded LHR, for
                          Lighthouse and report testing without a network.

## Building

    cd desktop
    cargo test -p slap-core         # the core's tests
    cargo test -p slap-engine       # the engine's, including every-page
                                    # Lighthouse, Stop and resume end to end
                                    # (that one needs `node` on PATH)
    cargo build                     # the desktop binary
    ./target/debug/slap-desktop --self-check

Release bundles come from the Tauri CLI, which CI installs via npm;
locally: `npx --yes @tauri-apps/cli@^2 build`. Linux needs the
webkit2gtk/gtk dev packages first (see `.github/workflows/desktop.yml` for
the exact list). CI (`desktop.yml`) builds Windows, macOS arm64, macOS
Intel, and Linux, runs `--self-check` on every artifact it builds, and
uploads the bundles. Run it by hand to try a build; a `v*` tag runs
`release.yml`, which builds through `desktop.yml` and publishes the
bundles as a GitHub Release (see "Releases" in the top-level README).

### Lighthouse in the installer

Lighthouse is fully self-contained in a release build: the app ships both
the Node worker and a Node runtime, so an installed SLAP runs Lighthouse on
a machine that has neither the repo nor Node. (The pinned Chrome for Testing
is still fetched on first use, so nothing browser-side ships.)

**Before `tauri build`, run the prepare step:**

    cd desktop
    node scripts/prepare-bundle.mjs
    npx --yes @tauri-apps/cli@^2 build

`prepare-bundle.mjs` does the two things a self-contained build needs: it
`npm install`s the worker (its `node_modules` is bundled as a resource) and
downloads a pinned Node runtime for the build's platform into
`src-tauri/binaries/slap-node-<triple>[.exe]`, where Tauri's `externalBin`
picks it up. Both are gitignored and fetched per build; CI runs the same
step on each runner. A build WITHOUT this step fails, because Tauri requires
the externalBin binary to exist — the intended fail-loud.

How it resolves at runtime:

- The **worker** is bundled via the resource glob `"../worker/**/*"` (the map
  form flattens `node_modules` and breaks module resolution). Tauri escapes
  the parent `..` to `_up_`, so it lands at `<resources>/_up_/worker` and
  `commands.rs::worker_dir` resolves it, falling back to `desktop/worker/`
  beside a dev build.
- The **Node runtime** ships as an `externalBin` named `slap-node` (not
  `node`, so a Linux package never collides with a system Node in
  `/usr/bin`). Tauri drops it beside the main binary;
  `commands.rs::bundled_node` finds `slap-node[.exe]` there and passes it as
  Lighthouse's `node_path`, falling back to `node` on PATH when absent.

Size: the payload is mostly JS and a Node binary, which compress well, so the
download stays modest even though the install does not. A verified Windows
release build produced a **40MB NSIS `-setup.exe` and a 67MB MSI**, expanding
to a **~224MB install** (app 18MB, `slap-node` 83MB, worker 123MB). That is
the trade for zero-prerequisite Lighthouse: a few MB before, tens of MB to
download now. To go back to a small install, remove `bundle.resources` and
`bundle.externalBin` and skip the prepare step; Lighthouse then needs Node
plus the repo's worker, as a dev build does.

## Rules the codebase holds itself to

- **The core imports no UI framework.** Front ends are clients of
  `slap-core`, never the other way around.
- **Same database, same paths.** Every existing install's history was
  written by an earlier version of the app; this one resolves the
  identical SQLite file (`slap/slap.sqlite3`, `SLAP_DB` override included)
  and opens it with the identical DDL. The pre-rename SALP fallbacks (the
  old `salp/` data directory and the `SALP_DB` env var) have been removed.
- **Rules are data.** The engine embeds `rules/rules.yaml`; a differential
  run against the earlier interpreter proved the two agree
  finding-for-finding, rendered text included. The wording has since been
  rewritten for clients (titles and details plain, remediation for whoever
  fixes it), and the report renders a finding's words from the current file,
  so rewording a rule is safe; its conditions are what must not drift.
- **Check the thing the real code path does, not a proxy for it.**
  `--self-check` runs a real storage roundtrip and loads the real rules;
  CI runs it on every built artifact, piped on Windows because PowerShell
  does not wait for a GUI-subsystem process.
- **Node owns everything that touches a browser.** Lighthouse (and later
  PDF export) live in the Node sidecar under `worker/`; Rust owns
  everything else.
