# SLAP: Super Lighthouse Analytics Project

**Per-page** website performance and security auditing. Finds a site's pages,
audits each one, turns the result into findings a site owner will act on, and
renders a client-facing HTML and PDF report.

```
discovery  ──►  collectors  ──►  observations  ──►  findings  ──►  report
(sitemap,      (many, dumb,     (one schema,       (rules,       (grouped by
 crawl)         per page)        immutable)         rule → PDF)
```

## The app

SLAP is a cross-platform **Tauri desktop app** for Windows, macOS, and Linux
(Rust core, system webview, Node sidecar for Lighthouse). Everything lives
under [`desktop/`](desktop/README.md), which has the full layout, the deeper
build notes, and the rules the codebase holds itself to.

## Building from source

**Prerequisites:** a stable Rust toolchain and Node.js — Node drives the
Lighthouse worker, the bundle-prep step, and the Tauri CLI. On Linux, install
the webkit2gtk and GTK development packages first (the exact list is in
[`.github/workflows/desktop.yml`](.github/workflows/desktop.yml)).

**Dev build** — the desktop binary, no installer:

    cd desktop
    cargo test -p slap-core                    # the core's tests
    cargo build                                # builds target/debug/slap-desktop
    ./target/debug/slap-desktop --self-check   # real storage + rules roundtrip

Lighthouse in a dev build needs Node on PATH and the worker's dependencies
(`cd desktop/worker && npm install`); the pinned Chrome for Testing is fetched
on first use.

**Release build** — the self-contained installer, with Lighthouse and a Node
runtime bundled so an installed SLAP needs neither the repo nor Node:

    cd desktop
    node scripts/prepare-bundle.mjs            # installs the worker, fetches a pinned Node
    npx --yes @tauri-apps/cli@^2 build         # produces the platform installer

The prepare step is required: a `tauri build` without it fails by design,
because Tauri expects the bundled Node binary to exist.
[`desktop/README.md`](desktop/README.md) covers what it fetches, the resulting
install size, and how the worker and Node resolve at runtime.

Distributables are built by `.github/workflows/desktop.yml` (Windows, macOS
Apple Silicon, macOS Intel, Linux) on `v*` tags or manual dispatch, with every
artifact self-checked on the runner that built it before upload.
