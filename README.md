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

SLAP is a **Tauri desktop app** (Rust core, system webview, Node sidecar
for Lighthouse) with iOS/Android companion viewers built from the same
codebase. Everything lives under [`desktop/`](desktop/README.md), which has
the layout, build commands, and the rules the codebase holds itself to.

    cd desktop
    cargo test -p slap-core
    cargo build
    ./target/debug/slap-desktop --self-check

Distributables are built by `.github/workflows/desktop.yml` (Windows,
macOS Apple Silicon, macOS Intel, Linux) on `v*` tags or manual dispatch,
with every artifact self-checked on the runner that built it before
upload. `android.yml` is the experimental phone lane.

## History

SLAP began as a Python + PyInstaller application (FastAPI web UI, ~700MB
bundles). It was rewritten as this Tauri app and the Python tree was
retired on 2026-08-27. What carried over unchanged: the observation
schema and metric registry, the SQLite database (existing history opens
as-is, legacy `salp` fallback included), the findings rules
(`desktop/crates/slap-core/rules/rules.yaml`), the Lighthouse Node worker
(`desktop/worker/`), the vulnerability database (`desktop/data/`), and
the report templates (`desktop/templates/`). The `docs/` directory
records the Python era's design notes and postmortems; the project docs
carry the rewrite's plan and status.
