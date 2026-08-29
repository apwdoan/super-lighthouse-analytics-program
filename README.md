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

## API keys

SLAP draws on two external data sources, each with its own free API key.
Neither key is needed to build or launch the app, but they change what you
get:

- **CrUX** — required for *field* (real-user) Core Web Vitals. Without it SLAP
  still audits, but reports carry Lighthouse lab data only.
- **NVD** — optional. A key raises the NVD request rate, cutting a full
  vulnerability-database rebuild from about ten minutes to about ninety
  seconds.

Both can be set two ways, with the environment variable winning over the
saved value:

- **CrUX** — export `CRUX_API_KEY`, or save it under **Settings** in the app
  (it is written to `config.toml` in SLAP's data directory).
- **NVD** — export `NVD_API_KEY`, or paste it under **Settings** in the app
  (saved as `nvd_api_key` in `config.toml`, on this machine only).

### CrUX (required for field data)

The [Chrome UX Report API](https://developer.chrome.com/docs/crux/api) needs a
Google Cloud API key provisioned for the Chrome UX Report API.

1. Sign in to the [Google Cloud Console](https://console.cloud.google.com).
2. Search for `Chrome UX Report API` and **Enable** it (enabling creates the
   service in your project, and a project for you if you have none).
3. Open **APIs & Services → Credentials**, choose **Create credentials → API
   key**, and copy the key.

Google's one-step shortcut is the ["Get a key"](https://goo.gle/crux-api-key)
link on the CrUX docs page. The key is free (150 queries/minute per project).

### NVD (optional, speeds up vulnerability data)

The [NVD](https://nvd.nist.gov) issues a free API key that raises your request
rate.

1. Go to
   [Request an API key](https://nvd.nist.gov/developers/request-an-api-key).
2. Enter your organisation name, a valid email, and your organisation type,
   accept the Terms of Use, and submit.
3. Open the activation email and click its link to activate the key. Activate
   it within seven days or the request expires and you must re-request.

The key is stored on this machine only and sent only to the NVD.
