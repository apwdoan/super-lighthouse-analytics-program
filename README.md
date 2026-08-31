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

## The report

Every audit ends in a client-facing report, rendered by the engine's `report`
module from a single self-contained Jinja template
([`report.html.jinja`](desktop/crates/slap-engine/src/report.html.jinja)) and
styled by [`report.css`](desktop/templates/report/report.css), which it reuses
verbatim from the Python era. The HTML is the deliverable: fully self-contained
(inlined CSS, no external assets), so it survives being emailed. The PDF is a
print-to-PDF rendering of that same document, so the two can never disagree.

Page one is the verdict, not the data: a plain-language headline, the Core Web
Vitals against their thresholds, and a strip of lab measurements. After that
comes **What to fix first** — every critical and high finding in full, each
with its specific fix — then **Security** (certificate, response headers,
cookies), and an appendix with the methodology, run provenance, detected
technology, and every measurement collected. The design rules behind this
layout live in [`docs/reports.md`](docs/reports.md).

### Branding

Reports are neutral out of the box, but you can put your own name and logo on
them. Under **Settings → Report branding** in the app:

- **Brand name** — printed in the masthead of every report.
- **Logo** — chosen from a local image (PNG, JPEG, GIF, WebP or SVG, under
  1 MB) and embedded in each report as a data URI, which is what keeps the
  HTML self-contained.

Either one or both works; with neither set the report falls back to the
neutral "Site performance and security audit" heading. Both are saved under
`[branding]` in SLAP's `config.toml`, so a config file alone is enough to
brand a run:

    [branding]
    company_name = "Your Company"
    logo_data_uri = "data:image/png;base64,..."

### WP Rocket suggestions

When a finding can be resolved from inside
[WP Rocket](https://wp-rocket.me), the report adds an "In WP Rocket" line to
that finding naming the exact setting to change. It is on by default. Turn it
off under **Settings → Report content** for clients who do not run WP Rocket,
or for reports that should not carry plugin-specific advice; WP Rocket
detection in the report's technology section is unaffected either way. Like
branding, the choice is saved in `config.toml`, as a top-level key (not inside
a section), so a config file alone controls it:

    wp_rocket_suggestions = false

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
