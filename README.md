# SLAP: Super Lighthouse Analytics Program

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
styled by [`report.css`](desktop/templates/report/report.css). It looks like
the Lighthouse report a client may know from PageSpeed Insights: score gauges
in Lighthouse's three bands, metric rows with Lighthouse's rating shapes, and
audit lists. The HTML is the deliverable: fully self-contained (inlined CSS, no
external assets), so it survives being emailed. The PDF is a print-to-PDF
rendering of that same document, so the two can never disagree. The print
does one thing the HTML cannot: when the report would end partway down its
last sheet, it grows the whole report (text, gauges and spacing) by as much
as fits without adding a sheet, up to 25%, so the space goes to legibility
rather than blank paper.

It is written for the site's owner, not its developer: plain names for the
metrics with Lighthouse's short names beside them, Lighthouse's audits
retitled as the problems they describe, and savings in seconds and KB.

Page one is the verdict, not the data: the home page's four Lighthouse gauges
(with the typical page's score under each when several pages were tested)
and a Security gauge counting the checks the home page passed, a
plain-language Core Web Vitals verdict from real-visitor data, and **What to
fix first**, every critical, high and medium finding in full with how to fix
it and the pages it affects. An audit run without Lighthouse still opens on
the Security gauge. Then:

- **Home page in detail**: the speed measurements, the ways to make the page
  faster, and each other category's problems.
- **Across the site**: how every tested page falls into Lighthouse's bands per
  category, the problems found on the most pages, and every page with its
  scores, load time and issue count.
- **Pages worth a closer look**: a section for each page that stands out,
  with pages of one type that share the same problems shown once, so an
  every-page report stays readable.
- **Security**, laid out as a Lighthouse category: its gauge, the problems
  with the connection, protective settings and cookies, then the checks that
  passed.
- **Software and technology**, and **About this report**: how the audit
  tested, the test details, notes on the results, and a short list of other
  measurements.

The design rules behind this layout live in [`docs/reports.md`](docs/reports.md).

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

### How to fix

Each finding in **What to fix first** carries a "How to fix" line saying
what to change. It is on by default. Turn it off under **Settings → Report
content** for reports that should state the problems and leave the fixes to
be quoted separately; the app's own views keep the advice either way. It is
saved as a top-level key in `config.toml`:

    fix_advice = false

### WP Rocket suggestions

When a finding can be resolved from inside
[WP Rocket](https://wp-rocket.me), the report adds an "In WP Rocket" line to
that finding naming the exact setting to change. It is on by default. Turn it
off under **Settings → Report content** for clients who do not run WP Rocket:
the line then goes from the findings in the app as well as from reports.
WP Rocket detection in the report's technology section is unaffected either
way. Like
branding, the choice is saved in `config.toml`, as a top-level key (not inside
a section), so a config file alone controls it:

    wp_rocket_suggestions = false

## Lighthouse on every page

With Lighthouse on, SLAP runs full, self-hosted Lighthouse (the bundled Node
worker driving a pinned Chrome for Testing, median of 3 runs a page). It is
on by default: **New audit** starts with Lighthouse ticked, since the
report's gauges and speed figures come from it. Untick it for a quick
server-and-security pass, or set `[lighthouse] enabled = false` in
`config.toml` to have it start unticked. Which pages it measures is a
setting, chosen in **New audit** or **Settings → Lighthouse**, and saved as
`[lighthouse] scope` in `config.toml`:

- **One page per template** (`sampled`, the default): the most representative
  pages, up to `lighthouse_pages_per_site` (5) a site.
- **Every discovered page** (`every_page`): every page discovery found, up to
  the per-site cap (`pages_per_site`, 20), which each report discloses.

Every page is about 30 seconds of wall-clock time at the default concurrency
of 3, so every-page mode turns a big batch into an overnight job. Before it
starts, New audit counts the pages (discovery only) and shows the time and disk
it will take. While it runs, an activity dock shows the pages in Chrome, pages
measured of planned, and an ETA. The batch can be stopped at any time.

Long batches are built to survive:

- **Each page is saved as it finishes.** A crash, a closed app or Stop costs at
  most the pages that were in Chrome at that moment.
- **Interrupted audits can be resumed** from New audit, in place, keeping every
  page already measured. A run is only resumed under the same Lighthouse and
  Chrome it started with; if either changed, the site is re-audited as a new
  run, so no report mixes two engines.
- **The machine is kept awake** for the length of the batch, and New audit
  warns before a long batch starts on battery.
- **Lighthouse concurrency is capped across the whole batch** (`[lighthouse]
  concurrency`, 3, never above 4), because contended CPU gives plausible,
  irreproducible scores. A finding flags a run whose CPU benchmark drifted
  between pages.

Each measured page keeps a compact summary (a few KB) that the report is drawn
from. Its full Lighthouse report (about 600 KB) is kept too unless
`[lighthouse] keep_artifacts = false`; the toggle is under Settings →
Lighthouse. Design notes: [`docs/every-page-lighthouse.md`](docs/every-page-lighthouse.md).

    [lighthouse]
    scope = "every_page"
    concurrency = 3
    keep_artifacts = true

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

### Releases

Pushing a version tag publishes a GitHub Release with an installer for every
platform:

1. Set the version in `desktop/src-tauri/tauri.conf.json` and in
   `[workspace.package]` of `desktop/Cargo.toml`. The two must agree.
2. Commit, then tag that commit and push the tag:

       git tag v0.2.0
       git push origin v0.2.0

[`.github/workflows/release.yml`](.github/workflows/release.yml) checks the
tag against both versions first, then builds Windows, macOS Apple Silicon,
macOS Intel and Linux through
[`.github/workflows/desktop.yml`](.github/workflows/desktop.yml), which
self-checks every build on the runner that made it. Only if all four
succeed does it publish the release: the Windows installer and MSI, a disk
image for each kind of Mac, the Linux AppImage and `.deb`, a
`SHA256SUMS.txt`, and notes on the first launch (the builds are not
code-signed yet), followed by GitHub's list of changes since the last
release. A tag like `v0.3.0-1` becomes a pre-release; the Windows MSI only
takes a numeric pre-release part, so the tag check refuses `v0.3.0-beta`.

To publish a tag that already exists, run **Release desktop app** by hand
from the Actions tab with that tag, optionally as a draft to look over
first. To build without releasing, run **Build desktop app (Tauri)** by
hand; its bundles stay on the run for 14 days.

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
