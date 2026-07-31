# Building the distributable

*Linux x86_64 built and verified 2026-07-31: full audit and PDF export from
a bundle, in an environment with no Node, no Playwright and no PATH beyond
`/usr/bin`. Windows and macOS use the same script and spec but have not been
built yet; run the CI workflow or build locally on each.*

The goal: a teammate unzips a folder, double-clicks `SLAP.exe`, and audits a
site. **No Python, no Node, no browser, no install.**

```
python packaging/build.py --zip
```

Output lands in `dist/SLAP/` (`dist/SLAP.app` on macOS). Measured on
Linux: 1.1GB unzipped, 413MB zipped.

## Run it on the platform you are shipping to

**PyInstaller is not a cross-compiler.** A Windows executable must be built
on Windows, a macOS app on macOS. The staging steps (npm, Chromium download,
Node check) are cross-platform, so logic errors surface anywhere, but the
final artifact is platform-specific.

Building needs Python, Node and npm on the *build* machine. None of that is
needed on a teammate's machine.

### Or let CI do all three

`.github/workflows/build.yml` builds all four targets on GitHub's own
runners, which is the only way to get them without owning four machines.

| Artifact | Runner | Notes |
|---|---|---|
| `SLAP-windows-x64` | `windows-latest` | |
| `SLAP-macos-arm64` | `macos-latest` | Apple Silicon |
| `SLAP-macos-x64` | `macos-15-intel` | Intel |
| `SLAP-linux-x64` | `ubuntu-latest` | |

- **Manually:** Actions → *Build distributables* → *Run workflow*. The
  picker takes `all`, `windows`, `linux`, `macos` (both Macs), or
  `macos-arm64` / `macos-x64` for one of them.
- **On a tag:** pushing `v0.2.0` builds all four.

Each job installs dependencies, runs the full test suite, builds, and then
**runs the bundle it just built** — a real audit and a real PDF export, not
just `doctor`. A build that cannot produce a PDF fails the job rather than
being uploaded. Artifacts are kept for 14 days.

The test suite runs on every platform in the matrix even when the picker
narrows the build, because "does the suite pass on Intel macOS" is worth
knowing on a run that only ships the arm64 zip. Only build, verify and
upload are gated.

`fail-fast` is off, so a Windows-only breakage still leaves usable macOS and
Linux artifacts.

**One step decides whether a platform is built.** The `gate` step writes
`build=true|false` and the three later steps read it. The condition used to
be repeated inline on each of them, which meant adding the Intel entry would
have been four edits and a job that tests and then silently uploads nothing
if you got one wrong.

### The Intel runner is not `macos-13`

That image was **retired on 2025-12-04**, so `runs-on: macos-13` now fails
outright rather than falling back to anything. The standard replacement is
`macos-15-intel` (4 CPU / 14GB, so slightly beefier than the 3 CPU / 7GB
arm64 runner). `macos-26-intel` also exists; 15 is deliberate, on the same
"build on the oldest system you need to support" reasoning as the glibc note
for Linux.

**Intel macOS has an expiry date on Actions.** `macos-15-intel` is available
until **August 2027**, after which GitHub drops x86_64 entirely. When that
lands, the Intel entry has to come out of the matrix and Intel teammates
need a local build or a machine of their own.

#### Three things the workflow gets wrong if you rewrite it

Each of these produced a green-looking job that was in fact broken, so they
are worth keeping in mind.

1. **Install `.[dev,all]`, not `.[all]`.** `all` is the *runtime* extras
   (playwright, pypdf, PySide6) and carries no test tooling, so the test step
   dies with `No module named pytest`. Nothing platform-specific about it;
   it just happened to be the first job to reach that step.
2. **Do not gate on `doctor`'s exit code.** `doctor` returns 1 when *any*
   backend is unavailable, and CI has no CrUX key, so under
   `set -euo pipefail` a healthy bundle fails the job. Assert on the backend
   lines a bundle is actually responsible for instead.
3. **Setting `PLAYWRIGHT_BROWSERS_PATH` job-wide changes `build.py`'s path.**
   It is set so the test step's Chromium download is reused rather than
   fetched twice, which means `stage_chromium()` finds a browser already
   there and skips its install. Pruning must therefore sit outside that
   branch, or the bundle ships the 320MB headless shell that `channel=
   "chromium"` exists to make unnecessary.

## What ends up in the folder

```
SLAP/
  SLAP.exe                        the app
  _internal/                      Python runtime, Qt, Playwright (+ its Node)
  runtime/
    node_worker/                  worker.js + node_modules   (161MB)
    browsers/chromium-<rev>/      Chromium                   (597MB)
  build-manifest.json             platform, Node and Python versions
```

`runtime/` sits **outside** `_internal` deliberately. `node_modules` is
~12,000 files; putting it through PyInstaller's archive makes builds slow
and the result opaque, and Python never imports any of it. As a plain
folder, a Lighthouse upgrade is a directory swap rather than a rebuild.

`slap/bundle.py` resolves all of this at runtime and returns None from a
source checkout, so a development install behaves exactly as before.

## Two things that make it one browser and one Node

Both were found by building a bundle and running it, not by reading code.

### `channel="chromium"` in the PDF backend

Playwright's `chromium.launch()` **defaults to the headless shell**, a
separate ~320MB download, not the full Chromium that Lighthouse uses. The
first bundle pruned the headless shell as unused, and the result was a
distributable whose `slap doctor` reported PDF export healthy and whose
actual export failed with `Executable doesn't exist at
.../chromium_headless_shell-1194/...`.

`report/pdf.py` now launches with `channel="chromium"`, so **one browser
serves both PDF rendering and Lighthouse**. That is what makes pruning the
headless shell safe, and it is worth 320MB. If you ever remove that
argument, stop pruning in `stage_chromium()`.

### Playwright's Node runs the Lighthouse worker

Playwright bundles its own Node (~110MB) to drive its protocol server. It
is currently v22.20.0, and Lighthouse 13 needs >= 22.19, so the build
reuses it instead of shipping a second runtime. Another 120MB, and one
fewer download step.

This is **verified, not assumed**: `driver_node_is_new_enough()` runs
`node --version` at build time and falls back to downloading a pinned Node
if Playwright ever ships an older one. A silent downgrade would otherwise
surface as a cryptic Lighthouse crash in a teammate's bundle.

## Playwright renames its browser directories

`playwright>=1.44` is an open range, so CI installs whatever is current. It
moved from 1.56 to 1.61 on its own, and **every platform's Chromium
directory was renamed** between browser revisions 1194 and 1228:

| | 1194 | 1228 |
|---|---|---|
| Linux | `chrome-linux/chrome` | `chrome-linux64/chrome` |
| Windows | `chrome-win/chrome.exe` | `chrome-win64/chrome.exe` |
| macOS | `chrome-mac/Chromium.app/.../Chromium` | `chrome-mac-{arm64,x64}/Google Chrome for Testing.app/.../Google Chrome for Testing` |

The macOS binary is not even called Chromium any more. `bundle.py` and
`collectors/lighthouse.py` each held a hardcoded copy of that table, so both
started returning None after a routine upgrade, on all four build targets at
once. The layout knowledge now lives in `bundle.CHROMIUM_GLOBS`, once, as
globs, and a parametrised test asserts every layout above still resolves.

Two lessons worth keeping:

- **This was invisible from a source checkout.** `default_chrome_path()`
  falls through to Playwright's own API, which of course knows where its
  browser is, so a developer machine keeps working while the bundle, which
  must resolve the path itself, does not.
- **Pinning is not the fix.** The report records `chrome_version` on every
  run precisely so a browser upgrade is visible rather than prevented. What
  had to change was code that assumed a layout would hold.

## A status check that can lie is worse than none

`check_backend()` originally confirmed that Chromium's executable *file
existed*. It passed while export failed, because Playwright was launching a
different binary than the one being stat-ed.

It now actually launches the browser and reports the version it got. Slower
by about a second, and it can no longer disagree with the code path it is
supposed to be checking. The same reasoning applies to anything else added
to `slap doctor`: check the thing the real code does, not a proxy for it.

Related: the PDF error handler used to replace Playwright's message with a
flat "Chromium is not installed", which was actively false here. The path
in Playwright's message was the whole diagnosis. It is passed through now.

## Size, and where it goes

| Component | Size | Avoidable? |
|---|---|---|
| Chromium | 597MB | No. Every approach needs a browser. |
| `node_modules` | 161MB | ~130MB via esbuild, at real fragility cost. See below. |
| Playwright (incl. its Node) | 130MB | No, and it doubles as the Lighthouse runtime. |
| PySide6 / Qt | 117MB | Mostly pruned already; `QtWebEngine` is excluded. |
| Python + everything else | ~150MB | No. |

**Why `node_modules` ships unbundled.** esbuild does produce a single 25MB
file from the worker, but Lighthouse resolves assets relative to its own
module path and a bundler flattens that. Three attempts hit three separate
runtime failures (`require("tty")`, `readdirSync("./locales/")`,
`readFileSync("../package.json")`), each only visible by running a real
audit. Each is fixable; the problem is that a Lighthouse upgrade can add a
new one silently. Next to 597MB of Chromium, 130MB is not worth that class
of risk.

## macOS specifics

The build produces `dist/SLAP.app`. PyInstaller's `BUNDLE()` wraps the
collected files, and `runtime/` goes inside `Contents/MacOS/` — which is
where `sys.executable` lives, so `bundle.py`'s "look beside the executable"
rule needs no platform-specific code.

- **Zipped with `ditto`, not `shutil.make_archive`.** `ditto` preserves
  symlinks, resource forks and the executable bit inside a `.app`. A plain
  zip loses the exec bit and the result will not open.
- **Gatekeeper will block an unsigned app** downloaded from anywhere. The
  first launch shows *"SLAP" cannot be opened because the developer cannot
  be verified*. Two ways past it, and teammates need to be told one of them
  in advance:

      xattr -dr com.apple.quarantine /Applications/SLAP.app

  or right-click the app → *Open* → *Open*. The right-click route only works
  the first time and is easier to talk someone through.

- **Notarisation removes the warning entirely** and needs an Apple Developer
  account ($99/yr) plus `codesign` and `notarytool` steps in the build. Worth
  it if this ever goes outside the team; overkill for three people.
- **Chromium is a nested `.app`** inside `SLAP.app`. Fine unsigned; if you
  ever sign, every nested executable needs signing too, which is the fiddly
  part of notarising this particular bundle.
- **Two separate Mac builds, and they are not interchangeable.** The bundled
  Chromium and Node are downloaded per architecture, so an arm64 build
  genuinely will not run on Intel. `build.py` puts the machine architecture
  in the zip name (`SLAP-macos-arm64.zip`, `SLAP-macos-x86_64.zip`) so the
  two cannot be confused once they are off the Actions page.
- **`LSMinimumSystemVersion` tracks the PySide6 wheel, not our own floor.**
  PySide6 6.11 ships `macosx_13_0_universal2`, so the plist says 13.0. It
  said 12.0 for a while, which bought nothing but a launch that dies on
  `import PySide6`. If PySide6 raises its minimum again, raise this with it.
- **Both Mac bundles carry Qt twice.** PySide6 ships universal2 wheels and
  PyInstaller copies the fat binaries through as-is, so the Intel bundle
  contains arm64 Qt slices it can never execute, and vice versa. Roughly
  60MB. PyInstaller can thin them with `target_arch` on `EXE`/`BUNDLE`,
  which shells out to `lipo`; it is left off because any dependency that is
  *not* universal then fails the build, and that is a new failure mode in
  exchange for 5% of a 1.1GB folder. Measure before deciding it matters.

## Linux specifics

The build produces `dist/SLAP/` with a `SLAP` executable. No signing or
quarantine to worry about.

The one real caveat is **glibc**: a bundle built on Ubuntu 24.04 will not
run on an older distro whose glibc is older. Build on the oldest system you
need to support. The CI matrix uses `ubuntu-latest`, which is fine for
current distros.

Chromium also needs a handful of system libraries that PyInstaller does not
collect (`libnss3`, `libatk`, `libgbm` and friends). Most desktops have
them; a minimal container does not. `SLAP --cli doctor` fails clearly if
Chromium cannot launch.

## Windows specifics

- **One-dir, not one-file.** One-file unpacks ~1GB to `%TEMP%` on every
  launch: slow, and a reliable antivirus trigger.
- **UPX is off.** Packed binaries are an antivirus magnet, and compressing
  a folder that is 95% Chromium saves little.
- **SmartScreen will warn** on an unsigned executable downloaded from the
  internet: "Windows protected your PC", and the user must click *More info
  → Run anyway*. Tell teammates in advance or it reads as malware. A code
  signing certificate (~$200-400/yr, OV or EV) removes it; EV clears
  SmartScreen immediately, OV needs reputation to build.
- **Share as a zip over something that preserves it** (a file share, an
  internal release page). Email and some chat tools strip .exe files even
  inside archives.
- The app is built `console=False`. The CLI still works from an existing
  terminal: `.\SLAP.exe --cli doctor`.

## Rebuilding after a code change

Staging is cached, so a code-only rebuild skips the downloads:

```
python packaging/build.py --skip-npm --skip-chromium
```

Takes about 30 seconds plus the runtime copy. Use `--force-staging` after a
Lighthouse or Playwright upgrade, and `--clean` if PyInstaller starts
behaving oddly.

## Verifying a build

Run it in an environment with nothing available, which is the state a
teammate's machine is in:

```bash
env -i PATH=/usr/bin:/bin HOME=/tmp/clean ./dist/SLAP/SLAP --cli doctor
```

Every backend except CrUX should report `ok`, and the paths should point
inside the bundle. Then do a real audit and export, because `doctor` alone
has been wrong before:

```bash
./dist/SLAP/SLAP --cli --db /tmp/t.sqlite3 audit example.com --lighthouse --lh-runs 1
./dist/SLAP/SLAP --cli --db /tmp/t.sqlite3 report 1 -o /tmp/t
```

## What is not done

- **No installer.** A zip and a folder. An MSI or Inno Setup script is a
  small addition if teammates want Start Menu entries.
- **No auto-update.** New build, new zip.
- **No code signing.** See the SmartScreen note above.
- **No notarisation.** macOS builds are unsigned, so Gatekeeper blocks the
  first launch until someone clears the quarantine attribute. See above.
