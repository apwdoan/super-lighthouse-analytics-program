# Building the distributable

*Linux x86_64 built and verified 2026-07-31: full audit and PDF export from
a bundle, in an environment with no Node, no Playwright and no PATH beyond
`/usr/bin`. Windows and macOS use the same script and spec but have not been
built yet; run the CI workflow or build locally on each.*

The goal: a teammate unzips a folder, double-clicks `SALP.exe`, and audits a
site. **No Python, no Node, no browser, no install.**

```
python packaging/build.py --zip
```

Output lands in `dist/SALP/` (`dist/SALP.app` on macOS). Measured on
Linux: 1.1GB unzipped, 413MB zipped.

## Run it on the platform you are shipping to

**PyInstaller is not a cross-compiler.** A Windows executable must be built
on Windows, a macOS app on macOS. The staging steps (npm, Chromium download,
Node check) are cross-platform, so logic errors surface anywhere, but the
final artifact is platform-specific.

Building needs Python, Node and npm on the *build* machine. None of that is
needed on a teammate's machine.

### Or let CI do all three

`.github/workflows/build.yml` builds Windows, macOS (Apple Silicon) and
Linux on GitHub's own runners, which is the only way to get all three
without owning all three machines.

- **Manually:** Actions → *Build distributables* → *Run workflow*, with a
  platform picker if you only want one.
- **On a tag:** pushing `v0.2.0` builds all three.

Each job installs dependencies, runs the full test suite, builds, and then
**runs the bundle it just built** — a real audit and a real PDF export, not
just `doctor`. A build that cannot produce a PDF fails the job rather than
being uploaded. Artifacts land under the run as `SALP-windows-x64`,
`SALP-macos-arm64`, `SALP-linux-x64`, kept for 14 days.

`fail-fast` is off, so a Windows-only breakage still leaves usable macOS and
Linux artifacts.

Intel Macs need a `macos-13` entry in the matrix; `macos-latest` is Apple
Silicon and its output will not run on an Intel machine.

## What ends up in the folder

```
SALP/
  SALP.exe                        the app
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

`salp/bundle.py` resolves all of this at runtime and returns None from a
source checkout, so a development install behaves exactly as before.

## Two things that make it one browser and one Node

Both were found by building a bundle and running it, not by reading code.

### `channel="chromium"` in the PDF backend

Playwright's `chromium.launch()` **defaults to the headless shell**, a
separate ~320MB download, not the full Chromium that Lighthouse uses. The
first bundle pruned the headless shell as unused, and the result was a
distributable whose `salp doctor` reported PDF export healthy and whose
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

## A status check that can lie is worse than none

`check_backend()` originally confirmed that Chromium's executable *file
existed*. It passed while export failed, because Playwright was launching a
different binary than the one being stat-ed.

It now actually launches the browser and reports the version it got. Slower
by about a second, and it can no longer disagree with the code path it is
supposed to be checking. The same reasoning applies to anything else added
to `salp doctor`: check the thing the real code does, not a proxy for it.

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

The build produces `dist/SALP.app`. PyInstaller's `BUNDLE()` wraps the
collected files, and `runtime/` goes inside `Contents/MacOS/` — which is
where `sys.executable` lives, so `bundle.py`'s "look beside the executable"
rule needs no platform-specific code.

- **Zipped with `ditto`, not `shutil.make_archive`.** `ditto` preserves
  symlinks, resource forks and the executable bit inside a `.app`. A plain
  zip loses the exec bit and the result will not open.
- **Gatekeeper will block an unsigned app** downloaded from anywhere. The
  first launch shows *"SALP" cannot be opened because the developer cannot
  be verified*. Two ways past it, and teammates need to be told one of them
  in advance:

      xattr -dr com.apple.quarantine /Applications/SALP.app

  or right-click the app → *Open* → *Open*. The right-click route only works
  the first time and is easier to talk someone through.

- **Notarisation removes the warning entirely** and needs an Apple Developer
  account ($99/yr) plus `codesign` and `notarytool` steps in the build. Worth
  it if this ever goes outside the team; overkill for three people.
- **Chromium is a nested `.app`** inside `SALP.app`. Fine unsigned; if you
  ever sign, every nested executable needs signing too, which is the fiddly
  part of notarising this particular bundle.
- **Apple Silicon only** unless you add a `macos-13` matrix entry. The
  bundled Chromium and Node are architecture-specific, so an arm64 build
  genuinely will not run on Intel.

## Linux specifics

The build produces `dist/SALP/` with a `SALP` executable. No signing or
quarantine to worry about.

The one real caveat is **glibc**: a bundle built on Ubuntu 24.04 will not
run on an older distro whose glibc is older. Build on the oldest system you
need to support. The CI matrix uses `ubuntu-latest`, which is fine for
current distros.

Chromium also needs a handful of system libraries that PyInstaller does not
collect (`libnss3`, `libatk`, `libgbm` and friends). Most desktops have
them; a minimal container does not. `SALP --cli doctor` fails clearly if
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
  terminal: `.\SALP.exe --cli doctor`.

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
env -i PATH=/usr/bin:/bin HOME=/tmp/clean ./dist/SALP/SALP --cli doctor
```

Every backend except CrUX should report `ok`, and the paths should point
inside the bundle. Then do a real audit and export, because `doctor` alone
has been wrong before:

```bash
./dist/SALP/SALP --cli --db /tmp/t.sqlite3 audit example.com --lighthouse --lh-runs 1
./dist/SALP/SALP --cli --db /tmp/t.sqlite3 report 1 -o /tmp/t
```

## What is not done

- **No installer.** A zip and a folder. An MSI or Inno Setup script is a
  small addition if teammates want Start Menu entries.
- **No auto-update.** New build, new zip.
- **No code signing.** See the SmartScreen note above.
- **Not built for macOS or Linux**, though nothing here is Windows-specific;
  run the same command on that platform. macOS additionally needs signing
  and notarisation or Gatekeeper blocks it outright.
