"""Build a self-contained SLAP distributable.

    python packaging/build.py

Produces ``dist/SLAP/`` containing everything: the Python runtime, the app,
a Node runtime, the Lighthouse worker with its dependencies, and Chromium.
A teammate unzips it and runs ``SLAP.exe``. They install nothing.

**PyInstaller is not a cross-compiler.** Run this on the platform you want
to ship to: a Windows build must be produced on Windows. The staging steps
below are cross-platform, so most breakage shows up on any OS, but the
final artifact is platform-specific.

Steps, each skippable with a flag so a rebuild after a code change is fast:

1. ``npm install --omit=dev`` for the Lighthouse worker
2. download a Node runtime for this platform
3. ``playwright install chromium`` into the staging directory
4. refresh the vulnerability database from OSV
5. run PyInstaller

Sizes, measured: Chromium ~600MB, node_modules ~161MB, Node ~120MB, Python
and Qt ~150MB. Expect a folder around 1GB and a zip around 350-400MB. That
is the price of "installs nothing"; almost all of it is Chromium, which no
approach avoids.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging"
STAGING = PACKAGING / "staging"
WORKER_SRC = ROOT / "src" / "slap" / "node_worker"

#: Pinned so every teammate's bundle measures on the same runtime. Lighthouse
#: 13 requires >= 22.19; do not lower this without checking its `engines`.
NODE_VERSION = "22.22.0"

#: Short, stable name for artifact filenames. sys.platform gives "win32"
#: even on 64-bit and "darwin" rather than "macos", neither of which reads
#: well on a download someone has to identify.
PLATFORM_TAG = {
    "win32": "windows", "darwin": "macos", "linux": "linux",
}.get(sys.platform, sys.platform)


def log(message: str) -> None:
    print(f"[build] {message}", flush=True)


def run(command: list[str], **kwargs) -> None:
    log(" ".join(str(c) for c in command))
    subprocess.run(command, check=True, **kwargs)


# --------------------------------------------------------------------------
# 1. Lighthouse dependencies
# --------------------------------------------------------------------------

#: A bundle whose vulnerability data is older than this is not fit to ship.
#: It would still print its own date in the report appendix, which is the
#: design working, but nobody reads an appendix before trusting a headline.
MAX_VULNDB_AGE_DAYS = 14


def stage_vulndb(force: bool = False, *, required: bool = False) -> Path | None:
    """Refresh the bundled vulnerability database from OSV.

    A distributable carries a *dated* database, and the date is baked in at
    build time. Without this step, a bundle built from an unchanged repo six
    months from now ships six-month-old data: correct-looking, honestly
    dated, and stale. The repo's committed copy is the development fallback,
    not the thing teammates should receive.

    Network failure is reported loudly and falls back to the committed copy,
    because a developer building on a train should still get a bundle. CI
    passes ``required=True`` so a release never ships the fallback silently.
    """
    from slap.vulndb import VulnDatabase, build_from_nvd, default_db_path

    target = default_db_path()
    existing = VulnDatabase.load(target)
    age = existing.age_days

    if not force and existing.available and age is not None and age <= 1:
        log(f"vulnerability database is {age} day(s) old; keeping it")
        return target

    log("refreshing the vulnerability database from the NIST NVD "
        "(keyless: ~5 min; set NVD_API_KEY to make it ~40s)")
    try:
        database = build_from_nvd(previous=existing)
    except Exception as exc:                          # noqa: BLE001
        message = f"vulnerability database refresh FAILED: {type(exc).__name__}: {exc}"
        if required:
            raise SystemExit(f"[build] {message}") from exc
        log(message)
        log("falling back to the committed copy "
            f"({existing.count} advisories, {age} day(s) old)")
        return target if existing.available else None

    if database.failures:
        # A package that had advisories last time and returns none now is a
        # failed query wearing a success. Shipping that is shipping a bundle
        # that reports less and looks clean doing it.
        message = ("could not query " + ", ".join(database.failures[:8])
                   + "; refusing to ship a quietly smaller database")
        if required:
            raise SystemExit(f"[build] {message}")
        log(message)
        return target if existing.available else None

    if not database.available:
        # An empty result is worse than an error: the bundle would start
        # fine, audit fine, and report zero known vulnerabilities forever.
        message = "OSV returned no advisories at all; refusing to ship an empty database"
        if required:
            raise SystemExit(f"[build] {message}")
        log(message)
        return target if existing.available else None

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(database.to_json(), encoding="utf-8")
    log(f"vulnerability database: {database.count} advisories across "
        f"{len(database.index)} packages ({target.stat().st_size / 1024:.0f} KB)")
    return target


def verify_vulndb(dist: Path) -> None:
    """Confirm the built bundle actually carries usable data.

    Checked against the file inside the bundle, not the one in the source
    tree, for the same reason `check_backend` launches Chromium rather than
    stat-ing it: the failure mode is a bundle that starts fine, audits fine,
    and silently reports nothing forever.
    """
    from slap.vulndb import VulnDatabase

    candidates = list(dist.rglob("vulndb.json"))
    if not candidates:
        raise SystemExit("[build] the bundle carries no vulndb.json. "
                         "Check the datas entry in packaging/slap.spec.")
    database = VulnDatabase.load(candidates[0])
    if not database.available:
        raise SystemExit(f"[build] {candidates[0]} holds no advisories")
    age = database.age_days
    if age is not None and age > MAX_VULNDB_AGE_DAYS:
        raise SystemExit(
            f"[build] the bundled vulnerability database is {age} days old "
            f"(limit {MAX_VULNDB_AGE_DAYS}). Run with --force-staging.")
    log(f"bundled vulnerability database: {database.count} advisories, "
        f"{age} day(s) old")


def stage_worker(force: bool = False) -> Path:
    """Install the worker's production dependencies into staging."""
    target = STAGING / "node_worker"
    if target.exists() and not force:
        log(f"worker already staged at {target}")
        return target

    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)
    for name in ("worker.js", "package.json"):
        shutil.copy2(WORKER_SRC / name, target / name)

    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if npm is None:
        raise SystemExit("npm not found. Node is needed to BUILD, not to run.")
    # --omit=dev keeps esbuild and friends out of the shipped tree.
    run([npm, "install", "--omit=dev", "--no-audit", "--no-fund"], cwd=target)
    shutil.rmtree(target / "node_modules" / ".bin", ignore_errors=True)
    log(f"worker staged: {_size(target)}")
    return target


# --------------------------------------------------------------------------
# 2. Node runtime
# --------------------------------------------------------------------------

def node_archive_name() -> tuple[str, str]:
    """(archive filename, extracted directory name) for this platform."""
    machine = platform.machine().lower()
    arch = {
        "amd64": "x64", "x86_64": "x64",
        "arm64": "arm64", "aarch64": "arm64",
    }.get(machine)
    if arch is None:
        raise SystemExit(f"unsupported architecture: {platform.machine()}")

    if sys.platform.startswith("win"):
        stem = f"node-v{NODE_VERSION}-win-{arch}"
        return f"{stem}.zip", stem
    if sys.platform == "darwin":
        stem = f"node-v{NODE_VERSION}-darwin-{arch}"
        return f"{stem}.tar.gz", stem
    stem = f"node-v{NODE_VERSION}-linux-{arch}"
    return f"{stem}.tar.xz", stem


MIN_NODE = (22, 19)


def playwright_driver_node() -> Path | None:
    """Node that ships inside the installed Playwright package."""
    try:
        import playwright
    except ImportError:
        return None
    driver = Path(playwright.__file__).parent / "driver"
    for name in ("node.exe", "node"):
        candidate = driver / name
        if candidate.exists():
            return candidate
    return None


def driver_node_is_new_enough() -> tuple[bool, str]:
    """Can Playwright's bundled Node run Lighthouse 13?

    Reusing it saves shipping a second ~120MB Node runtime. Verified rather
    than assumed, because a future Playwright could quietly pin an older
    Node and the failure would surface as a cryptic Lighthouse crash in a
    teammate's bundle.
    """
    node = playwright_driver_node()
    if node is None:
        return False, "Playwright driver node not found"
    try:
        result = subprocess.run([str(node), "--version"],
                                capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, f"could not run driver node: {exc}"
    raw = result.stdout.strip().lstrip("v")
    try:
        parts = tuple(int(x) for x in raw.split(".")[:2])
    except ValueError:
        return False, f"unparseable driver node version {raw!r}"
    ok = parts >= MIN_NODE
    return ok, (f"Playwright driver node v{raw} "
                f"({'>=' if ok else '<'} {MIN_NODE[0]}.{MIN_NODE[1]} required)")


def stage_node(force: bool = False) -> Path | None:
    """Download a Node runtime, but only if Playwright's is too old."""
    reusable, detail = driver_node_is_new_enough()
    log(detail)
    if reusable and not force:
        log("reusing Playwright's Node; skipping the separate download (~120MB saved)")
        shutil.rmtree(STAGING / "node", ignore_errors=True)
        return None

    target = STAGING / "node"
    if target.exists() and not force:
        log(f"node already staged at {target}")
        return target

    archive_name, extracted = node_archive_name()
    url = f"https://nodejs.org/dist/v{NODE_VERSION}/{archive_name}"
    download = STAGING / archive_name
    STAGING.mkdir(parents=True, exist_ok=True)

    if not download.exists():
        log(f"downloading {url}")
        urllib.request.urlretrieve(url, download)

    log(f"unpacking {archive_name}")
    shutil.rmtree(target, ignore_errors=True)
    if archive_name.endswith(".zip"):
        with zipfile.ZipFile(download) as archive:
            archive.extractall(STAGING)
    else:
        with tarfile.open(download) as archive:
            archive.extractall(STAGING)
    (STAGING / extracted).rename(target)

    # Only the executable and its shared libraries are needed; the bundled
    # npm, docs and headers are build-time tools.
    for junk in ("lib/node_modules", "include", "share", "CHANGELOG.md"):
        shutil.rmtree(target / junk, ignore_errors=True)
        (target / junk).unlink(missing_ok=True) if (target / junk).is_file() else None

    if not sys.platform.startswith("win"):
        os.chmod(target / "bin" / "node", 0o755)
    log(f"node staged: {_size(target)}")
    return target


# --------------------------------------------------------------------------
# 3. Chromium
# --------------------------------------------------------------------------

def stage_chromium(force: bool = False) -> Path:
    """Download Chromium with the SAME Playwright that will be bundled.

    Playwright resolves its browser by revision, so a mismatch between the
    packaged Playwright and the packaged browser fails at runtime with a
    message about running `playwright install`, which a teammate with a
    self-contained bundle cannot act on.
    """
    target = STAGING / "browsers"
    already = target.exists() and any(target.glob("chromium-*"))

    if already and not force:
        log(f"chromium already staged at {target}")
    else:
        target.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(target)}
        run([sys.executable, "-m", "playwright", "install", "chromium"],
            env=environment)

    # Pruning runs on EVERY call, not only after a fresh install. CI points
    # PLAYWRIGHT_BROWSERS_PATH here so the test step's browser download is
    # reused; that path skips the install above, and pruning inside the else
    # branch would silently ship the 320MB headless shell.
    #
    # Prune the headless shell and ffmpeg, ~330MB together.
    #
    # This is only safe because report/pdf.py launches with
    # channel="chromium". Playwright's DEFAULT is the headless shell, so
    # dropping these without that flag produces a bundle whose `doctor`
    # reports healthy and whose PDF export fails with "Executable doesn't
    # exist". If you ever remove that channel argument, stop pruning here.
    for extra in list(target.glob("chromium_headless_shell-*")) + list(target.glob("ffmpeg-*")):
        log(f"pruning {extra.name}")
        shutil.rmtree(extra, ignore_errors=True)

    log(f"chromium staged: {_size(target)}")
    return target


# --------------------------------------------------------------------------
# 4. PyInstaller
# --------------------------------------------------------------------------

def dist_target() -> Path:
    """Where runtime/ has to land, which differs on macOS.

    A .app is a directory, and `sys.executable` inside one points at
    ``Contents/MacOS/SLAP``. Putting runtime/ there keeps bundle.py's
    "look beside the executable" rule true on every platform.
    """
    if sys.platform == "darwin":
        return ROOT / "dist" / "SLAP.app" / "Contents" / "MacOS"
    return ROOT / "dist" / "SLAP"


def shippable_path() -> Path:
    """What actually gets zipped and handed to someone."""
    if sys.platform == "darwin":
        return ROOT / "dist" / "SLAP.app"
    return ROOT / "dist" / "SLAP"


def run_pyinstaller(clean: bool = False) -> Path:
    spec = PACKAGING / "slap.spec"
    command = [sys.executable, "-m", "PyInstaller", str(spec), "--noconfirm"]
    if clean:
        command.append("--clean")
    run(command, cwd=ROOT)
    target = dist_target()
    if not target.exists():
        raise SystemExit(f"PyInstaller did not produce {target}")
    return target


def copy_runtime(dist: Path) -> None:
    """Place the staged runtime beside the executable.

    Deliberately copied rather than passed to PyInstaller as `datas`:
    node_modules is ~12,000 files, and putting it through the archive makes
    builds slow, the result opaque, and a Lighthouse upgrade a full rebuild
    instead of a directory swap.
    """
    runtime = dist / "runtime"
    shutil.rmtree(runtime, ignore_errors=True)
    runtime.mkdir(parents=True, exist_ok=True)
    required = ("node_worker", "browsers")
    for name in (*required, "node"):
        source = STAGING / name
        if not source.exists():
            if name in required:
                raise SystemExit(f"staging incomplete: {source} missing")
            continue      # no staged node: Playwright's driver node is used
        log(f"copying {name}")
        shutil.copytree(source, runtime / name, symlinks=True)
    log(f"runtime placed: {_size(runtime)}")


def _size(path: Path) -> str:
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    return f"{total / 1_048_576:.0f} MB"


# --------------------------------------------------------------------------
# 5. macOS: re-seal the bundle, and get the user past Gatekeeper
# --------------------------------------------------------------------------

#: Shipped beside the .app inside the zip. A double-clickable script rather
#: than a line in a README, because the note nobody reads is exactly how
#: "damaged" becomes "this build is broken".
FIRST_RUN_NAME = "First run (macOS).command"

FIRST_RUN_COMMAND = """\
#!/bin/bash
#
# SLAP is not signed with a paid Apple Developer certificate, so macOS
# refuses to open it and reports that it is "damaged". It is not damaged.
# That is what Gatekeeper says about ANY app downloaded from the internet
# without an Apple signature, and the fix is to remove the download flag.
#
# You only need to run this once, on this copy of SLAP.
#
# Finder will not let you double-click this the first time either:
#     RIGHT CLICK it, choose Open, then Open again in the dialog.

cd "$(dirname "$0")" || exit 1

if [ ! -d "SLAP.app" ]; then
  echo "SLAP.app is not in this folder."
  echo "Keep this script and SLAP.app together and try again."
  read -n 1 -s -r -p "Press any key to close this window."
  exit 1
fi

echo "Removing the macOS download flag from SLAP.app..."
xattr -dr com.apple.quarantine "SLAP.app" 2>/dev/null

echo "Starting SLAP. Your browser will open in a moment."
open "SLAP.app" || {
  echo
  echo "macOS still refused to open it. From Terminal, run:"
  echo "    xattr -dr com.apple.quarantine \\"$PWD/SLAP.app\\""
  read -n 1 -s -r -p "Press any key to close this window."
  exit 1
}

sleep 2
"""

FIRST_RUN_README = """\
SLAP for macOS
==============

If you double-click SLAP.app first, macOS says it is "damaged and can't be
opened". It is not damaged. SLAP is not signed with a paid Apple Developer
certificate, and that is the message macOS shows for any unsigned app that
came from the internet.

To run it
---------

  RIGHT CLICK "%(script)s", choose Open, then Open again.

That removes the download flag from SLAP.app and starts it. You only need
to do it once. Afterwards, open SLAP.app normally.

If you would rather do it yourself, the same thing in Terminal:

  xattr -dr com.apple.quarantine /path/to/SLAP.app

What SLAP is
------------

A website performance and security auditor. It opens in your browser at
http://127.0.0.1:8765 and everything runs on this machine: no account, no
upload, no server. Quit it from the "Quit SLAP" button in the sidebar.

Keep SLAP.app and this folder's contents together the first time you run
it. Afterwards you can move SLAP.app anywhere, including Applications.
""" % {"script": FIRST_RUN_NAME}


def sign_macos_app(app: Path) -> None:
    """Re-seal the .app, after everything has been copied into it.

    **This is what "SLAP is damaged and can't be opened" means.** macOS is
    not describing a corrupt download; it is reporting a code signature
    that does not match the bundle's contents. PyInstaller signs the .app
    when it assembles it, and then this script copies ~700MB of
    ``runtime/`` and a build manifest *inside* ``Contents/MacOS``. Every
    one of those files lands under the seal PyInstaller just applied, so
    the signature is invalid before the build finishes. On Apple Silicon
    that is fatal rather than cosmetic: the kernel enforces signatures on
    every executable, so a broken seal is an app that cannot start at all.

    Nothing caught it because nothing verified the signature and because
    the CI check launches ``Contents/MacOS/SLAP`` directly from a shell.
    Running the inner executable does not consult the bundle seal;
    double-clicking the .app does. Same shape as the windowed-build crash:
    the one launch every user performs was the one nothing exercised.

    So: sign last, and verify. ``--deep`` because every Mach-O in the
    bundle needs a signature of its own on arm64, including the Chromium
    and Node that were copied in whole. Ad-hoc (``--sign -``) because this
    project has no Apple certificate; that is enough for the app to RUN,
    and Gatekeeper's separate objection to unsigned downloads is what the
    first-run helper handles.
    """
    if sys.platform != "darwin":
        return

    log("re-signing the .app now that runtime/ is in place")
    # Extended attributes collected during staging (quarantine flags on the
    # downloaded Chromium, Finder metadata) make codesign fail outright with
    # "resource fork, Finder information, or similar detritus not allowed".
    subprocess.run(["xattr", "-cr", str(app)], check=False)

    deep = subprocess.run(
        ["codesign", "--force", "--deep", "--sign", "-", "--timestamp=none",
         str(app)], capture_output=True, text=True)
    if deep.returncode != 0:
        # Not fatal, and not silent. `--deep` walks a nested Chromium .app
        # of ~12,000 files and can object to something inside a framework
        # that has nothing to do with whether SLAP opens. Sealing the outer
        # bundle alone still fixes "damaged", and leaves Chromium carrying
        # Google's own signature, which is the better one anyway.
        log("deep signing failed, sealing the outer bundle only: "
            + " ".join((deep.stderr or "").split())[:300])
        run(["codesign", "--force", "--sign", "-", "--timestamp=none",
             str(app)])

    # The outer seal decides whether the .app opens, so a failure here
    # fails the build. Shipping an unopenable bundle that took ten minutes
    # to build wastes far more of someone's day than a red CI step does.
    sealed = subprocess.run(["codesign", "--verify", "--strict", str(app)],
                            capture_output=True, text=True)
    if sealed.returncode != 0:
        raise SystemExit(
            "[build] the .app will not seal, so macOS would call it damaged:\n"
            f"  {' '.join((sealed.stderr or '').split())}\n"
            "  Most likely cause: something wrote into the bundle after this\n"
            "  step, or runtime/ sits somewhere codesign will not seal. Apple\n"
            "  expects only executables in Contents/MacOS; moving runtime/ to\n"
            "  Contents/Resources (and teaching bundle.runtime_dir to look\n"
            "  there) is the fix if this is the layout it objects to."
        )
    log("bundle signature verified")

    # Nested code is checked but not gated. A quibble inside Chromium's own
    # framework does not stop SLAP from launching, and the check that
    # actually proves the nested binaries run is the one already in the
    # pipeline: `slap verify` launches Chromium for the PDF export and Node
    # for Lighthouse, from this exact bundle, immediately after this step.
    deep = subprocess.run(["codesign", "--verify", "--deep", "--strict",
                           str(app)], capture_output=True, text=True)
    if deep.returncode != 0:
        log("note: nested signature check reported: "
            + " ".join((deep.stderr or "").split())[:300])


def add_macos_first_run_files(archive: Path) -> None:
    """Put the Gatekeeper helper and its explanation inside the zip.

    Appended to the archive rather than staged into a folder first: the
    .app is a gigabyte and copying it to add two small files beside it
    would double the build's disk and minutes for no gain. They land at the
    archive root, so unzipping produces a folder holding SLAP.app, the
    helper, and the README together.
    """
    import time

    # A real timestamp, not ZipInfo's 1980 default. A file dated 1980 sitting
    # beside an app macOS just called "damaged" reads as more corruption,
    # which is the one impression these two files exist to prevent.
    now = time.localtime()[:6]

    with zipfile.ZipFile(archive, "a") as bundle_zip:
        script = zipfile.ZipInfo(FIRST_RUN_NAME, date_time=now)
        # create_system=3 marks the entry as Unix; without it the mode bits
        # below are ignored on extraction and the "script" arrives without
        # its executable bit, which is a double-click that does nothing.
        script.create_system = 3
        script.external_attr = 0o100755 << 16
        bundle_zip.writestr(script, FIRST_RUN_COMMAND)

        readme = zipfile.ZipInfo("READ ME FIRST (macOS).txt", date_time=now)
        readme.create_system = 3
        readme.external_attr = 0o100644 << 16
        bundle_zip.writestr(readme, FIRST_RUN_README)


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip-npm", action="store_true")
    parser.add_argument("--skip-node", action="store_true")
    parser.add_argument("--skip-chromium", action="store_true")
    parser.add_argument("--skip-vulndb", action="store_true",
                        help="use the committed vulnerability database as-is")
    parser.add_argument("--require-vulndb", action="store_true",
                        help="fail rather than fall back to the committed "
                             "database. CI passes this so a release never "
                             "ships stale data by accident")
    parser.add_argument("--force-staging", action="store_true",
                        help="re-download and reinstall everything")
    parser.add_argument("--clean", action="store_true",
                        help="pass --clean to PyInstaller")
    parser.add_argument("--zip", action="store_true",
                        help="also produce dist/SLAP-<platform>.zip")
    args = parser.parse_args(argv)

    log(f"building on {sys.platform} / {platform.machine()}")
    if not args.skip_npm:
        stage_worker(args.force_staging)
    if not args.skip_node:
        stage_node(args.force_staging)
    if not args.skip_chromium:
        stage_chromium(args.force_staging)
    if not args.skip_vulndb:
        stage_vulndb(args.force_staging, required=args.require_vulndb)

    dist = run_pyinstaller(clean=args.clean)
    copy_runtime(dist)
    # Scanned over the SHIPPABLE root, not the dist target. They are the
    # same directory everywhere except macOS, where dist is
    # Contents/MacOS (the executable and runtime/) but PyInstaller puts an
    # .app's data files under Contents/Resources, symlinked from
    # Contents/Frameworks. rglob does not follow directory symlinks, so
    # scanning Contents/MacOS reported "no vulndb.json" on a bundle that
    # carried it, and failed every macOS build.
    verify_vulndb(shippable_path())

    manifest = {
        "platform": sys.platform,
        "machine": platform.machine(),
        "node": NODE_VERSION,
        "python": sys.version.split()[0],
        "chromium_only": True,
    }
    # The database date belongs in the manifest as well as the report: it is
    # the one build input that goes stale on its own after shipping.
    try:
        from slap.vulndb import VulnDatabase, default_db_path

        database = VulnDatabase.load(default_db_path())
        manifest["vulndb_generated"] = database.generated_at
        manifest["vulndb_advisories"] = database.count
    except Exception:                                 # noqa: BLE001
        manifest["vulndb_generated"] = None
    (dist / "build-manifest.json").write_text(json.dumps(manifest, indent=2))

    if sys.platform == "darwin":
        # PyInstaller emits BOTH dist/SLAP/ (the COLLECT output) and
        # dist/SLAP.app/. Only the .app got runtime/, so leaving the other
        # behind is a ~400MB copy that looks like the app and does not work.
        stray = ROOT / "dist" / "SLAP"
        if stray.is_dir():
            log("removing the redundant non-.app collection")
            shutil.rmtree(stray, ignore_errors=True)

    # LAST. Every line above this one may write inside the .app, and each
    # write invalidates the signature; see sign_macos_app for what that
    # costs. Anything added to this function after today belongs ABOVE
    # here unless it genuinely must follow the seal.
    sign_macos_app(shippable_path())

    shippable = shippable_path()
    log(f"built {shippable} ({_size(shippable)})")

    if args.zip:
        name = f"SLAP-{PLATFORM_TAG}-{platform.machine()}"
        archive = ROOT / "dist" / f"{name}.zip"
        log(f"zipping to {archive.name} (a few minutes)")
        if sys.platform == "darwin":
            # ditto preserves symlinks, resource forks and the executable
            # bit inside a .app. shutil.make_archive does not, and an .app
            # that lost its exec bit will not open. It also preserves the
            # code signature, which a naive zip-and-unzip round trip
            # destroys just as thoroughly as writing into the bundle does.
            run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                 str(shippable), str(archive)])
            add_macos_first_run_files(archive)
        else:
            shutil.make_archive(str(ROOT / "dist" / name), "zip",
                                shippable.parent, shippable.name)
        log(f"zipped: {archive.stat().st_size / 1_048_576:.0f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
