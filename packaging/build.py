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
4. run PyInstaller

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

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip-npm", action="store_true")
    parser.add_argument("--skip-node", action="store_true")
    parser.add_argument("--skip-chromium", action="store_true")
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

    dist = run_pyinstaller(clean=args.clean)
    copy_runtime(dist)

    manifest = {
        "platform": sys.platform,
        "machine": platform.machine(),
        "node": NODE_VERSION,
        "python": sys.version.split()[0],
        "chromium_only": True,
    }
    (dist / "build-manifest.json").write_text(json.dumps(manifest, indent=2))

    if sys.platform == "darwin":
        # PyInstaller emits BOTH dist/SLAP/ (the COLLECT output) and
        # dist/SLAP.app/. Only the .app got runtime/, so leaving the other
        # behind is a ~400MB copy that looks like the app and does not work.
        stray = ROOT / "dist" / "SLAP"
        if stray.is_dir():
            log("removing the redundant non-.app collection")
            shutil.rmtree(stray, ignore_errors=True)

    shippable = shippable_path()
    log(f"built {shippable} ({_size(shippable)})")

    if args.zip:
        name = f"SLAP-{PLATFORM_TAG}-{platform.machine()}"
        archive = ROOT / "dist" / f"{name}.zip"
        log(f"zipping to {archive.name} (a few minutes)")
        if sys.platform == "darwin":
            # ditto preserves symlinks, resource forks and the executable
            # bit inside a .app. shutil.make_archive does not, and an .app
            # that lost its exec bit will not open.
            run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                 str(shippable), str(archive)])
        else:
            shutil.make_archive(str(ROOT / "dist" / name), "zip",
                                shippable.parent, shippable.name)
        log(f"zipped: {archive.stat().st_size / 1_048_576:.0f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
