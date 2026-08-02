"""Locating the runtime pieces, whether running from source or frozen.

SLAP needs three things that are not Python: a Node runtime, the Lighthouse
worker's ``node_modules``, and a Chromium build. From a source checkout
those come from the developer's machine. From a PyInstaller bundle they
ship inside the distributable, because the whole point of the bundle is
that a teammate installs nothing.

Layout of a built distributable::

    SLAP/
      SLAP.exe                     PyInstaller entry point
      _internal/                   Python runtime and site-packages
      runtime/
        node/node.exe              Node 22 for the Lighthouse worker
        node_worker/               worker.js + node_modules
        browsers/chromium-<rev>/   Playwright's Chromium

``runtime/`` deliberately sits **outside** ``_internal``. The Lighthouse
worker's ``node_modules`` is roughly 12,000 files; putting it through
PyInstaller's archive makes builds slow and the contents opaque, and none
of it is imported by Python anyway. Keeping it a plain folder also means a
Lighthouse upgrade is a directory swap rather than a rebuild.

Everything here degrades to "not bundled" and returns None, so a source
checkout behaves exactly as it did before.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

#: Name of the runtime folder beside the executable.
RUNTIME_DIRNAME = "runtime"

#: Minimum Node for Lighthouse 13, from its package.json `engines`.
MIN_NODE = (22, 19)


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def bundle_root() -> Path | None:
    """Directory containing the executable, or None from source.

    One-dir builds put the exe beside ``_internal``; ``sys.executable`` is
    the reliable anchor in both one-dir and one-file layouts, whereas
    ``sys._MEIPASS`` points at the temporary extraction directory for
    one-file and would lose ``runtime/``.
    """
    if not is_frozen():
        return None
    return Path(sys.executable).resolve().parent


def runtime_dir() -> Path | None:
    root = bundle_root()
    if root is None:
        return None
    directory = root / RUNTIME_DIRNAME
    return directory if directory.is_dir() else None


def _first_existing(*candidates: Path) -> Path | None:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def package_roots() -> list[Path]:
    """Every directory bundled Python packages can resolve under.

    One-dir builds put them in ``_internal`` beside the executable. A macOS
    .app does not: PyInstaller splits an app bundle's contents between
    ``Contents/Frameworks`` (binaries) and ``Contents/Resources`` (data),
    while the executable sits alone in ``Contents/MacOS``. Searching only
    beside the executable is why the first full Mac run of `slap verify`
    reported "no Node in the bundle" on a bundle that carried Playwright's
    driver Node in Frameworks the whole time — and why nothing before that
    run noticed Lighthouse had silently never worked in a Mac bundle.
    """
    root = bundle_root()
    if root is None:
        return []
    roots = [root, *root.glob("_internal*")]
    if root.name == "MacOS" and root.parent.name == "Contents":
        contents = root.parent
        roots += [contents / "Frameworks", contents / "Resources"]
    return [r for r in roots if r.is_dir()]


def playwright_driver_node() -> Path | None:
    """Node shipped inside the Playwright package, if it is there.

    Playwright bundles a full Node runtime to drive its own protocol server
    (~110MB). When it is new enough for Lighthouse, reusing it saves
    shipping a *second* Node in the same distributable. The build script
    checks the version and only stages a separate runtime if this one is
    too old, so a future Playwright that downgrades its Node cannot break
    the bundle silently.
    """
    for parent in package_roots():
        found = _first_existing(
            parent / "playwright" / "driver" / "node.exe",
            parent / "playwright" / "driver" / "node",
        )
        if found is not None:
            return found
    return None


def bundled_node() -> Path | None:
    """The Node executable to run the Lighthouse worker with.

    A dedicated ``runtime/node`` wins if the build staged one; otherwise
    Playwright's driver Node is used.
    """
    runtime = runtime_dir()
    staged = None
    if runtime is not None:
        staged = _first_existing(
            runtime / "node" / "node.exe",
            runtime / "node" / "node",
            runtime / "node" / "bin" / "node",
        )
    return staged if staged is not None else playwright_driver_node()


def bundled_worker() -> Path | None:
    """The bundled Lighthouse worker script, if there is one."""
    runtime = runtime_dir()
    if runtime is None:
        return None
    return _first_existing(runtime / "node_worker" / "worker.js")


def browsers_dir() -> Path | None:
    """The bundled Playwright browsers directory, if there is one."""
    runtime = runtime_dir()
    if runtime is None:
        return None
    directory = runtime / "browsers"
    return directory if directory.is_dir() else None


#: Where the Chromium executable sits inside one ``chromium-<rev>`` folder.
#:
#: These are GLOBS, not fixed paths, because Playwright renames these
#: directories and Chromium itself gets renamed inside them. Between
#: revisions 1194 and 1228 alone, every single platform moved:
#:
#:     chrome-linux/chrome   ->  chrome-linux64/chrome
#:     chrome-win/chrome.exe ->  chrome-win64/chrome.exe
#:     chrome-mac/Chromium.app/Contents/MacOS/Chromium
#:         -> chrome-mac-{arm64,x64}/Google Chrome for Testing.app/
#:            Contents/MacOS/Google Chrome for Testing
#:
#: A hardcoded table silently returned None everywhere after a routine
#: Playwright upgrade, which in a bundle means "no browser shipped".
CHROMIUM_GLOBS = (
    "chrome-win*/chrome.exe",
    "chrome-linux*/chrome",
    "chrome-mac*/*.app/Contents/MacOS/*",
)


def find_chromium_in(revision_dir: Path) -> Path | None:
    """The Chromium executable inside one ``chromium-<rev>`` directory."""
    for pattern in CHROMIUM_GLOBS:
        for candidate in sorted(revision_dir.glob(pattern)):
            if not candidate.is_file():
                continue
            # The macOS pattern ends in `*` because the binary is named
            # after the app, and that name changed too ("Chromium" ->
            # "Google Chrome for Testing"). A .app's MacOS/ directory can
            # hold helpers, so match the one binary macOS itself would
            # launch: the one sharing the bundle's name. Checking the
            # executable bit instead would be wrong on Windows and would
            # break on any unzip that drops permissions.
            if candidate.suffix != ".exe" and candidate.name != "chrome":
                app = candidate.parents[2]
                if app.suffix == ".app" and candidate.name != app.stem:
                    continue
            return candidate
    return None


def find_chromium_under(browsers: Path) -> Path | None:
    """Newest Chromium under a Playwright browsers directory, or None.

    Newest revision wins, so dropping in an upgraded browser directory does
    not need a config change. ``chromium_headless_shell-*`` is deliberately
    not matched: the glob is ``chromium-*`` and the shell directory does not
    start with that.
    """
    revisions = sorted(
        browsers.glob("chromium-*"),
        key=lambda p: (_revision_number(p), p.name),
        reverse=True,
    )
    for directory in revisions:
        found = find_chromium_in(directory)
        if found is not None:
            return found
    return None


def _revision_number(path: Path) -> int:
    """Sort revisions numerically: chromium-1228 is newer than chromium-999."""
    tail = path.name.rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else -1


def bundled_chromium() -> Path | None:
    """The bundled Chromium executable, if there is one."""
    browsers = browsers_dir()
    if browsers is None:
        return None
    return find_chromium_under(browsers)


def configure_environment() -> None:
    """Point Playwright at the bundled browsers. Call once at startup.

    Playwright resolves its browser by revision under
    ``PLAYWRIGHT_BROWSERS_PATH``, so setting that one variable makes **both**
    PDF export and the Lighthouse runner use the bundled Chromium, with no
    other code changes. It is set only when a bundled browsers directory
    exists, and never overrides a value the user set deliberately.

    The bundled Playwright and the bundled browser revision must match,
    which they do because the build script downloads the browser with the
    same Playwright it packages.
    """
    browsers = browsers_dir()
    if browsers is not None and not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)

    # Nothing in a bundle should ever try to fetch a browser at runtime.
    if is_frozen():
        os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")


def describe() -> dict[str, str | None]:
    """What the runtime resolved to. Rendered by `slap doctor`."""
    return {
        "frozen": str(is_frozen()),
        "bundle_root": str(bundle_root()) if bundle_root() else None,
        "node": str(bundled_node()) if bundled_node() else None,
        "node_source": (
            None if not bundled_node() else
            "playwright driver"
            if bundled_node() == playwright_driver_node() else "staged runtime"
        ),
        "worker": str(bundled_worker()) if bundled_worker() else None,
        "chromium": str(bundled_chromium()) if bundled_chromium() else None,
    }
