"""Tests for frozen-bundle path resolution.

These run from a source checkout, so `is_frozen()` is False throughout and
the interesting cases are simulated by monkeypatching `sys.frozen` and
`sys.executable`. That is enough: the logic under test is "given this
directory layout, which file do we pick", and the real bundle is verified
separately by actually building and running one.
"""

from __future__ import annotations

import sys

import pytest

from slap import bundle


@pytest.fixture
def fake_bundle(tmp_path, monkeypatch):
    """A directory laid out like a built distributable."""
    root = tmp_path / "SLAP"
    (root / "runtime" / "node_worker").mkdir(parents=True)
    (root / "runtime" / "node_worker" / "worker.js").write_text("//")
    (root / "runtime" / "browsers" / "chromium-1194" / "chrome-linux").mkdir(parents=True)
    (root / "runtime" / "browsers" / "chromium-1194" / "chrome-linux" / "chrome").write_text("")
    (root / "_internal" / "playwright" / "driver").mkdir(parents=True)
    (root / "_internal" / "playwright" / "driver" / "node").write_text("")
    (root / "SLAP").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(root), raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "SLAP"))
    return root


# --------------------------------------------------------------------------
# From source, everything is None and nothing changes
# --------------------------------------------------------------------------

def test_source_checkout_resolves_nothing():
    assert bundle.is_frozen() is False
    assert bundle.bundle_root() is None
    assert bundle.bundled_node() is None
    assert bundle.bundled_worker() is None
    assert bundle.bundled_chromium() is None


def test_configure_environment_is_a_no_op_from_source(monkeypatch):
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    bundle.configure_environment()
    assert "PLAYWRIGHT_BROWSERS_PATH" not in __import__("os").environ


# --------------------------------------------------------------------------
# From a bundle
# --------------------------------------------------------------------------

def test_bundle_root_follows_the_executable_not_meipass(fake_bundle, monkeypatch):
    """One-file builds set _MEIPASS to a temp dir that has no runtime/."""
    monkeypatch.setattr(sys, "_MEIPASS", "/tmp/definitely-not-here", raising=False)
    assert bundle.bundle_root() == fake_bundle


def test_resolves_worker_and_chromium(fake_bundle):
    assert bundle.bundled_worker() == fake_bundle / "runtime/node_worker/worker.js"
    assert bundle.bundled_chromium() == (
        fake_bundle / "runtime/browsers/chromium-1194/chrome-linux/chrome"
    )


def test_falls_back_to_playwrights_node(fake_bundle):
    """Saves shipping a second ~120MB Node in the same distributable."""
    assert bundle.bundled_node() == fake_bundle / "_internal/playwright/driver/node"
    assert bundle.describe()["node_source"] == "playwright driver"


def test_a_staged_node_wins_over_playwrights(fake_bundle):
    staged = fake_bundle / "runtime" / "node" / "bin"
    staged.mkdir(parents=True)
    (staged / "node").write_text("")
    assert bundle.bundled_node() == staged / "node"
    assert bundle.describe()["node_source"] == "staged runtime"


def test_resolves_a_macos_app_layout(tmp_path, monkeypatch):
    """The only macOS verification possible without a Mac.

    PyInstaller's BUNDLE() puts the executable at Contents/MacOS/SLAP, so
    runtime/ goes beside it there. Chromium inside a .app has a different
    path shape again. Neither is exercised by the Linux build, so it is
    asserted here rather than discovered on someone's laptop.
    """
    app = tmp_path / "SLAP.app" / "Contents" / "MacOS"
    chromium = (app / "runtime" / "browsers" / "chromium-1194" /
                "chrome-mac" / "Chromium.app" / "Contents" / "MacOS")
    chromium.mkdir(parents=True)
    (chromium / "Chromium").write_text("")
    (app / "runtime" / "node_worker").mkdir(parents=True)
    (app / "runtime" / "node_worker" / "worker.js").write_text("//")
    (app / "SLAP").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(app), raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "SLAP"))

    assert bundle.bundle_root() == app
    assert bundle.bundled_chromium() == chromium / "Chromium"
    assert bundle.bundled_worker() == app / "runtime" / "node_worker" / "worker.js"


def test_finds_playwrights_node_inside_a_mac_apps_frameworks(tmp_path,
                                                             monkeypatch):
    """The check the first full Mac `slap verify` failed. PyInstaller does
    not put an .app's packages beside the executable: they are split between
    Contents/Frameworks (binaries) and Contents/Resources (data), and
    Playwright's driver Node is a binary. Searching only Contents/MacOS and
    `_internal*` reported "no Node in the bundle" on a bundle that carried
    it, which also means Lighthouse had silently never worked in a Mac
    bundle: the audit degrades to no-lab rather than erroring, so only the
    dedicated lighthouse check ever noticed."""
    contents = tmp_path / "SLAP.app" / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)
    (macos / "SLAP").write_text("")
    driver = contents / "Frameworks" / "playwright" / "driver"
    driver.mkdir(parents=True)
    (driver / "node").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(contents / "Frameworks"),
                        raising=False)
    monkeypatch.setattr(sys, "executable", str(macos / "SLAP"))

    assert bundle.playwright_driver_node() == driver / "node"
    assert bundle.bundled_node() == driver / "node"


def test_resolves_a_windows_layout(tmp_path, monkeypatch):
    root = tmp_path / "SLAP"
    chromium = root / "runtime" / "browsers" / "chromium-1194" / "chrome-win"
    chromium.mkdir(parents=True)
    (chromium / "chrome.exe").write_text("")
    (root / "_internal" / "playwright" / "driver").mkdir(parents=True)
    (root / "_internal" / "playwright" / "driver" / "node.exe").write_text("")
    (root / "SLAP.exe").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(root), raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "SLAP.exe"))

    assert bundle.bundled_chromium() == chromium / "chrome.exe"
    assert bundle.bundled_node() == (
        root / "_internal" / "playwright" / "driver" / "node.exe"
    )


def test_newest_chromium_revision_wins(fake_bundle):
    newer = fake_bundle / "runtime/browsers/chromium-1300/chrome-linux"
    newer.mkdir(parents=True)
    (newer / "chrome").write_text("")
    assert bundle.bundled_chromium() == newer / "chrome"


def test_configure_environment_points_playwright_at_the_bundle(fake_bundle, monkeypatch):
    import os

    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    bundle.configure_environment()
    assert os.environ["PLAYWRIGHT_BROWSERS_PATH"] == str(fake_bundle / "runtime/browsers")
    assert os.environ["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] == "1"


def test_configure_environment_respects_a_deliberate_override(fake_bundle, monkeypatch):
    import os

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/somewhere/else")
    bundle.configure_environment()
    assert os.environ["PLAYWRIGHT_BROWSERS_PATH"] == "/somewhere/else"


def test_missing_runtime_folder_degrades_quietly(fake_bundle):
    import shutil

    shutil.rmtree(fake_bundle / "runtime")
    assert bundle.runtime_dir() is None
    assert bundle.bundled_worker() is None
    assert bundle.bundled_chromium() is None
    # Playwright's node lives outside runtime/, so it still resolves.
    assert bundle.bundled_node() is not None


# --------------------------------------------------------------------------
# The runner honours all of it
# --------------------------------------------------------------------------

def test_runner_uses_the_bundled_node_and_worker(fake_bundle):
    from slap.collectors.lighthouse import LighthouseConfig, LighthouseRunner

    runner = LighthouseRunner(LighthouseConfig())
    assert runner.worker_script == fake_bundle / "runtime/node_worker/worker.js"
    assert runner.node_executable == str(fake_bundle / "_internal/playwright/driver/node")


def test_an_explicit_node_path_still_wins(fake_bundle):
    from slap.collectors.lighthouse import LighthouseConfig, LighthouseRunner

    runner = LighthouseRunner(LighthouseConfig(node_path="/usr/local/bin/node"))
    assert runner.node_executable == "/usr/local/bin/node"


def test_chrome_resolution_prefers_the_bundle(fake_bundle, monkeypatch):
    from slap.collectors.lighthouse import default_chrome_path

    monkeypatch.delenv("CHROME_PATH", raising=False)
    assert default_chrome_path() == str(
        fake_bundle / "runtime/browsers/chromium-1194/chrome-linux/chrome"
    )


# --------------------------------------------------------------------------
# Playwright renames its browser directories. Repeatedly.
#
# Between revisions 1194 and 1228 every platform moved, and the hardcoded
# table these tests replaced returned None for all of them after a routine
# `pip install -U playwright`. In a bundle that means "no browser shipped".
# --------------------------------------------------------------------------

import pytest

from slap import bundle as _bundle


def _make(root, relative: str):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"#!/bin/sh\n")
    path.chmod(0o755)
    return path


@pytest.mark.parametrize("layout", [
    # Playwright <= 1.56 (revision 1194)
    "chrome-linux/chrome",
    "chrome-win/chrome.exe",
    "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
    # Playwright 1.61 (revision 1228). Every one of these is a rename.
    "chrome-linux64/chrome",
    "chrome-win64/chrome.exe",
    "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/"
    "Google Chrome for Testing",
    "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/"
    "Google Chrome for Testing",
])
def test_every_known_playwright_layout_resolves(tmp_path, layout):
    revision = tmp_path / "chromium-1228"
    expected = _make(revision, layout)
    assert _bundle.find_chromium_in(revision) == expected
    assert _bundle.find_chromium_under(tmp_path) == expected


def test_the_newest_revision_wins_numerically(tmp_path):
    """chromium-1228 is newer than chromium-999, but sorts before it as text."""
    _make(tmp_path / "chromium-999", "chrome-linux64/chrome")
    newest = _make(tmp_path / "chromium-1228", "chrome-linux64/chrome")
    assert _bundle.find_chromium_under(tmp_path) == newest


def test_the_headless_shell_is_not_mistaken_for_chromium(tmp_path):
    """build.py prunes the shell; a bundle must never resolve to one."""
    _make(tmp_path / "chromium_headless_shell-1228",
          "chrome-linux64/chrome-headless-shell")
    assert _bundle.find_chromium_under(tmp_path) is None


def test_a_directory_with_no_browser_returns_none(tmp_path):
    (tmp_path / "chromium-1228").mkdir()
    assert _bundle.find_chromium_under(tmp_path) is None


def test_a_helper_file_beside_the_mac_binary_is_not_mistaken_for_it(tmp_path):
    """The macOS pattern ends in `*` because the binary name keeps changing.

    Match the binary macOS itself would launch, the one named after the
    .app, rather than whatever sorts first in Contents/MacOS/.
    """
    revision = tmp_path / "chromium-1228"
    app = revision / "chrome-mac-arm64" / "Google Chrome for Testing.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    (macos / "AAA_helper").write_text("sorts first, not the binary")
    real = macos / "Google Chrome for Testing"
    real.write_text("the real one")

    assert _bundle.find_chromium_in(revision) == real
