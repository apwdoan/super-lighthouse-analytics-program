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

from salp import bundle


@pytest.fixture
def fake_bundle(tmp_path, monkeypatch):
    """A directory laid out like a built distributable."""
    root = tmp_path / "SALP"
    (root / "runtime" / "node_worker").mkdir(parents=True)
    (root / "runtime" / "node_worker" / "worker.js").write_text("//")
    (root / "runtime" / "browsers" / "chromium-1194" / "chrome-linux").mkdir(parents=True)
    (root / "runtime" / "browsers" / "chromium-1194" / "chrome-linux" / "chrome").write_text("")
    (root / "_internal" / "playwright" / "driver").mkdir(parents=True)
    (root / "_internal" / "playwright" / "driver" / "node").write_text("")
    (root / "SALP").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(root), raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "SALP"))
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

    PyInstaller's BUNDLE() puts the executable at Contents/MacOS/SALP, so
    runtime/ goes beside it there. Chromium inside a .app has a different
    path shape again. Neither is exercised by the Linux build, so it is
    asserted here rather than discovered on someone's laptop.
    """
    app = tmp_path / "SALP.app" / "Contents" / "MacOS"
    chromium = (app / "runtime" / "browsers" / "chromium-1194" /
                "chrome-mac" / "Chromium.app" / "Contents" / "MacOS")
    chromium.mkdir(parents=True)
    (chromium / "Chromium").write_text("")
    (app / "runtime" / "node_worker").mkdir(parents=True)
    (app / "runtime" / "node_worker" / "worker.js").write_text("//")
    (app / "SALP").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(app), raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "SALP"))

    assert bundle.bundle_root() == app
    assert bundle.bundled_chromium() == chromium / "Chromium"
    assert bundle.bundled_worker() == app / "runtime" / "node_worker" / "worker.js"


def test_resolves_a_windows_layout(tmp_path, monkeypatch):
    root = tmp_path / "SALP"
    chromium = root / "runtime" / "browsers" / "chromium-1194" / "chrome-win"
    chromium.mkdir(parents=True)
    (chromium / "chrome.exe").write_text("")
    (root / "_internal" / "playwright" / "driver").mkdir(parents=True)
    (root / "_internal" / "playwright" / "driver" / "node.exe").write_text("")
    (root / "SALP.exe").write_text("")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(root), raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "SALP.exe"))

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
    from salp.collectors.lighthouse import LighthouseConfig, LighthouseRunner

    runner = LighthouseRunner(LighthouseConfig())
    assert runner.worker_script == fake_bundle / "runtime/node_worker/worker.js"
    assert runner.node_executable == str(fake_bundle / "_internal/playwright/driver/node")


def test_an_explicit_node_path_still_wins(fake_bundle):
    from salp.collectors.lighthouse import LighthouseConfig, LighthouseRunner

    runner = LighthouseRunner(LighthouseConfig(node_path="/usr/local/bin/node"))
    assert runner.node_executable == "/usr/local/bin/node"


def test_chrome_resolution_prefers_the_bundle(fake_bundle, monkeypatch):
    from salp.collectors.lighthouse import default_chrome_path

    monkeypatch.delenv("CHROME_PATH", raising=False)
    assert default_chrome_path() == str(
        fake_bundle / "runtime/browsers/chromium-1194/chrome-linux/chrome"
    )
