"""The build script's macOS handling, which is not testable on macOS here.

Every assertion in this file is about the *decisions* the build script
makes rather than about codesign's output, because there is no Mac in this
environment and pretending otherwise is how the bug these tests exist for
shipped in the first place: nothing ever checked the signature, so nobody
noticed the build was invalidating it.

What CI still has to prove, and does: `slap verify` launches Chromium and
Node out of the signed bundle immediately after this signing step, so a
signature that breaks the nested binaries fails the macOS job.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys
import zipfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "packaging"))

import build  # noqa: E402


class FakeRun:
    """Records commands. Fails the ones whose text contains a marker."""

    def __init__(self, fail_containing: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail_containing = fail_containing

    def __call__(self, command, **kwargs):
        words = [str(c) for c in command]
        self.calls.append(words)
        joined = " ".join(words)
        failed = bool(self.fail_containing and self.fail_containing in joined)
        if failed and kwargs.get("check"):
            raise subprocess.CalledProcessError(1, words)
        return subprocess.CompletedProcess(
            words, 1 if failed else 0, stdout="", stderr="a nested quibble")

    def flags_for(self, tool: str) -> list[str]:
        for call in self.calls:
            if call and call[0] == tool:
                return call
        return []


@pytest.fixture
def on_macos(monkeypatch):
    monkeypatch.setattr(build.sys, "platform", "darwin")


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------

def test_signing_is_a_no_op_off_macos(monkeypatch, tmp_path):
    """Windows and Linux builds must not grow a dependency on codesign."""
    fake = FakeRun()
    monkeypatch.setattr(build.sys, "platform", "linux")
    # Only subprocess.run is faked: build.run() itself is the code under
    # test as much as anything else here, since it is what adds check=True
    # and therefore what turns a failed codesign into a failed build.
    monkeypatch.setattr(build.subprocess, "run", fake)
    build.sign_macos_app(tmp_path / "SLAP.app")
    assert fake.calls == []


def test_the_app_is_signed_deeply_and_ad_hoc(on_macos, monkeypatch, tmp_path):
    """`--deep` because every Mach-O in the bundle needs its own signature
    on Apple Silicon, including the Chromium and Node copied in whole.
    Ad-hoc because this project has no Apple certificate, and ad-hoc is
    enough for the app to RUN."""
    fake = FakeRun()
    # Only subprocess.run is faked: build.run() itself is the code under
    # test as much as anything else here, since it is what adds check=True
    # and therefore what turns a failed codesign into a failed build.
    monkeypatch.setattr(build.subprocess, "run", fake)

    build.sign_macos_app(tmp_path / "SLAP.app")

    sign = next(c for c in fake.calls if c[0] == "codesign" and "--force" in c)
    assert "--deep" in sign
    assert sign[sign.index("--sign") + 1] == "-"        # ad-hoc
    assert str(tmp_path / "SLAP.app") in sign

    # Extended attributes picked up during staging make codesign refuse
    # outright ("resource fork, Finder information, or similar detritus").
    assert ["xattr", "-cr", str(tmp_path / "SLAP.app")] in fake.calls


def test_deep_signing_falling_over_still_seals_the_bundle(on_macos, monkeypatch,
                                                          tmp_path, capsys):
    """`--deep` walks a nested Chromium .app of ~12,000 files and can object
    to something inside a framework that has nothing to do with whether
    SLAP opens. Sealing the outer bundle alone still fixes "damaged", so a
    build that can produce a working app should produce one."""
    fake = FakeRun(fail_containing="--deep --sign")
    monkeypatch.setattr(build.subprocess, "run", fake)

    build.sign_macos_app(tmp_path / "SLAP.app")

    plain = [c for c in fake.calls
             if c[0] == "codesign" and "--force" in c and "--deep" not in c]
    assert plain, "no fallback seal was applied"
    assert "deep signing failed" in capsys.readouterr().out
    # And the gate still ran: an unsealed bundle must not get through.
    assert any(c[:3] == ["codesign", "--verify", "--strict"]
               for c in fake.calls)


def test_a_broken_outer_seal_fails_the_build(on_macos, monkeypatch, tmp_path):
    """The seal is what decides whether the .app opens at all. Shipping an
    unopenable bundle wastes far more of someone's day than a red CI step,
    and the message has to name the layout that causes it: nothing about
    "code object is not signed at all" points at Contents/MacOS."""
    fake = FakeRun(fail_containing="--verify --strict")
    # Only subprocess.run is faked: build.run() itself is the code under
    # test as much as anything else here, since it is what adds check=True
    # and therefore what turns a failed codesign into a failed build.
    monkeypatch.setattr(build.subprocess, "run", fake)

    with pytest.raises(SystemExit) as raised:
        build.sign_macos_app(tmp_path / "SLAP.app")
    message = str(raised.value)
    assert "damaged" in message
    assert "Contents/Resources" in message


def test_a_nested_quibble_is_reported_not_fatal(on_macos, monkeypatch,
                                                tmp_path, capsys):
    """Chromium's own framework failing a strict nested check does not stop
    SLAP launching, and the check that actually proves the nested binaries
    run is `slap verify` launching them, which happens right after."""
    fake = FakeRun(fail_containing="--deep --strict")
    # Only subprocess.run is faked: build.run() itself is the code under
    # test as much as anything else here, since it is what adds check=True
    # and therefore what turns a failed codesign into a failed build.
    monkeypatch.setattr(build.subprocess, "run", fake)

    build.sign_macos_app(tmp_path / "SLAP.app")          # must not raise
    assert "nested signature check reported" in capsys.readouterr().out


# --------------------------------------------------------------------------
# Ordering: the actual bug
# --------------------------------------------------------------------------

def _main_source() -> tuple[ast.FunctionDef, list[str]]:
    path = pathlib.Path(build.__file__)
    lines = path.read_text(encoding="utf-8").splitlines()
    tree = ast.parse("\n".join(lines))
    main = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    return main, lines


def test_the_bundle_is_signed_after_everything_that_writes_into_it():
    """The bug, stated as a rule.

    PyInstaller signs the .app when it assembles it; this script then
    copied ~700MB of runtime/ and a build manifest inside Contents/MacOS.
    Every one of those files landed under a seal that was already applied,
    so the signature was invalid before the build finished, and macOS
    reported the result as "damaged and can't be opened".

    Signing therefore has to be the last thing that touches the bundle. A
    reordering, or a new post-sign write, brings the whole failure back.
    """
    main, lines = _main_source()
    calls = {
        node.func.id: node.lineno
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "sign_macos_app" in calls, "main() no longer signs the bundle"
    assert calls["sign_macos_app"] > calls["copy_runtime"], \
        "signing must follow the runtime copy or the seal is broken again"

    manifest_line = next(i + 1 for i, line in enumerate(lines)
                         if "build-manifest.json" in line and "write_text" in line)
    assert calls["sign_macos_app"] > manifest_line, \
        "the manifest is written inside the bundle; sign after it"


def test_signing_precedes_the_zip():
    """A zip made before signing ships the broken bundle regardless of what
    the build does to dist/ afterwards."""
    main, _ = _main_source()
    calls = [(node.lineno, node.func.id) for node in ast.walk(main)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    sign = next(line for line, name in calls if name == "sign_macos_app")
    zip_helper = next(line for line, name in calls
                      if name == "add_macos_first_run_files")
    assert sign < zip_helper


# --------------------------------------------------------------------------
# Getting past Gatekeeper
# --------------------------------------------------------------------------

def test_the_first_run_helper_is_executable_inside_the_zip(tmp_path):
    """Without the Unix mode bits, the "script" extracts without its
    executable bit: a double-click that does nothing, which is a worse
    first impression than the error it exists to fix."""
    archive = tmp_path / "SLAP-macos-arm64.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("SLAP.app/Contents/MacOS/SLAP", "binary")

    build.add_macos_first_run_files(archive)

    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        assert "SLAP.app/Contents/MacOS/SLAP" in names, "the app survived"
        info = zf.getinfo(build.FIRST_RUN_NAME)
        assert info.create_system == 3, "not marked Unix; the mode is ignored"
        assert (info.external_attr >> 16) & 0o111, "not executable"
        script = zf.read(build.FIRST_RUN_NAME).decode()
        readme = zf.read("READ ME FIRST (macOS).txt").decode()

    assert script.startswith("#!/bin/bash")
    assert "xattr -dr com.apple.quarantine" in script
    assert 'open "SLAP.app"' in script
    # The one instruction a user cannot guess: Finder blocks the helper too.
    assert "RIGHT CLICK" in script and "RIGHT CLICK" in readme


def test_the_helper_script_is_valid_shell_and_finds_its_own_folder(tmp_path):
    """It is launched by double-click from wherever the user unzipped, so
    it cannot assume the working directory."""
    script = tmp_path / "First run (macOS).command"
    script.write_text(build.FIRST_RUN_COMMAND, encoding="utf-8")
    subprocess.run(["bash", "-n", str(script)], check=True)
    assert 'cd "$(dirname "$0")"' in build.FIRST_RUN_COMMAND

    # Run it for real from a different directory, with no app beside it: it
    # must say so rather than silently doing nothing.
    result = subprocess.run(["bash", str(script)], cwd=tmp_path.parent,
                            capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert "SLAP.app is not in this folder" in result.stdout


def test_the_readme_explains_that_damaged_is_not_damaged():
    """The word the user will search for has to appear, next to the reason.
    "Damaged" sounds like a corrupt download and sends people to re-download
    the same zip."""
    prose = " ".join(build.FIRST_RUN_README.split())     # unwrap the lines
    assert 'is "damaged and can\'t be opened"' in prose
    assert "It is not damaged" in prose
    assert "xattr -dr com.apple.quarantine" in prose
