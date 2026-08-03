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


needs_bash = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the Windows runner's `bash` on PATH is the WSL launcher stub, and "
           "with no distribution installed `bash -n script` exits non-zero "
           "for a reason that has nothing to do with the script. Probing the "
           "stub does not help: `bash -c true` exits ZERO on it, so a probe "
           "reports a working bash and the test runs anyway. The macOS "
           "first-run helper is a macOS artifact; its shell syntax is "
           "validated on the Unix runners, which have a real bash.")


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


def test_the_build_does_not_re_sign_the_bundle(on_macos, monkeypatch, tmp_path):
    """The launch gate is already in place, and re-signing would break it.

    PyInstaller signs ``Contents/MacOS/SLAP`` when it assembles the .app,
    before the build copies ``runtime/`` in beside it; that copy does not
    touch the executable's Mach-O, so the signature the arm64 kernel checks
    survives. Re-signing is not a safe belt-and-braces: pointed at a bundle's
    main executable codesign walks ``Contents/`` into the bundled
    ``node_modules`` and fails, and ``--force`` replaces the good signature
    before it does. Both earlier CI runs on a real Mac died on exactly that
    call. So the build must NOT invoke a signing codesign at all."""
    fake = FakeRun()
    monkeypatch.setattr(build.subprocess, "run", fake)

    app = tmp_path / "SLAP.app"
    build.sign_macos_app(app)

    assert not any(c and c[0] == "codesign" for c in fake.calls), \
        "re-signing walks the bundled runtime and breaks PyInstaller's signature"
    # The one thing it does do: clear the extended attributes staging leaves
    # behind ("resource fork, Finder information, or similar detritus"), which
    # lives in xattrs, not in the Mach-O, so clearing it spares the signature.
    assert ["xattr", "-cr", str(app)] in fake.calls


def test_finalising_the_bundle_never_fails_the_build(on_macos, monkeypatch,
                                                     tmp_path):
    """Nothing this step does is allowed to fail the build. The signature
    that matters is already present and this step cannot improve on it, so
    even if clearing attributes reports trouble the build carries on. The
    launch gate is enforced later, by ``slap verify`` running the bundle."""
    fake = FakeRun(fail_containing="xattr")      # the attribute clear "fails"
    monkeypatch.setattr(build.subprocess, "run", fake)

    build.sign_macos_app(tmp_path / "SLAP.app")          # must not raise
    # And it did so without ever handing codesign the bundle to walk.
    assert not any(c and c[0] == "codesign" for c in fake.calls)


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


def test_the_bundle_is_finalised_after_everything_that_writes_into_it():
    """The original bug, stated as a rule that outlives its first cause.

    PyInstaller signs the .app when it assembles it; this script then copied
    ~700MB of runtime/ and a build manifest inside Contents/MacOS. Every one
    of those files landed under a seal already applied, so the signature was
    invalid before the build finished and macOS called the result "damaged".
    The fix stopped re-sealing, but the ordering invariant it exposed still
    holds: ``sign_macos_app`` now clears the quarantine and Finder attributes
    off the bundle, and doing that BEFORE the runtime copy would leave the
    copied files' attributes in the shipped app. Anything that reintroduces a
    seal, too, would have to come after every write. So this step stays last.
    """
    main, lines = _main_source()
    calls = {
        node.func.id: node.lineno
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "sign_macos_app" in calls, "main() no longer finalises the bundle"
    assert calls["sign_macos_app"] > calls["copy_runtime"], \
        "finalising must follow the runtime copy or its files keep their xattrs"

    manifest_line = next(i + 1 for i, line in enumerate(lines)
                         if "build-manifest.json" in line and "write_text" in line)
    assert calls["sign_macos_app"] > manifest_line, \
        "the manifest is written inside the bundle; finalise after it"


def test_finalising_precedes_the_zip():
    """A zip made before the bundle is finalised ships attributes the build
    meant to strip, regardless of what it does to dist/ afterwards."""
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


@needs_bash
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
