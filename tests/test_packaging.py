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
import shutil
import subprocess
import sys
import zipfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "packaging"))

import build  # noqa: E402


def _has_working_bash() -> bool:
    """A POSIX bash that actually runs, not just a name on PATH.

    The Windows CI runner has a ``bash`` on PATH, but it is the WSL launcher
    stub, and with no distribution installed ``bash -c true`` exits non-zero
    with "Windows Subsystem for Linux has no installed distributions". A test
    that shells out to bash then fails for a reason that has nothing to do
    with what it is testing. The macOS first-run helper is a macOS artifact;
    its shell syntax is validated on the Unix runners, which have a real
    bash, and skipped where there is not one to trust.
    """
    bash = shutil.which("bash")
    if not bash:
        return False
    try:
        return subprocess.run([bash, "-c", "true"], capture_output=True,
                              timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_bash = pytest.mark.skipif(
    not _has_working_bash(),
    reason="no working POSIX bash (e.g. the Windows WSL stub with no distro)")


class FakeRun:
    """Records commands. Fails the ones whose text contains a marker."""

    def __init__(self, fail_containing: str | None = None,
                 fail_endswith: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail_containing = fail_containing
        # The main executable path ends in .../SLAP.app/Contents/MacOS/SLAP
        # and contains the app path as a prefix, so substring matching cannot
        # tell "sign the executable" from "seal the bundle". `fail_endswith`
        # can: the seal command's last argument is the .app itself.
        self.fail_endswith = fail_endswith

    def __call__(self, command, **kwargs):
        words = [str(c) for c in command]
        self.calls.append(words)
        joined = " ".join(words)
        failed = bool(self.fail_containing and self.fail_containing in joined)
        failed = failed or bool(self.fail_endswith
                                and joined.endswith(self.fail_endswith))
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


def test_the_main_executable_is_signed_ad_hoc(on_macos, monkeypatch, tmp_path):
    """The launch gate. On Apple Silicon the kernel refuses to exec an
    unsigned Mach-O, so ``Contents/MacOS/SLAP`` must carry a signature.
    Ad-hoc (``--sign -``) because this project has no Apple certificate, and
    ad-hoc is enough for the app to RUN; Gatekeeper is a separate problem
    the first-run helper handles."""
    fake = FakeRun()
    # Only subprocess.run is faked: build.run() itself is the code under
    # test as much as anything else here, since it is what adds check=True
    # and therefore what turns a failed codesign into a failed build.
    monkeypatch.setattr(build.subprocess, "run", fake)

    app = tmp_path / "SLAP.app"
    exe = str(app / "Contents" / "MacOS" / "SLAP")
    build.sign_macos_app(app)

    sign = next(c for c in fake.calls
                if c[0] == "codesign" and "--force" in c and c[-1] == exe)
    assert sign[sign.index("--sign") + 1] == "-"         # ad-hoc
    # Extended attributes picked up during staging make codesign refuse
    # outright ("resource fork, Finder information, or similar detritus").
    assert ["xattr", "-cr", str(app)] in fake.calls
    # A bundle seal is also attempted, best-effort, on the .app itself.
    assert any(c[0] == "codesign" and "--force" in c and c[-1] == str(app)
               for c in fake.calls)


def test_a_failed_bundle_seal_does_not_fail_the_build(on_macos, monkeypatch,
                                                      tmp_path, capsys):
    """The seal that codesign cannot produce for this layout, and that the
    app does not need. ``runtime/node_modules`` defeats codesign's bundle
    scanner; the app launches anyway (signed executable + quarantine strip),
    so a failed seal is a note, not a dead build. The first real Mac run
    died here, on a signature nothing would ever have used."""
    fake = FakeRun(fail_endswith="SLAP.app")     # only .app-targeted commands
    monkeypatch.setattr(build.subprocess, "run", fake)

    build.sign_macos_app(tmp_path / "SLAP.app")          # must not raise
    assert "bundle seal skipped" in capsys.readouterr().out


def test_a_broken_executable_signature_fails_the_build(on_macos, monkeypatch,
                                                       tmp_path):
    """The one signature that IS fatal: if the main executable will not
    sign, the app cannot start on arm64, and shipping it wastes far more of
    someone's day than a red CI step."""
    fake = FakeRun(fail_containing="--verify")   # the executable verify fails
    monkeypatch.setattr(build.subprocess, "run", fake)

    with pytest.raises(SystemExit) as raised:
        build.sign_macos_app(tmp_path / "SLAP.app")
    assert "will not launch" in str(raised.value)


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
