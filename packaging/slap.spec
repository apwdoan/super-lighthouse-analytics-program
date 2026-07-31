# PyInstaller spec for SLAP. Driven by packaging/build.py, not run directly.
#
# One-dir, not one-file. One-file unpacks ~1GB to a temp directory on every
# launch, which is slow and reliably trips Windows antivirus heuristics. The
# runtime/ folder (Node, Chromium, node_modules) is copied in afterwards by
# build.py rather than declared here; see copy_runtime() for why.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"

# Files read at runtime via `Path(__file__).parent`. They must land at the
# same relative path inside the bundle or those lookups miss.
datas = [
    (str(SRC / "slap" / "findings" / "rules.yaml"), "slap/findings"),
    (str(SRC / "slap" / "report" / "templates"), "slap/report/templates"),
    # worker.js is also shipped in runtime/node_worker/ with its
    # dependencies; this copy keeps a source-layout fallback working.
    (str(SRC / "slap" / "node_worker" / "worker.js"), "slap/node_worker"),
]

# Playwright's own files, collected EXPLICITLY rather than trusting whichever
# pyinstaller-hooks-contrib version CI happens to resolve. This is what puts
# `playwright/driver/node(.exe)` in the bundle, and that binary is the Node
# runtime the Lighthouse worker runs on. If it is ever missing, the bundle
# has no Node at all and Lighthouse is silently unavailable in a way that
# looks like a Lighthouse problem.
datas += collect_data_files("playwright")

hiddenimports = [
    # Imported lazily inside functions, so PyInstaller's static analysis
    # does not see them.
    "playwright",
    "playwright.sync_api",
    "playwright.async_api",
    "pypdf",
    "h2",
    "httpx",
    *collect_submodules("jinja2"),
]

# Qt modules SLAP does not use. WebEngine alone is ~150MB and the app opens
# reports with the system handler instead.
excludes = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick", "PySide6.QtQuick", "PySide6.QtQml",
    "PySide6.Qt3DCore", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtBluetooth",
    "PySide6.QtDesigner", "PySide6.QtTest", "PySide6.QtSql", "PySide6.QtNetwork",
    "PySide6.QtPositioning", "PySide6.QtSensors", "PySide6.QtSerialPort",
    "tkinter", "matplotlib", "numpy", "PIL", "pytest",
]

analysis = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="SLAP",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX-packed binaries are an antivirus magnet
    console=False,      # GUI app; the CLI is reachable via SLAP --cli
    icon=None,
)

collection = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SLAP",
)

if sys.platform == "darwin":
    # macOS expects a .app, and a bare folder of binaries will not open from
    # Finder. build.py knows to put runtime/ inside Contents/MacOS/, which
    # is also where `sys.executable` lives, so bundle.py resolves it with no
    # platform-specific code.
    BUNDLE(
        collection,
        name="SLAP.app",
        icon=None,
        bundle_identifier="ca.slap.app",
        info_plist={
            "NSHighResolutionCapable": True,
            # Tracks the PySide6 wheel, not our own floor. PySide6 6.11
            # ships macosx_13_0_universal2, so a bundle built against it
            # cannot run on macOS 12 regardless of what this says. Claiming
            # 12.0 only buys a launch that dies on `import PySide6`.
            "LSMinimumSystemVersion": "13.0",
            # Not a document-based app, and no reason to show in the dock
            # switcher as anything other than a normal app.
            "LSApplicationCategoryType": "public.app-category.developer-tools",
            "CFBundleShortVersionString": "0.1.0",
        },
    )
