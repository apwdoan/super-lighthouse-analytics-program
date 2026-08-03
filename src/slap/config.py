"""Settings, resolved from defaults, a TOML file, and the environment.

Kept separate from the collectors so a front-end can build a Settings
object from a Qt preferences dialog just as easily as from a file.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .collectors.base import CollectorConfig
from .collectors.lighthouse import LighthouseConfig
from .discovery import DiscoveryConfig
from .vulndb import bundled_db_path, newer_of


def user_vulndb_path() -> Path:
    """The writable copy, in the per-user data directory."""
    return default_data_dir() / "vulndb.json"


def default_vulndb_path() -> Path:
    """Whichever vulnerability database is newer: bundled or user-refreshed.

    A bundle's copy sits inside the application directory, which may be
    read-only and is replaced wholesale on upgrade. `slap vulndb update`
    therefore writes to the user directory, and this picks the fresher of the
    two by the date each one carries. Preferring the user's copy
    unconditionally would pin a teammate to a stale refresh forever after
    they installed a newer bundle.
    """
    return newer_of(user_vulndb_path(), bundled_db_path()) or bundled_db_path()


def writable_vulndb_path() -> Path:
    """Where a refresh should be written.

    The user directory when the bundled copy is not writable, which covers a
    frozen bundle in Program Files and an .app whose signature a write would
    break. In a source checkout the package directory is writable and is the
    right place, because that copy is what gets committed.
    """
    bundled = bundled_db_path()
    try:
        bundled.parent.mkdir(parents=True, exist_ok=True)
        probe = bundled.parent / ".write-test"
        probe.touch()
        probe.unlink()
    except OSError:
        return user_vulndb_path()
    import sys

    if getattr(sys, "frozen", False):
        # Writable, but inside the bundle: the next upgrade would silently
        # discard the refresh and nobody would know why their data aged.
        return user_vulndb_path()
    return bundled


#: The directory this app used before it was renamed from SALP to SLAP.
#: Kept because the data under it is not disposable: the database holds
#: immutable run history, and `artifact` rows store absolute paths to
#: gzipped LHR blobs. Silently pointing at a fresh empty directory would
#: look exactly like "the app lost my audits".
LEGACY_DIRNAME = "salp"

DIRNAME = "slap"


def data_dir_base() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))


def legacy_db_path() -> Path:
    return data_dir_base() / LEGACY_DIRNAME / f"{LEGACY_DIRNAME}.sqlite3"


def default_data_dir() -> Path:
    """Per-user data directory. Respects LOCALAPPDATA on Windows.

    Falls back to the legacy ``salp`` directory when it holds a database
    and the new directory does not exist, so an existing install keeps its
    history across the rename with no migration step the user has to know
    about. The whole directory falls back or none of it does: splitting
    the database from the artifacts it references would leave dangling
    paths in `artifact`.

    The trigger is the legacy *database*, not merely the legacy directory.
    A stray `salp/reports/` left behind by an `-o` export is not history
    worth pinning every future run to, and the app cannot reach artifacts
    it has no database rows for anyway.

    Once the new directory exists it always wins, so nothing silently
    reverts after a fresh install has been used.
    """
    base = data_dir_base()
    current = base / DIRNAME
    if not current.exists() and legacy_db_path().is_file():
        return base / LEGACY_DIRNAME
    return current


def using_legacy_data_dir() -> bool:
    """True when we fell back to the pre-rename directory. Shown by `doctor`."""
    return default_data_dir().name == LEGACY_DIRNAME


def default_db_path() -> Path:
    """The database file, named to match whichever directory we landed in.

    The file was `salp.sqlite3` before the rename. Returning
    `<legacy dir>/slap.sqlite3` would create an empty second database
    beside the real one, which is a worse failure than an error: the app
    starts fine and simply shows no history.
    """
    directory = default_data_dir()
    if directory.name == LEGACY_DIRNAME:
        return legacy_db_path()
    return directory / f"{DIRNAME}.sqlite3"


@dataclass(slots=True)
class Settings:
    db_path: Path = field(default_factory=default_db_path)
    artifact_dir: Path = field(default_factory=lambda: default_data_dir() / "artifacts")
    report_dir: Path = field(default_factory=lambda: default_data_dir() / "reports")
    rules_path: Path | None = None
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    lighthouse: LighthouseConfig = field(default_factory=LighthouseConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    #: Where the offline vulnerability database lives. Bundled beside the
    #: package; `slap vulndb update` refreshes it.
    vulndb_path: Path = field(default_factory=default_vulndb_path)
    #: Endpoint probing. Off by default and authorised per host, never
    #: globally: a global flag gets switched on once and then silently
    #: applies to the next client, who never agreed to it.
    probe_enabled: bool = False
    probe_rate_per_second: float = 2.0
    #: Report branding. Keys: company_name, accent (hex), logo_data_uri.
    #: Deliberately a plain dict so a Qt preferences dialog and a TOML file
    #: can both populate it without a schema change.
    branding: dict[str, Any] = field(default_factory=dict)
    #: Where these settings were loaded from, and therefore where a settings
    #: page must write. Recorded by :meth:`load` whether or not the file
    #: exists yet; None on a directly-constructed Settings (tests, scratch).
    config_path: Path | None = None

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Settings":
        settings = cls()

        path = Path(config_path) if config_path else default_data_dir() / "config.toml"
        settings.config_path = path
        if path.is_file():
            raw: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
            for key in ("db_path", "artifact_dir", "report_dir", "rules_path",
                        "vulndb_path"):
                if key in raw:
                    setattr(settings, key, Path(raw[key]).expanduser())
            collector_raw = raw.get("collector", {})
            if collector_raw:
                settings.collector = replace(settings.collector, **collector_raw)
            if discovery_raw := raw.get("discovery"):
                settings.discovery = replace(settings.discovery, **discovery_raw)
            if lighthouse_raw := raw.get("lighthouse"):
                for key, value in lighthouse_raw.items():
                    if hasattr(settings.lighthouse, key):
                        if key == "form_factors" or key == "categories":
                            value = tuple(value)
                        setattr(settings.lighthouse, key, value)
            if branding_raw := raw.get("branding"):
                settings.branding = dict(branding_raw)
            # Endpoint probing. Read here because it was NOT, for as long as
            # the feature existed: `probe_enabled` was a field on this class
            # that nothing ever loaded, so `slap probe allow` closed by
            # telling people to "set probe_enabled = true in config.toml"
            # and that instruction did nothing. The whole feature -- 16
            # probes, the calibration pass, the block-page detection -- was
            # reachable only through `audit --probe`, and the tool's own
            # advice about the other route was false.
            if isinstance(raw.get("probe_enabled"), bool):
                settings.probe_enabled = raw["probe_enabled"]
            if isinstance(raw.get("probe_rate_per_second"), (int, float)):
                settings.probe_rate_per_second = float(raw["probe_rate_per_second"])

        # Environment wins, so a teammate can point at their own key without
        # editing a shared config file.
        if env_key := os.environ.get("CRUX_API_KEY"):
            settings.collector = replace(settings.collector, crux_api_key=env_key)
        # SALP_DB still works. Anyone who put it in a shell profile should
        # not have their database quietly change location because the
        # project was renamed.
        if env_db := (os.environ.get("SLAP_DB") or os.environ.get("SALP_DB")):
            settings.db_path = Path(env_db).expanduser()

        return settings

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Writing one setting back. The read side is tomllib; there is no toml
# WRITER in the standard library, and that absence shaped this function.
# --------------------------------------------------------------------------

_KEY_SHAPE = re.compile(r"^[A-Za-z0-9_\-]{10,200}$")

_SECTION = re.compile(r"^\s*\[[^\]]+\]\s*$")


def _render(value: str | bool | float) -> str:
    if isinstance(value, bool):                 # before the numeric check:
        return "true" if value else "false"     # bool IS an int in Python
    if isinstance(value, (int, float)):
        return str(value)
    return f'"{value}"'


def save_setting(key: str, value: str | bool | float | None, *,
                 section: str | None = None,
                 path: str | Path | None = None) -> Path:
    """Persist (or remove) one setting in config.toml. Returns the path.

    A surgical text edit, not a parse-and-rewrite. config.toml is user-owned:
    it may carry comments, hand-tuned lighthouse settings, and formatting the
    user chose. ``tomllib`` is read-only, and serialising the parsed dict
    back would destroy all of that to change one line. So this touches the
    one line it is about -- replace it where it exists, insert it into the
    right section where it does not, create the file when there is none --
    and leaves every other byte alone.

    ``section=None`` means a top-level key, and that case is the one with a
    trap in it: in TOML a bare key written after ``[collector]`` belongs to
    *collector*, so a top-level setting cannot simply be appended to the end
    of the file. It goes in the region above the first section header, which
    is the only place it means what it says.

    The result is parsed with tomllib BEFORE it replaces the original, and a
    result that does not parse, or does not read back as the value it was
    asked to write, raises with the original file untouched. An editor that
    can corrupt a config file is worse than no editor.
    """
    import os
    import tomllib as _tomllib

    path = Path(path) if path else default_data_dir() / "config.toml"
    original = path.read_text(encoding="utf-8") if path.is_file() else None
    lines = (original or "").splitlines()

    header = f"[{section}]" if section else None
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")

    # Walk once, tracking which section each line is in, and record both the
    # existing entry (if any) and where a new one would have to go.
    current: str | None = None
    key_line: int | None = None
    insert_at: int | None = None
    for i, line in enumerate(lines):
        if _SECTION.match(line):
            if current is None and section is None and insert_at is None:
                insert_at = i            # end of the top-level region
            current = line.strip()
            if current == header:
                insert_at = i + 1
            continue
        if current == header and pattern.match(line):
            key_line = i
    if insert_at is None:
        insert_at = len(lines)           # no sections at all, or none matched

    entry = None if value is None else f"{key} = {_render(value)}"
    if key_line is not None:
        if entry is None:
            del lines[key_line]
        else:
            lines[key_line] = entry
    elif entry is not None:
        if header is not None and header not in (line.strip() for line in lines):
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend([header, entry])
        else:
            lines.insert(insert_at, entry)
    else:
        # Removing something that is not there: nothing to do, and creating
        # an empty file to say so would be noise.
        return path

    if original is None:
        lines.insert(0, "# SLAP configuration. Read at startup; the settings "
                        "page edits it in place.")

    text = "\n".join(lines) + "\n"
    parsed = _tomllib.loads(text)          # raises before any file is touched
    scope = parsed if section is None else (parsed.get(section) or {})
    if scope.get(key) != value:
        raise ValueError("the edited config did not read back correctly; "
                         "nothing was saved")

    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_name(path.name + ".tmp")
    scratch.write_text(text, encoding="utf-8")
    os.replace(scratch, path)
    return path


def save_crux_api_key(key: str | None,
                      path: str | Path | None = None) -> Path:
    """Persist (or clear) the CrUX API key.

    The key is validated against the shape API keys actually have, because
    the failure mode of writing an arbitrary string into a quoted TOML value
    is an injection into a file the whole app reads at startup.
    """
    key = (key or "").strip() or None
    if key is not None and not _KEY_SHAPE.fullmatch(key):
        raise ValueError(
            "That does not look like an API key (letters, digits, - and _ "
            "only). Nothing was saved.")
    return save_setting("crux_api_key", key, section="collector", path=path)


def save_probe_enabled(enabled: bool, path: str | Path | None = None) -> Path:
    """Persist the global endpoint-probing switch.

    Top-level, not in a section, because that is the shape `slap probe
    allow` has been telling people to write by hand for as long as the
    feature has existed.
    """
    return save_setting("probe_enabled", bool(enabled), path=path)
