"""Settings, resolved from defaults, a TOML file, and the environment.

Kept separate from the collectors so a front-end can build a Settings
object from a Qt preferences dialog just as easily as from a file.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .collectors.base import CollectorConfig
from .collectors.lighthouse import LighthouseConfig


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
    #: Report branding. Keys: company_name, accent (hex), logo_data_uri.
    #: Deliberately a plain dict so a Qt preferences dialog and a TOML file
    #: can both populate it without a schema change.
    branding: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Settings":
        settings = cls()

        path = Path(config_path) if config_path else default_data_dir() / "config.toml"
        if path.is_file():
            raw: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
            for key in ("db_path", "artifact_dir", "report_dir", "rules_path"):
                if key in raw:
                    setattr(settings, key, Path(raw[key]).expanduser())
            collector_raw = raw.get("collector", {})
            if collector_raw:
                settings.collector = replace(settings.collector, **collector_raw)
            if lighthouse_raw := raw.get("lighthouse"):
                for key, value in lighthouse_raw.items():
                    if hasattr(settings.lighthouse, key):
                        if key == "form_factors" or key == "categories":
                            value = tuple(value)
                        setattr(settings.lighthouse, key, value)
            if branding_raw := raw.get("branding"):
                settings.branding = dict(branding_raw)

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
