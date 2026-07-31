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


def default_data_dir() -> Path:
    """Per-user data directory. Respects LOCALAPPDATA on Windows."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "salp"


@dataclass(slots=True)
class Settings:
    db_path: Path = field(default_factory=lambda: default_data_dir() / "salp.sqlite3")
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
        if env_db := os.environ.get("SALP_DB"):
            settings.db_path = Path(env_db).expanduser()

        return settings

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
