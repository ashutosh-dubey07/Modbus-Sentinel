"""Load and validate local Modbus Sentinel settings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


class ConfigError(ValueError):
    """Raised when the local settings file is missing or invalid."""


_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@dataclass(frozen=True)
class AppSettings:
    name: str
    database_path: Path
    log_level: str


def load_settings(path: Path) -> AppSettings:
    """Read settings and resolve relative database paths beside the TOML file."""
    config_path = Path(path)
    try:
        with config_path.open("rb") as file:
            raw = tomllib.load(file)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {config_path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc

    app = raw.get("app")
    if not isinstance(app, dict):
        raise ConfigError("config must contain an [app] table")
    unknown_keys = set(app) - {"name", "mode", "database_path", "log_level"}
    if unknown_keys:
        names = ", ".join(sorted(str(key) for key in unknown_keys))
        raise ConfigError(f"unknown [app] setting(s): {names}")

    name = app.get("name", "Modbus Sentinel")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("app.name must be a non-empty string")

    mode = app.get("mode", "simulation")
    if mode != "simulation":
        raise ConfigError("app.mode must be 'simulation'; live mode is not supported")

    database_text = app.get("database_path", "data/modbus_sentinel.sqlite3")
    if not isinstance(database_text, str) or not database_text.strip():
        raise ConfigError("app.database_path must be a non-empty path")
    database_path = Path(database_text).expanduser()
    if not database_path.is_absolute():
        database_path = config_path.parent / database_path

    log_level = app.get("log_level", "INFO")
    if not isinstance(log_level, str) or log_level.upper() not in _LOG_LEVELS:
        allowed = ", ".join(sorted(_LOG_LEVELS))
        raise ConfigError(f"app.log_level must be one of: {allowed}")

    return AppSettings(
        name=name.strip(),
        database_path=database_path.resolve(),
        log_level=log_level.upper(),
    )
