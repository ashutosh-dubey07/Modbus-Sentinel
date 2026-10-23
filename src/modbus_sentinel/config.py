"""TOML configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import tomllib
from typing import Any


class ConfigError(ValueError):
    """Raised when the configuration file is missing or invalid."""


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    host: str
    port: int
    unit_id: int
    start_address: int
    register_count: int
    poll_interval_seconds: float
    timeout_seconds: float


@dataclass(frozen=True)
class Threshold:
    minimum: float | None = None
    maximum: float | None = None


@dataclass(frozen=True)
class SentinelConfig:
    device: DeviceConfig
    register_names: dict[int, str]
    thresholds: dict[int, Threshold]


def _integer(value: Any, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{field} must be an integer from {low} to {high}")
    return value


def _number(value: Any, field: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0):
        qualifier = "a finite positive number" if positive else "a finite number"
        raise ConfigError(f"{field} must be {qualifier}")
    return result


def load_config(path: Path) -> SentinelConfig:
    """Load and validate the monitor configuration from a TOML file."""
    try:
        with path.open("rb") as file:
            raw = tomllib.load(file)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    device_raw = raw.get("device")
    if not isinstance(device_raw, dict):
        raise ConfigError("config must contain a [device] table")

    name = device_raw.get("name", "Modbus device")
    host = device_raw.get("host")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("device.name must be a non-empty string")
    if not isinstance(host, str) or not host.strip():
        raise ConfigError("device.host must be a non-empty string")

    port = _integer(device_raw.get("port", 502), "device.port", 1, 65535)
    unit_id = _integer(device_raw.get("unit_id", 1), "device.unit_id", 0, 255)
    start_address = _integer(
        device_raw.get("start_address", 0), "device.start_address", 0, 65535
    )
    register_count = _integer(
        device_raw.get("register_count", 1), "device.register_count", 1, 125
    )
    if start_address + register_count > 65536:
        raise ConfigError("requested register range must end at address 65535 or below")

    poll_interval = _number(
        device_raw.get("poll_interval_seconds", 2),
        "device.poll_interval_seconds",
        positive=True,
    )
    timeout = _number(
        device_raw.get("timeout_seconds", 3),
        "device.timeout_seconds",
        positive=True,
    )

    register_names: dict[int, str] = {}
    names_raw = raw.get("registers", {})
    if not isinstance(names_raw, dict):
        raise ConfigError("[registers] must be a table mapping addresses to names")
    for address_text, label in names_raw.items():
        try:
            address = _integer(int(address_text), f"registers.{address_text} address", 0, 65535)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"registers key {address_text!r} must be an address") from exc
        if not isinstance(label, str) or not label.strip():
            raise ConfigError(f"registers.{address_text} must be a non-empty string")
        if not start_address <= address < start_address + register_count:
            raise ConfigError(f"registers.{address_text} is outside the requested range")
        register_names[address] = label.strip()

    thresholds: dict[int, Threshold] = {}
    thresholds_raw = raw.get("thresholds", {})
    if not isinstance(thresholds_raw, dict):
        raise ConfigError("[thresholds] must be a table")
    for address_text, limits in thresholds_raw.items():
        try:
            address = int(address_text)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"thresholds key {address_text!r} must be an address") from exc
        _integer(address, f"thresholds.{address_text} address", 0, 65535)
        if not start_address <= address < start_address + register_count:
            raise ConfigError(f"thresholds.{address_text} is outside the requested range")
        if not isinstance(limits, dict) or not limits:
            raise ConfigError(f"thresholds.{address_text} must define min and/or max")
        unknown_keys = set(limits) - {"min", "max"}
        if unknown_keys:
            raise ConfigError(f"thresholds.{address_text} only accepts min and max")
        minimum = (
            _number(limits["min"], f"thresholds.{address_text}.min")
            if "min" in limits
            else None
        )
        maximum = (
            _number(limits["max"], f"thresholds.{address_text}.max")
            if "max" in limits
            else None
        )
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ConfigError(f"thresholds.{address_text}.min must not exceed max")
        thresholds[address] = Threshold(minimum, maximum)

    return SentinelConfig(
        device=DeviceConfig(
            name=name.strip(),
            host=host.strip(),
            port=port,
            unit_id=unit_id,
            start_address=start_address,
            register_count=register_count,
            poll_interval_seconds=poll_interval,
            timeout_seconds=timeout,
        ),
        register_names=register_names,
        thresholds=thresholds,
    )
