"""Compatibility stub for the retired live Modbus TCP client."""

from __future__ import annotations

from .config import DeviceConfig


class ModbusError(Exception):
    """Raised when a Modbus operation is unavailable or invalid."""


def read_holding_registers(device: DeviceConfig) -> list[int]:
    """Reject live-device reads in this simulation-only release."""
    del device
    raise ModbusError(
        "Live device connections are disabled; this release is simulation-only."
    )
