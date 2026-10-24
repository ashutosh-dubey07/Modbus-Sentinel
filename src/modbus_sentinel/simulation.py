"""Deterministic Modbus request samples that stay in memory."""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Sequence

from .inventory import Asset


SCENARIO_NAMES = (
    "normal_poll",
    "address_sweep",
    "write_attempt",
    "invalid_request",
)


@dataclass(frozen=True)
class SimulatedFrame:
    scenario: str
    sequence: int
    offset_ms: int
    source_asset_id: str
    destination_asset_id: str
    frame: bytes


def _integer(value: int, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _wrap_frame(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    transaction_id = _integer(transaction_id, "transaction_id", 0, 65535)
    unit_id = _integer(unit_id, "unit_id", 0, 255)
    length = len(pdu) + 1
    header = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
    return header + pdu


def build_read_request(
    transaction_id: int,
    start_address: int,
    quantity: int,
    *,
    function_code: int = 3,
    unit_id: int = 1,
) -> bytes:
    """Build a Modbus TCP read request for function code 3 or 4."""
    if function_code not in {3, 4}:
        raise ValueError("function_code must be 3 or 4")
    start_address = _integer(start_address, "start_address", 0, 65535)
    quantity = _integer(quantity, "quantity", 1, 125)
    if start_address + quantity > 65536:
        raise ValueError("requested address range must end at 65535 or below")
    pdu = struct.pack(">BHH", function_code, start_address, quantity)
    return _wrap_frame(transaction_id, unit_id, pdu)


def build_write_single_request(
    transaction_id: int,
    address: int,
    value: int,
    *,
    unit_id: int = 1,
) -> bytes:
    """Build a write request as inert sample bytes, without sending it."""
    address = _integer(address, "address", 0, 65535)
    value = _integer(value, "value", 0, 65535)
    pdu = struct.pack(">BHH", 6, address, value)
    return _wrap_frame(transaction_id, unit_id, pdu)


def _first_asset(assets: Sequence[Asset], asset_type: str) -> Asset:
    matches = sorted(
        (asset for asset in assets if asset.asset_type == asset_type),
        key=lambda asset: asset.id,
    )
    if not matches:
        raise ValueError(f"scenario needs a simulated {asset_type} asset")
    return matches[0]


def generate_scenario(name: str, assets: Sequence[Asset]) -> list[SimulatedFrame]:
    """Generate a repeatable scenario; frames are returned, never transmitted."""
    plc = _first_asset(assets, "plc")
    if name == "normal_poll":
        source = _first_asset(assets, "hmi")
        return [
            SimulatedFrame(
                name,
                1,
                0,
                source.id,
                plc.id,
                build_read_request(1, 0, 2),
            )
        ]

    if name == "address_sweep":
        source = _first_asset(assets, "engineering_workstation")
        addresses = (0, 100, 200, 300)
        return [
            SimulatedFrame(
                name,
                sequence,
                (sequence - 1) * 100,
                source.id,
                plc.id,
                build_read_request(sequence, address, 1),
            )
            for sequence, address in enumerate(addresses, start=1)
        ]

    if name == "write_attempt":
        source = _first_asset(assets, "engineering_workstation")
        return [
            SimulatedFrame(
                name,
                1,
                0,
                source.id,
                plc.id,
                build_write_single_request(1, 2, 1),
            )
        ]

    if name == "invalid_request":
        source = _first_asset(assets, "engineering_workstation")
        malformed_frame = bytearray(build_read_request(1, 0, 1))
        malformed_frame[2:4] = b"\x00\x01"  # Modbus protocol ID must be zero.
        return [
            SimulatedFrame(
                name,
                1,
                0,
                source.id,
                plc.id,
                bytes(malformed_frame),
            )
        ]

    raise ValueError(f"unknown simulation scenario: {name}")
