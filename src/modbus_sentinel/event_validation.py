"""Validate parsed simulated requests against the local asset inventory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .inventory import Asset
from .protocol import ModbusFrameError, ParsedRequest, parse_modbus_tcp_request
from .simulation import SimulatedFrame


@dataclass(frozen=True)
class ValidatedEvent:
    frame: SimulatedFrame
    source_asset: Asset | None
    destination_asset: Asset | None
    parsed: ParsedRequest | None
    errors: tuple[str, ...]

    @property
    def is_valid(self) -> bool:
        return self.parsed is not None and not self.errors


def validate_simulated_frame(
    frame: SimulatedFrame, assets: Sequence[Asset]
) -> ValidatedEvent:
    """Parse a sample frame and check that both endpoint IDs are known."""
    by_id = {asset.id: asset for asset in assets}
    source = by_id.get(frame.source_asset_id)
    destination = by_id.get(frame.destination_asset_id)
    errors: list[str] = []

    if not isinstance(frame.scenario, str) or not frame.scenario.strip():
        errors.append("scenario name is empty")
    if isinstance(frame.sequence, bool) or not isinstance(frame.sequence, int) or frame.sequence < 1:
        errors.append("sequence must be a positive integer")
    if isinstance(frame.offset_ms, bool) or not isinstance(frame.offset_ms, int) or frame.offset_ms < 0:
        errors.append("offset must be a non-negative integer")
    if source is None:
        errors.append(f"unknown source asset {frame.source_asset_id!r}")
    if destination is None:
        errors.append(f"unknown destination asset {frame.destination_asset_id!r}")
    if frame.source_asset_id == frame.destination_asset_id:
        errors.append("source and destination assets must be different")

    parsed: ParsedRequest | None
    try:
        parsed = parse_modbus_tcp_request(frame.frame)
    except ModbusFrameError as exc:
        parsed = None
        errors.append(str(exc))

    return ValidatedEvent(
        frame=frame,
        source_asset=source,
        destination_asset=destination,
        parsed=parsed,
        errors=tuple(errors),
    )
