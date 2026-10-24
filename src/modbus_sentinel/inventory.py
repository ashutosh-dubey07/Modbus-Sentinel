"""Local inventory for simulated industrial assets and network segments."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3

from .database import database_session, initialize_database


VALID_ZONES = {"enterprise", "operations", "control", "safety"}
VALID_ASSET_TYPES = {
    "plc",
    "hmi",
    "engineering_workstation",
    "historian",
    "sensor",
    "gateway",
}
VALID_CRITICALITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class NetworkSegment:
    id: str
    name: str
    zone: str
    description: str = ""


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    asset_type: str
    segment_id: str
    node_ref: str
    criticality: str


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def add_segment(database_path: Path, segment: NetworkSegment) -> None:
    """Add a simulated network segment."""
    segment_id = _text(segment.id, "segment.id")
    name = _text(segment.name, "segment.name")
    zone = _text(segment.zone, "segment.zone")
    description = segment.description
    if not isinstance(description, str):
        raise ValueError("segment.description must be a string")
    if zone not in VALID_ZONES:
        raise ValueError(f"segment.zone must be one of: {', '.join(sorted(VALID_ZONES))}")

    with database_session(database_path) as connection:
        connection.execute(
            "INSERT INTO network_segments (id, name, zone, description) VALUES (?, ?, ?, ?)",
            (segment_id, name, zone, description.strip()),
        )


def add_asset(database_path: Path, asset: Asset) -> None:
    """Add an asset inside an existing simulated network segment."""
    values = (
        _text(asset.id, "asset.id"),
        _text(asset.name, "asset.name"),
        _text(asset.asset_type, "asset.asset_type"),
        _text(asset.segment_id, "asset.segment_id"),
        _text(asset.node_ref, "asset.node_ref"),
        _text(asset.criticality, "asset.criticality"),
    )
    if values[2] not in VALID_ASSET_TYPES:
        raise ValueError(f"asset.asset_type must be one of: {', '.join(sorted(VALID_ASSET_TYPES))}")
    if values[5] not in VALID_CRITICALITIES:
        raise ValueError(
            f"asset.criticality must be one of: {', '.join(sorted(VALID_CRITICALITIES))}"
        )

    with database_session(database_path) as connection:
        connection.execute(
            """
            INSERT INTO assets (id, name, asset_type, segment_id, node_ref, criticality)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            values,
        )


def list_segments(database_path: Path) -> list[NetworkSegment]:
    """Return simulated network segments in a stable order."""
    with database_session(database_path) as connection:
        rows = connection.execute(
            "SELECT id, name, zone, description FROM network_segments ORDER BY id"
        ).fetchall()
    return [NetworkSegment(**dict(row)) for row in rows]


def list_assets(database_path: Path, segment_id: str | None = None) -> list[Asset]:
    """Return simulated assets, optionally limited to one segment."""
    with database_session(database_path) as connection:
        if segment_id is None:
            rows = connection.execute(
                """
                SELECT id, name, asset_type, segment_id, node_ref, criticality
                FROM assets ORDER BY id
                """
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT id, name, asset_type, segment_id, node_ref, criticality
                FROM assets WHERE segment_id = ? ORDER BY id
                """,
                (segment_id,),
            ).fetchall()
    return [Asset(**dict(row)) for row in rows]


def seed_demo_inventory(database_path: Path) -> None:
    """Create a small fictional plant layout once, without overwriting edits."""
    initialize_database(database_path)
    segments = (
        NetworkSegment("enterprise", "Enterprise", "enterprise", "Business systems"),
        NetworkSegment("operations", "Operations", "operations", "Plant operations"),
        NetworkSegment("cell-a", "Cell A", "control", "Fictional control cell"),
    )
    assets = (
        Asset("eng-ws-01", "Engineering workstation", "engineering_workstation", "operations", "SIM-ENG-01", "high"),
        Asset("hist-01", "Historian", "historian", "operations", "SIM-HIST-01", "medium"),
        Asset("hmi-01", "Operator HMI", "hmi", "cell-a", "SIM-HMI-01", "high"),
        Asset("plc-01", "Process PLC", "plc", "cell-a", "SIM-PLC-01", "critical"),
        Asset("sensor-01", "Process sensor", "sensor", "cell-a", "SIM-SENSOR-01", "high"),
    )

    with database_session(database_path) as connection:
        for segment in segments:
            connection.execute(
                """
                INSERT OR IGNORE INTO network_segments (id, name, zone, description)
                VALUES (?, ?, ?, ?)
                """,
                (segment.id, segment.name, segment.zone, segment.description),
            )
        for asset in assets:
            connection.execute(
                """
                INSERT OR IGNORE INTO assets
                    (id, name, asset_type, segment_id, node_ref, criticality)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    asset.id,
                    asset.name,
                    asset.asset_type,
                    asset.segment_id,
                    asset.node_ref,
                    asset.criticality,
                ),
            )
