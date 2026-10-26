"""Persist parsed results from local simulation scenarios."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from .audit import append_audit_entry
from .database import database_session, initialize_database
from .event_validation import ValidatedEvent, validate_simulated_frame
from .inventory import list_assets
from .simulation import generate_scenario


def store_validated_events(
    database_path: Path, run_id: str, events: list[ValidatedEvent]
) -> list[str]:
    """Save valid and invalid requests, preserving each original byte frame."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")
    initialize_database(database_path)
    event_ids: list[str] = []

    with database_session(database_path, immediate=True) as connection:
        for event in events:
            parsed = event.parsed
            event_id = uuid4().hex
            connection.execute(
                """
                INSERT INTO modbus_events (
                    id, run_id, scenario, sequence, offset_ms,
                    source_ref, destination_ref, source_asset_id, destination_asset_id,
                    raw_frame, transaction_id, unit_id, function_code,
                    start_address, quantity, register_value, is_valid,
                    validation_errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    run_id.strip(),
                    event.frame.scenario,
                    event.frame.sequence,
                    event.frame.offset_ms,
                    event.frame.source_asset_id,
                    event.frame.destination_asset_id,
                    event.source_asset.id if event.source_asset else None,
                    event.destination_asset.id if event.destination_asset else None,
                    sqlite3.Binary(event.frame.frame),
                    parsed.transaction_id if parsed else None,
                    parsed.unit_id if parsed else None,
                    parsed.function_code if parsed else None,
                    parsed.start_address if parsed else None,
                    parsed.quantity if parsed else None,
                    parsed.register_value if parsed else None,
                    int(event.is_valid),
                    json.dumps(event.errors),
                ),
            )
            event_ids.append(event_id)
        append_audit_entry(
            connection,
            event_type="simulation.events_recorded",
            entity_type="simulation_run",
            entity_id=run_id.strip(),
            details={
                "event_count": len(event_ids),
                "valid_event_count": sum(event.is_valid for event in events),
                "invalid_event_count": sum(not event.is_valid for event in events),
            },
        )

    return event_ids


def record_scenario(
    database_path: Path, scenario: str, *, run_id: str | None = None
) -> tuple[str, list[ValidatedEvent]]:
    """Generate, validate, and store one local scenario run."""
    initialize_database(database_path)
    assets = list_assets(database_path)
    frames = generate_scenario(scenario, assets)
    events = [validate_simulated_frame(frame, assets) for frame in frames]
    actual_run_id = run_id or uuid4().hex
    store_validated_events(database_path, actual_run_id, events)
    return actual_run_id, events
