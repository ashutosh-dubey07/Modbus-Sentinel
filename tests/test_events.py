import json
from pathlib import Path

from modbus_sentinel.database import database_session
from modbus_sentinel.event_validation import validate_simulated_frame
from modbus_sentinel.events import record_scenario, store_validated_events
from modbus_sentinel.inventory import list_assets, seed_demo_inventory
from modbus_sentinel.simulation import generate_scenario


def test_record_scenario_persists_valid_frames(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)

    run_id, events = record_scenario(database_path, "address_sweep", run_id="run-1")

    assert run_id == "run-1"
    assert len(events) == 4
    assert all(event.is_valid for event in events)
    with database_session(database_path) as connection:
        rows = connection.execute(
            """
            SELECT scenario, source_ref, destination_ref, function_code,
                   is_valid, raw_frame
            FROM modbus_events WHERE run_id = ? ORDER BY sequence
            """,
            (run_id,),
        ).fetchall()
    assert len(rows) == 4
    assert all(row["scenario"] == "address_sweep" for row in rows)
    assert all(row["source_ref"] == "eng-ws-01" for row in rows)
    assert all(row["destination_ref"] == "plc-01" for row in rows)
    assert all(row["function_code"] == 3 and row["is_valid"] == 1 for row in rows)
    assert all(bytes(row["raw_frame"]) for row in rows)


def test_invalid_frame_is_stored_with_original_bytes_and_errors(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    assets = list_assets(database_path)
    frame = generate_scenario("normal_poll", assets)[0]
    frame = frame.__class__(
        scenario="malformed_sample",
        sequence=1,
        offset_ms=0,
        source_asset_id="missing-asset",
        destination_asset_id=frame.destination_asset_id,
        frame=b"\x00",
    )
    event = validate_simulated_frame(frame, assets)

    store_validated_events(database_path, "bad-run", [event])

    with database_session(database_path) as connection:
        row = connection.execute(
            """
            SELECT source_ref, source_asset_id, raw_frame, is_valid, validation_errors
            FROM modbus_events WHERE run_id = ?
            """,
            ("bad-run",),
        ).fetchone()
    assert row["source_ref"] == "missing-asset"
    assert row["source_asset_id"] is None
    assert bytes(row["raw_frame"]) == b"\x00"
    assert row["is_valid"] == 0
    errors = json.loads(row["validation_errors"])
    assert any("unknown source asset" in error for error in errors)
    assert any("shorter" in error for error in errors)
