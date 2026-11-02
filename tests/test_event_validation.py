from dataclasses import replace
from pathlib import Path

from modbus_sentinel.event_validation import validate_simulated_frame
from modbus_sentinel.inventory import list_assets, seed_demo_inventory
from modbus_sentinel.simulation import generate_scenario


def test_valid_simulated_frame_resolves_both_assets(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    assets = list_assets(database_path)
    frame = generate_scenario("normal_poll", assets)[0]

    event = validate_simulated_frame(frame, assets)

    assert event.is_valid
    assert event.source_asset is not None and event.source_asset.id == "hmi-01"
    assert event.destination_asset is not None and event.destination_asset.id == "plc-01"
    assert event.parsed is not None and event.parsed.function_code == 3


def test_unknown_asset_is_retained_as_validation_error(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    assets = list_assets(database_path)
    frame = replace(
        generate_scenario("normal_poll", assets)[0], source_asset_id="unknown-node"
    )

    event = validate_simulated_frame(frame, assets)

    assert not event.is_valid
    assert event.source_asset is None
    assert "unknown source asset 'unknown-node'" in event.errors


def test_malformed_request_is_retained_with_parser_error(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    assets = list_assets(database_path)
    frame = replace(generate_scenario("normal_poll", assets)[0], frame=b"\x00")

    event = validate_simulated_frame(frame, assets)

    assert not event.is_valid
    assert event.parsed is None
    assert any("shorter" in error for error in event.errors)


def test_invalid_request_scenario_is_rejected_by_parser(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    assets = list_assets(database_path)
    frame = generate_scenario("invalid_request", assets)[0]

    event = validate_simulated_frame(frame, assets)

    assert not event.is_valid
    assert event.parsed is None
    assert any("protocol ID must be 0" in error for error in event.errors)
