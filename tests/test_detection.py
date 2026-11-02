from dataclasses import replace
from pathlib import Path

import pytest

from modbus_sentinel.database import database_session
from modbus_sentinel.detection import detect_run, evaluate_events, list_detections
from modbus_sentinel.event_validation import validate_simulated_frame
from modbus_sentinel.events import record_scenario, store_validated_events
from modbus_sentinel.inventory import list_assets, seed_demo_inventory
from modbus_sentinel.simulation import generate_scenario


def _database(tmp_path: Path) -> Path:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    return database_path


def test_normal_poll_does_not_create_a_finding(tmp_path: Path) -> None:
    database_path = _database(tmp_path)
    run_id, _ = record_scenario(database_path, "normal_poll", run_id="normal-1")

    assert detect_run(database_path, run_id) == []
    assert list_detections(database_path, run_id) == []


def test_address_enumeration_uses_requests_and_saves_event_evidence(
    tmp_path: Path,
) -> None:
    database_path = _database(tmp_path)
    run_id, _ = record_scenario(database_path, "address_sweep", run_id="sweep-1")
    with database_session(database_path) as connection:
        connection.execute(
            "UPDATE modbus_events SET scenario = 'unlabeled' WHERE run_id = ?",
            (run_id,),
        )

    findings = detect_run(database_path, run_id)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "modbus.address_enumeration"
    assert finding.severity == "medium"
    assert finding.source_ref == "eng-ws-01"
    assert finding.destination_ref == "plc-01"
    assert finding.details["addresses"] == [0, 100, 200, 300]
    assert finding.details["distinct_address_count"] == 4
    assert len(finding.evidence) == 4
    assert all("start address" in evidence.reason for evidence in finding.evidence)

    restored = list_detections(database_path, run_id)
    assert restored == findings
    assert detect_run(database_path, run_id) == findings
    with database_session(database_path) as connection:
        detection_count = connection.execute(
            "SELECT COUNT(*) FROM detections WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        evidence_count = connection.execute(
            """
            SELECT COUNT(*) FROM detection_evidence
            WHERE detection_id = ?
            """,
            (finding.id,),
        ).fetchone()[0]
    assert detection_count == 1
    assert evidence_count == 4


def test_write_request_creates_high_severity_finding(tmp_path: Path) -> None:
    database_path = _database(tmp_path)
    run_id, _ = record_scenario(database_path, "write_attempt", run_id="write-1")

    findings = detect_run(database_path, run_id)

    assert len(findings) == 1
    assert findings[0].rule_id == "modbus.write_request"
    assert findings[0].severity == "high"
    assert findings[0].details["addresses"] == [2]
    assert len(findings[0].evidence) == 1
    assert "value 1" in findings[0].evidence[0].reason


def test_invalid_request_creates_finding_with_validation_reason(
    tmp_path: Path,
) -> None:
    database_path = _database(tmp_path)
    assets = list_assets(database_path)
    source_frame = generate_scenario("normal_poll", assets)[0]
    invalid_frame = replace(source_frame, frame=b"\x00")
    invalid_event = validate_simulated_frame(invalid_frame, assets)
    run_id = "invalid-1"
    store_validated_events(database_path, run_id, [invalid_event])

    findings = detect_run(database_path, run_id)

    assert len(findings) == 1
    assert findings[0].rule_id == "modbus.invalid_request"
    assert findings[0].severity == "high"
    assert len(findings[0].evidence) == 1
    assert "shorter" in findings[0].evidence[0].reason


def test_detect_run_rejects_unknown_run(tmp_path: Path) -> None:
    database_path = _database(tmp_path)

    with pytest.raises(ValueError, match="no simulated events"):
        detect_run(database_path, "missing-run")


def test_detection_engine_rejects_non_simulation_events() -> None:
    event = {"run_id": "live-run", "simulation_only": 0}

    with pytest.raises(ValueError, match="simulation-only"):
        evaluate_events("live-run", [event])
