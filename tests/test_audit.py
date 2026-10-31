from pathlib import Path
import sqlite3

import pytest

from modbus_sentinel.audit import list_audit_entries, verify_audit_chain
from modbus_sentinel.containment import (
    decide_containment,
    execute_containment,
    request_containment,
)
from modbus_sentinel.database import database_session
from modbus_sentinel.detection import detect_run
from modbus_sentinel.events import record_scenario
from modbus_sentinel.incidents import acknowledge_incident, create_incidents_for_run
from modbus_sentinel.inventory import seed_demo_inventory
from modbus_sentinel.verification import verify_containment


def _record_containment_workflow(database_path: Path) -> None:
    seed_demo_inventory(database_path)
    run_id, _ = record_scenario(database_path, "address_sweep", run_id="audit-run")
    detect_run(database_path, run_id)
    incident = create_incidents_for_run(database_path, run_id)[0]
    acknowledge_incident(
        database_path,
        incident.id,
        actor_id="operator-1",
        actor_role="operator",
    )
    action = request_containment(
        database_path,
        incident.id,
        "eng-ws-01",
        actor_id="operator-1",
        actor_role="operator",
    )
    action = decide_containment(
        database_path,
        action.id,
        "approve",
        actor_id="admin-1",
        actor_role="admin",
    )
    action = execute_containment(database_path, action.id)
    verify_containment(database_path, action.id)


def test_audit_chain_records_workflow_and_verifies_hash_links(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    _record_containment_workflow(database_path)

    entries = list_audit_entries(database_path)
    result = verify_audit_chain(database_path)

    assert result.valid
    assert result.entries_checked == len(entries)
    assert result.last_sequence == len(entries)
    assert result.head_hash == entries[-1].entry_hash
    assert entries[0].previous_hash == "0" * 64
    assert [entry.sequence for entry in entries] == list(
        range(1, len(entries) + 1)
    )
    assert all(
        entry.previous_hash == entries[index - 1].entry_hash
        for index, entry in enumerate(entries)
        if index > 0
    )
    assert {
        "simulation.events_recorded",
        "detection.run_evaluated",
        "incident.created",
        "incident.acknowledged",
        "containment.requested",
        "containment.approved",
        "containment.executed",
        "containment.verification_recorded",
    } <= {entry.event_type for entry in entries}


def test_empty_audit_chain_is_valid(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)

    result = verify_audit_chain(database_path)

    assert result.valid
    assert result.entries_checked == 0
    assert result.last_sequence == 0
    assert result.head_hash == "0" * 64


def test_audit_entries_cannot_be_updated_or_deleted(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    record_scenario(database_path, "normal_poll", run_id="append-only-run")

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with database_session(database_path, immediate=True) as connection:
            connection.execute("UPDATE audit_log SET event_type = 'changed'")

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with database_session(database_path, immediate=True) as connection:
            connection.execute("DELETE FROM audit_log")


def test_chain_verifier_detects_changed_entry_content(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    record_scenario(database_path, "normal_poll", run_id="tamper-run")
    with database_session(database_path, immediate=True) as connection:
        connection.execute("DROP TRIGGER audit_log_no_update")
        connection.execute("UPDATE audit_log SET details_json = '{}' WHERE sequence = 1")

    result = verify_audit_chain(database_path)

    assert not result.valid
    assert result.issue_sequence == 1
    assert "content hash" in result.reason
