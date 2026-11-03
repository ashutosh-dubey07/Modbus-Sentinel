from pathlib import Path

import pytest

from modbus_sentinel.detection import detect_run
from modbus_sentinel.events import record_scenario
from modbus_sentinel.incidents import (
    acknowledge_incident,
    close_incident,
    create_incidents_for_run,
    list_admin_notifications,
    list_incidents,
    mark_notification_read,
)
from modbus_sentinel.inventory import seed_demo_inventory


def _database_with_run(tmp_path: Path, scenario: str) -> tuple[Path, str]:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    run_id, _ = record_scenario(database_path, scenario, run_id=f"{scenario}-run")
    detect_run(database_path, run_id)
    return database_path, run_id


def test_incident_and_admin_notification_are_created_once(tmp_path: Path) -> None:
    database_path, run_id = _database_with_run(tmp_path, "address_sweep")

    first = create_incidents_for_run(database_path, run_id)
    second = create_incidents_for_run(database_path, run_id)
    unread = list_admin_notifications(database_path, unread_only=True)

    assert first == second
    assert len(first) == 1
    assert first[0].status == "open"
    assert first[0].rule_id == "modbus.address_enumeration"
    assert first[0].severity == "medium"
    assert len(unread) == 1
    assert unread[0].incident_id == first[0].id
    assert unread[0].recipient_role == "admin"
    assert unread[0].channel == "in_app"
    assert unread[0].kind == "incident_opened"
    assert list_incidents(database_path, run_id) == first


def test_incident_requires_operator_ack_then_admin_close(tmp_path: Path) -> None:
    database_path, run_id = _database_with_run(tmp_path, "write_attempt")
    incident = create_incidents_for_run(database_path, run_id)[0]

    with pytest.raises(PermissionError, match="cannot perform close_incident"):
        close_incident(
            database_path,
            incident.id,
            actor_id="operator-1",
            actor_role="operator",
        )
    with pytest.raises(PermissionError, match="cannot perform acknowledge_incident"):
        acknowledge_incident(
            database_path,
            incident.id,
            actor_id="viewer-1",
            actor_role="viewer",
        )
    with pytest.raises(ValueError, match="only acknowledged"):
        close_incident(
            database_path,
            incident.id,
            actor_id="admin-1",
            actor_role="admin",
        )

    acknowledged = acknowledge_incident(
        database_path,
        incident.id,
        actor_id="operator-1",
        actor_role="operator",
    )
    assert acknowledged.status == "acknowledged"
    assert acknowledged.acknowledged_by == "operator-1"
    assert acknowledged.acknowledged_role == "operator"
    assert acknowledged.acknowledged_at is not None

    closed = close_incident(
        database_path,
        incident.id,
        actor_id="admin-1",
        actor_role="admin",
    )
    assert closed.status == "closed"
    assert closed.closed_by == "admin-1"
    assert closed.closed_role == "admin"
    assert closed.closed_at is not None
    with pytest.raises(ValueError, match="only open"):
        acknowledge_incident(
            database_path,
            incident.id,
            actor_id="admin-1",
            actor_role="admin",
        )


def test_only_admin_can_mark_admin_notification_read(tmp_path: Path) -> None:
    database_path, run_id = _database_with_run(tmp_path, "write_attempt")
    create_incidents_for_run(database_path, run_id)
    notification = list_admin_notifications(database_path)[0]

    with pytest.raises(PermissionError, match="cannot perform read_admin_notification"):
        mark_notification_read(
            database_path,
            notification.id,
            actor_id="operator-1",
            actor_role="operator",
        )

    read = mark_notification_read(
        database_path,
        notification.id,
        actor_id="admin-1",
        actor_role="admin",
    )

    assert read.status == "read"
    assert read.read_by == "admin-1"
    assert read.read_at is not None
    assert list_admin_notifications(database_path, unread_only=True) == []


def test_run_without_findings_does_not_create_incident_or_notification(
    tmp_path: Path,
) -> None:
    database_path, run_id = _database_with_run(tmp_path, "normal_poll")

    assert create_incidents_for_run(database_path, run_id) == []
    assert list_incidents(database_path, run_id) == []
    assert list_admin_notifications(database_path) == []
