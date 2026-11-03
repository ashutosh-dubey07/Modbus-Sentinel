from pathlib import Path

import pytest

from modbus_sentinel.containment import (
    decide_containment,
    execute_containment,
    get_simulated_asset_state,
    request_containment,
)
from modbus_sentinel.detection import detect_run
from modbus_sentinel.events import record_scenario
from modbus_sentinel.incidents import (
    acknowledge_incident,
    close_incident,
    create_incidents_for_run,
    list_admin_notifications,
    mark_notification_read,
)
from modbus_sentinel.inventory import seed_demo_inventory


def _open_acknowledged_incident(
    tmp_path: Path, scenario: str = "address_sweep"
) -> tuple[Path, str]:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    run_id, _ = record_scenario(database_path, scenario, run_id=f"{scenario}-run")
    detect_run(database_path, run_id)
    incident = create_incidents_for_run(database_path, run_id)[0]
    acknowledge_incident(
        database_path,
        incident.id,
        actor_id="operator-1",
        actor_role="operator",
    )
    return database_path, incident.id


def test_isolation_requires_request_and_separate_admin_approval(
    tmp_path: Path,
) -> None:
    database_path, incident_id = _open_acknowledged_incident(tmp_path)
    before = get_simulated_asset_state(database_path, "eng-ws-01")
    assert before.state == "connected"

    action = request_containment(
        database_path,
        incident_id,
        "eng-ws-01",
        actor_id="operator-1",
        actor_role="operator",
    )
    assert action.status == "pending_approval"
    assert get_simulated_asset_state(database_path, "eng-ws-01").state == "connected"
    inbox_item = next(
        item
        for item in list_admin_notifications(database_path, unread_only=True)
        if item.containment_action_id == action.id
    )
    assert inbox_item.kind == "containment_approval_requested"
    assert inbox_item.channel == "in_app"
    assert inbox_item.status == "unread"
    assert inbox_item.incident_id is None
    with pytest.raises(ValueError, match="decide or execute pending containment"):
        close_incident(
            database_path,
            incident_id,
            actor_id="admin-1",
            actor_role="admin",
        )
    read_item = mark_notification_read(
        database_path,
        inbox_item.id,
        actor_id="admin-1",
        actor_role="admin",
    )
    assert read_item.status == "read"

    with pytest.raises(PermissionError, match="cannot approve their own"):
        decide_containment(
            database_path,
            action.id,
            "approve",
            actor_id="operator-1",
            actor_role="admin",
        )

    approved = decide_containment(
        database_path,
        action.id,
        "approve",
        actor_id="admin-1",
        actor_role="admin",
    )
    assert approved.status == "approved"
    assert approved.decided_by == "admin-1"
    assert get_simulated_asset_state(database_path, "eng-ws-01").state == "connected"

    executed = execute_containment(database_path, action.id)
    state = get_simulated_asset_state(database_path, "eng-ws-01")
    assert executed.status == "executed"
    assert executed.executed_at is not None
    assert state.state == "isolated"
    assert state.last_action_type == "containment"
    assert state.last_action_id == action.id
    assert state.changed_at is not None

    with pytest.raises(ValueError, match="already isolated"):
        request_containment(
            database_path,
            incident_id,
            "eng-ws-01",
            actor_id="operator-1",
            actor_role="operator",
        )


def test_rejected_request_cannot_change_simulated_asset_state(
    tmp_path: Path,
) -> None:
    database_path, incident_id = _open_acknowledged_incident(
        tmp_path, "write_attempt"
    )
    action = request_containment(
        database_path,
        incident_id,
        "eng-ws-01",
        actor_id="operator-1",
        actor_role="operator",
    )

    rejected = decide_containment(
        database_path,
        action.id,
        "reject",
        actor_id="admin-1",
        actor_role="admin",
    )

    assert rejected.status == "rejected"
    with pytest.raises(ValueError, match="only approved"):
        execute_containment(database_path, action.id)
    assert get_simulated_asset_state(database_path, "eng-ws-01").state == "connected"


def test_containment_checks_role_incident_and_simulated_asset(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    seed_demo_inventory(database_path)
    run_id, _ = record_scenario(database_path, "address_sweep", run_id="open-run")
    detect_run(database_path, run_id)
    incident = create_incidents_for_run(database_path, run_id)[0]

    with pytest.raises(ValueError, match="must be acknowledged"):
        request_containment(
            database_path,
            incident.id,
            "eng-ws-01",
            actor_id="operator-1",
            actor_role="operator",
        )
    with pytest.raises(PermissionError, match="cannot perform request_containment"):
        request_containment(
            database_path,
            incident.id,
            "eng-ws-01",
            actor_id="viewer-1",
            actor_role="viewer",
        )

    acknowledged = acknowledge_incident(
        database_path,
        incident.id,
        actor_id="operator-1",
        actor_role="operator",
    )
    assert acknowledged.status == "acknowledged"
    with pytest.raises(ValueError, match="unknown simulated asset"):
        request_containment(
            database_path,
            incident.id,
            "physical-plc",
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
    with pytest.raises(PermissionError, match="cannot perform decide_containment"):
        decide_containment(
            database_path,
            action.id,
            "approve",
            actor_id="operator-2",
            actor_role="operator",
        )
