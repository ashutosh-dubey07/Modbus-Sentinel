from pathlib import Path

import pytest

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
from modbus_sentinel.verification import (
    list_containment_verifications,
    verify_containment,
)


def _containment_action(database_path: Path, *, execute: bool = True) -> str:
    seed_demo_inventory(database_path)
    run_id, _ = record_scenario(database_path, "address_sweep", run_id="verify-run")
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
    if execute:
        action = execute_containment(database_path, action.id)
    return action.id


def test_verifier_records_matching_simulated_isolation(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    action_id = _containment_action(database_path)

    result = verify_containment(database_path, action_id)

    assert result.containment_action_id == action_id
    assert result.asset_id == "eng-ws-01"
    assert result.expected_state == "isolated"
    assert result.observed_state == "isolated"
    assert result.observed_last_action_type == "containment"
    assert result.observed_last_action_id == action_id
    assert result.result == "passed"
    assert "isolated by this containment action" in result.reason
    assert result.checked_at
    assert list_containment_verifications(database_path, action_id) == [result]


def test_verifier_records_a_mismatch_without_changing_asset_state(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    action_id = _containment_action(database_path)
    with database_session(database_path) as connection:
        connection.execute(
            "UPDATE simulated_asset_state SET last_action_id = ? WHERE asset_id = ?",
            ("different-action", "eng-ws-01"),
        )

    result = verify_containment(database_path, action_id)

    assert result.result == "failed"
    assert result.observed_state == "isolated"
    assert result.observed_last_action_id == "different-action"
    assert "does not match" in result.reason
    with database_session(database_path) as connection:
        state = connection.execute(
            "SELECT state, last_action_id FROM simulated_asset_state WHERE asset_id = ?",
            ("eng-ws-01",),
        ).fetchone()
    assert tuple(state) == ("isolated", "different-action")


def test_verifier_requires_an_executed_known_action(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    action_id = _containment_action(database_path, execute=False)

    with pytest.raises(ValueError, match="must be executed"):
        verify_containment(database_path, action_id)
    with pytest.raises(ValueError, match="unknown containment action"):
        verify_containment(database_path, "missing-action")
    with pytest.raises(ValueError, match="non-empty string"):
        verify_containment(database_path, " ")

    assert list_containment_verifications(database_path) == []
