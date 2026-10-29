"""Approval-gated containment that changes only local simulated state."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from uuid import NAMESPACE_URL, uuid4, uuid5

from .audit import append_audit_entry
from .database import database_session, initialize_database
from .incidents import authorize_demo_action


@dataclass(frozen=True)
class ContainmentAction:
    id: str
    incident_id: str
    asset_id: str
    action_type: str
    status: str
    requested_by: str
    requested_role: str
    requested_at: str
    decided_by: str | None
    decided_role: str | None
    decision_at: str | None
    executed_at: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class SimulatedAssetState:
    asset_id: str
    state: str
    last_action_type: str | None
    last_action_id: str | None
    changed_at: str | None


def _required_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _action_from_row(row: sqlite3.Row) -> ContainmentAction:
    return ContainmentAction(
        id=row["id"],
        incident_id=row["incident_id"],
        asset_id=row["asset_id"],
        action_type=row["action_type"],
        status=row["status"],
        requested_by=row["requested_by"],
        requested_role=row["requested_role"],
        requested_at=row["requested_at"],
        decided_by=row["decided_by"],
        decided_role=row["decided_role"],
        decision_at=row["decision_at"],
        executed_at=row["executed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def request_containment(
    database_path: Path,
    incident_id: str,
    asset_id: str,
    *,
    actor_id: str,
    actor_role: str,
) -> ContainmentAction:
    """Request simulated isolation of an inventory asset for an acknowledged incident."""
    role = authorize_demo_action(actor_role, "request_containment")
    incident_key = _required_text(incident_id, "incident_id")
    asset_key = _required_text(asset_id, "asset_id")
    actor = _required_text(actor_id, "actor_id")
    initialize_database(database_path)

    action_id = uuid4().hex
    with database_session(database_path, immediate=True) as connection:
        incident = connection.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_key,)
        ).fetchone()
        if incident is None:
            raise ValueError(f"unknown incident: {incident_key}")
        if incident["status"] != "acknowledged":
            raise ValueError("incident must be acknowledged before containment is requested")

        asset = connection.execute(
            "SELECT simulation_only FROM assets WHERE id = ?", (asset_key,)
        ).fetchone()
        if asset is None or asset["simulation_only"] != 1:
            raise ValueError(f"unknown simulated asset: {asset_key}")

        state = connection.execute(
            "SELECT state FROM simulated_asset_state WHERE asset_id = ?",
            (asset_key,),
        ).fetchone()
        if state is not None and state["state"] == "isolated":
            raise ValueError(f"simulated asset {asset_key!r} is already isolated")

        pending = connection.execute(
            """
            SELECT id FROM containment_actions
            WHERE incident_id = ? AND asset_id = ?
              AND action_type = 'isolate_asset'
              AND status IN ('pending_approval', 'approved')
            """,
            (incident_key, asset_key),
        ).fetchone()
        if pending is not None:
            raise ValueError("an isolation request is already pending for this incident and asset")

        connection.execute(
            """
            INSERT INTO containment_actions (
                id, incident_id, asset_id, action_type, status,
                requested_by, requested_role
            ) VALUES (?, ?, ?, 'isolate_asset', 'pending_approval', ?, ?)
            """,
            (action_id, incident_key, asset_key, actor, role),
        )
        notification_id = uuid5(
            NAMESPACE_URL,
            f"modbus-sentinel:containment-notification:{action_id}",
        ).hex
        connection.execute(
            """
            INSERT INTO containment_approval_notifications (
                id, containment_action_id, recipient_role, channel, kind, message
            ) VALUES (?, ?, 'admin', 'in_app',
                      'containment_approval_requested', ?)
            """,
            (
                notification_id,
                action_id,
                f"Containment approval requested for simulated asset {asset_key}.",
            ),
        )
        append_audit_entry(
            connection,
            event_type="containment.requested",
            entity_type="containment_action",
            entity_id=action_id,
            actor_id=actor,
            actor_role=role,
            details={
                "action_type": "isolate_asset",
                "asset_id": asset_key,
                "incident_id": incident_key,
                "status": "pending_approval",
            },
        )
    return get_containment_action(database_path, action_id)


def get_containment_action(
    database_path: Path, action_id: str
) -> ContainmentAction:
    """Return a stored simulated containment action."""
    action_key = _required_text(action_id, "action_id")
    initialize_database(database_path)
    with database_session(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM containment_actions WHERE id = ?", (action_key,)
        ).fetchone()
    if row is None:
        raise ValueError(f"unknown containment action: {action_key}")
    return _action_from_row(row)


def list_containment_actions(
    database_path: Path, incident_id: str | None = None
) -> list[ContainmentAction]:
    """List simulated containment actions, optionally for one incident."""
    initialize_database(database_path)
    query = "SELECT * FROM containment_actions"
    parameters: tuple[str, ...] = ()
    if incident_id is not None:
        query += " WHERE incident_id = ?"
        parameters = (_required_text(incident_id, "incident_id"),)
    query += " ORDER BY created_at, id"
    with database_session(database_path) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_action_from_row(row) for row in rows]


def decide_containment(
    database_path: Path,
    action_id: str,
    decision: str,
    *,
    actor_id: str,
    actor_role: str,
) -> ContainmentAction:
    """Approve or reject a pending request as a different demo administrator."""
    role = authorize_demo_action(actor_role, "decide_containment")
    action_key = _required_text(action_id, "action_id")
    actor = _required_text(actor_id, "actor_id")
    normalized_decision = _required_text(decision, "decision").lower()
    if normalized_decision not in {"approve", "reject"}:
        raise ValueError("decision must be 'approve' or 'reject'")
    initialize_database(database_path)

    with database_session(database_path, immediate=True) as connection:
        row = connection.execute(
            """
            SELECT status, requested_by, incident_id, asset_id
            FROM containment_actions WHERE id = ?
            """,
            (action_key,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown containment action: {action_key}")
        if row["status"] != "pending_approval":
            raise ValueError("only pending containment requests can be decided")
        if normalized_decision == "approve" and row["requested_by"] == actor:
            raise PermissionError("the requester cannot approve their own containment request")
        if normalized_decision == "approve":
            incident = connection.execute(
                """
                SELECT status FROM incidents
                WHERE id = (
                    SELECT incident_id FROM containment_actions WHERE id = ?
                )
                """,
                (action_key,),
            ).fetchone()
            if incident is None or incident["status"] != "acknowledged":
                raise ValueError("incident must remain acknowledged for approval")

        new_status = "approved" if normalized_decision == "approve" else "rejected"
        updated = connection.execute(
            """
            UPDATE containment_actions
            SET status = ?, decided_by = ?, decided_role = ?,
                decision_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending_approval'
            """,
            (new_status, actor, role, action_key),
        )
        if updated.rowcount != 1:
            raise ValueError("containment request was already decided")
        append_audit_entry(
            connection,
            event_type=f"containment.{new_status}",
            entity_type="containment_action",
            entity_id=action_key,
            actor_id=actor,
            actor_role=role,
            details={
                "asset_id": row["asset_id"],
                "incident_id": row["incident_id"],
                "status": new_status,
            },
        )
    return get_containment_action(database_path, action_key)


def execute_containment(
    database_path: Path, action_id: str
) -> ContainmentAction:
    """Apply an approved isolation action to the local simulated asset state."""
    action_key = _required_text(action_id, "action_id")
    initialize_database(database_path)
    with database_session(database_path, immediate=True) as connection:
        action = connection.execute(
            """
            SELECT incident_id, asset_id, status, decided_by
            FROM containment_actions WHERE id = ?
            """,
            (action_key,),
        ).fetchone()
        if action is None:
            raise ValueError(f"unknown containment action: {action_key}")
        if action["status"] != "approved":
            raise ValueError("only approved containment requests can be executed")

        incident = connection.execute(
            "SELECT status FROM incidents WHERE id = ?", (action["incident_id"],)
        ).fetchone()
        if incident is None or incident["status"] != "acknowledged":
            raise ValueError("incident must remain acknowledged to execute containment")

        state = connection.execute(
            "SELECT state FROM simulated_asset_state WHERE asset_id = ?",
            (action["asset_id"],),
        ).fetchone()
        if state is not None and state["state"] == "isolated":
            raise ValueError("simulated asset is already isolated")

        connection.execute(
            """
            INSERT INTO simulated_asset_state (
                asset_id, state, last_action_type, last_action_id
            ) VALUES (?, 'isolated', 'containment', ?)
            ON CONFLICT (asset_id) DO UPDATE SET
                state = 'isolated',
                last_action_type = 'containment',
                last_action_id = excluded.last_action_id,
                changed_at = CURRENT_TIMESTAMP,
                simulation_only = 1
            """,
            (action["asset_id"], action_key),
        )
        updated = connection.execute(
            """
            UPDATE containment_actions
            SET status = 'executed', executed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'approved'
            """,
            (action_key,),
        )
        if updated.rowcount != 1:
            raise ValueError("containment request was already executed")
        append_audit_entry(
            connection,
            event_type="containment.executed",
            entity_type="containment_action",
            entity_id=action_key,
            details={
                "action_type": "isolate_asset",
                "asset_id": action["asset_id"],
                "approved_by": action["decided_by"],
                "incident_id": action["incident_id"],
                "status": "executed",
            },
        )
    return get_containment_action(database_path, action_key)


def get_simulated_asset_state(
    database_path: Path, asset_id: str
) -> SimulatedAssetState:
    """Read local simulated state; an asset with no state row starts connected."""
    asset_key = _required_text(asset_id, "asset_id")
    initialize_database(database_path)
    with database_session(database_path) as connection:
        asset = connection.execute(
            "SELECT simulation_only FROM assets WHERE id = ?", (asset_key,)
        ).fetchone()
        if asset is None or asset["simulation_only"] != 1:
            raise ValueError(f"unknown simulated asset: {asset_key}")
        row = connection.execute(
            "SELECT * FROM simulated_asset_state WHERE asset_id = ?", (asset_key,)
        ).fetchone()
    if row is None:
        return SimulatedAssetState(
            asset_id=asset_key,
            state="connected",
            last_action_type=None,
            last_action_id=None,
            changed_at=None,
        )
    return SimulatedAssetState(
        asset_id=row["asset_id"],
        state=row["state"],
        last_action_type=row["last_action_type"],
        last_action_id=row["last_action_id"],
        changed_at=row["changed_at"],
    )
