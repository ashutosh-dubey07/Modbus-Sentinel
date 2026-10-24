"""Independent checks of containment against local simulated asset state."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from uuid import uuid4

from .audit import append_audit_entry
from .database import database_session, initialize_database


@dataclass(frozen=True)
class ContainmentVerification:
    id: str
    containment_action_id: str
    asset_id: str
    expected_state: str
    observed_state: str
    observed_last_action_type: str | None
    observed_last_action_id: str | None
    result: str
    reason: str
    checked_at: str


def _verification_from_row(row: sqlite3.Row) -> ContainmentVerification:
    return ContainmentVerification(
        id=row["id"],
        containment_action_id=row["containment_action_id"],
        asset_id=row["asset_id"],
        expected_state=row["expected_state"],
        observed_state=row["observed_state"],
        observed_last_action_type=row["observed_last_action_type"],
        observed_last_action_id=row["observed_last_action_id"],
        result=row["result"],
        reason=row["reason"],
        checked_at=row["checked_at"],
    )


def verify_containment(
    database_path: Path, action_id: str
) -> ContainmentVerification:
    """Record whether an executed isolation matches the simulated asset state."""
    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("action_id must be a non-empty string")
    action_key = action_id.strip()
    initialize_database(database_path)

    with database_session(database_path, immediate=True) as connection:
        action = connection.execute(
            """
            SELECT id, asset_id, status, action_type
            FROM containment_actions WHERE id = ?
            """,
            (action_key,),
        ).fetchone()
        if action is None:
            raise ValueError(f"unknown containment action: {action_key}")
        if action["status"] != "executed":
            raise ValueError("containment must be executed before it can be verified")
        if action["action_type"] != "isolate_asset":
            raise ValueError("this verifier only supports simulated asset isolation")

        asset = connection.execute(
            "SELECT simulation_only FROM assets WHERE id = ?",
            (action["asset_id"],),
        ).fetchone()
        if asset is None or asset["simulation_only"] != 1:
            raise ValueError("containment action does not reference a simulated asset")

        state = connection.execute(
            """
            SELECT state, last_action_type, last_action_id
            FROM simulated_asset_state WHERE asset_id = ?
            """,
            (action["asset_id"],),
        ).fetchone()
        observed_state = state["state"] if state is not None else "connected"
        observed_action_type = (
            state["last_action_type"] if state is not None else None
        )
        observed_action_id = state["last_action_id"] if state is not None else None

        passed = (
            observed_state == "isolated"
            and observed_action_type == "containment"
            and observed_action_id == action_key
        )
        if passed:
            reason = "The simulated asset is isolated by this containment action."
        elif observed_state != "isolated":
            reason = (
                "Expected isolated simulated state, "
                f"but observed {observed_state}."
            )
        else:
            reason = (
                "The simulated asset is isolated, but its last action does not "
                "match this containment request."
            )

        verification_id = uuid4().hex
        connection.execute(
            """
            INSERT INTO containment_verifications (
                id, containment_action_id, asset_id, expected_state,
                observed_state, observed_last_action_type,
                observed_last_action_id, result, reason
            ) VALUES (?, ?, ?, 'isolated', ?, ?, ?, ?, ?)
            """,
            (
                verification_id,
                action_key,
                action["asset_id"],
                observed_state,
                observed_action_type,
                observed_action_id,
                "passed" if passed else "failed",
                reason,
            ),
        )
        append_audit_entry(
            connection,
            event_type="containment.verification_recorded",
            entity_type="containment_verification",
            entity_id=verification_id,
            details={
                "asset_id": action["asset_id"],
                "containment_action_id": action_key,
                "observed_state": observed_state,
                "result": "passed" if passed else "failed",
            },
        )
        row = connection.execute(
            "SELECT * FROM containment_verifications WHERE id = ?",
            (verification_id,),
        ).fetchone()

    return _verification_from_row(row)


def list_containment_verifications(
    database_path: Path, action_id: str | None = None
) -> list[ContainmentVerification]:
    """Return saved verification results in chronological order."""
    initialize_database(database_path)
    query = "SELECT * FROM containment_verifications"
    parameters: tuple[str, ...] = ()
    if action_id is not None:
        if not isinstance(action_id, str) or not action_id.strip():
            raise ValueError("action_id must be a non-empty string")
        query += " WHERE containment_action_id = ?"
        parameters = (action_id.strip(),)
    query += " ORDER BY checked_at, id"
    with database_session(database_path) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_verification_from_row(row) for row in rows]
