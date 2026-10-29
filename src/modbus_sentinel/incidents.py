"""Local incident lifecycle and administrator inbox for simulated findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from uuid import NAMESPACE_URL, uuid5

from .audit import append_audit_entry
from .database import database_session, initialize_database
from .detection import list_detections


_ACTION_ROLES = {
    "acknowledge_incident": {"operator", "admin"},
    "close_incident": {"admin"},
    "read_admin_notification": {"admin"},
    "request_containment": {"operator", "admin"},
    "decide_containment": {"admin"},
    "request_recovery": {"operator", "admin"},
    "decide_recovery": {"admin"},
}


@dataclass(frozen=True)
class Incident:
    id: str
    detection_id: str
    run_id: str
    rule_id: str
    severity: str
    title: str
    summary: str
    source_ref: str
    destination_ref: str
    status: str
    acknowledged_by: str | None
    acknowledged_role: str | None
    acknowledged_at: str | None
    closed_by: str | None
    closed_role: str | None
    closed_at: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AdminNotification:
    id: str
    incident_id: str | None
    containment_action_id: str | None
    recovery_action_id: str | None
    recipient_role: str
    channel: str
    kind: str
    message: str
    status: str
    read_by: str | None
    read_at: str | None
    created_at: str


def _required_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def authorize_demo_action(actor_role: str, action: str) -> str:
    """Apply the local demo role policy; this does not authenticate a person."""
    role = _required_text(actor_role, "actor_role").lower()
    allowed_roles = _ACTION_ROLES.get(action)
    if allowed_roles is None:
        raise ValueError(f"unknown demo action: {action}")
    if role not in {"viewer", "operator", "admin"}:
        raise ValueError("actor_role must be viewer, operator, or admin")
    if role not in allowed_roles:
        raise PermissionError(f"role {role!r} cannot perform {action}")
    return role


def _incident_id(detection_id: str) -> str:
    return uuid5(NAMESPACE_URL, f"modbus-sentinel:incident:{detection_id}").hex


def _notification_id(incident_id: str) -> str:
    return uuid5(
        NAMESPACE_URL,
        f"modbus-sentinel:notification:{incident_id}:admin:incident_opened",
    ).hex


def _incident_from_row(row: sqlite3.Row) -> Incident:
    return Incident(
        id=row["id"],
        detection_id=row["detection_id"],
        run_id=row["run_id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        title=row["title"],
        summary=row["summary"],
        source_ref=row["source_ref"],
        destination_ref=row["destination_ref"],
        status=row["status"],
        acknowledged_by=row["acknowledged_by"],
        acknowledged_role=row["acknowledged_role"],
        acknowledged_at=row["acknowledged_at"],
        closed_by=row["closed_by"],
        closed_role=row["closed_role"],
        closed_at=row["closed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _notification_from_row(row: sqlite3.Row) -> AdminNotification:
    return AdminNotification(
        id=row["id"],
        incident_id=row["incident_id"],
        containment_action_id=row["containment_action_id"],
        recovery_action_id=row["recovery_action_id"],
        recipient_role=row["recipient_role"],
        channel=row["channel"],
        kind=row["kind"],
        message=row["message"],
        status=row["status"],
        read_by=row["read_by"],
        read_at=row["read_at"],
        created_at=row["created_at"],
    )


def create_incidents_for_run(database_path: Path, run_id: str) -> list[Incident]:
    """Create one open incident and in-app admin notification per finding."""
    normalized_run_id = _required_text(run_id, "run_id")
    detections = list_detections(database_path, normalized_run_id)
    initialize_database(database_path)

    with database_session(database_path, immediate=True) as connection:
        for detection in detections:
            incident_id = _incident_id(detection.id)
            inserted = connection.execute(
                "INSERT OR IGNORE INTO incidents (id, detection_id) VALUES (?, ?)",
                (incident_id, detection.id),
            )
            message = (
                f"{detection.severity.upper()} incident: {detection.title} "
                f"from {detection.source_ref} to {detection.destination_ref}."
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO admin_notifications (
                    id, incident_id, recipient_role, channel, kind, message
                ) VALUES (?, ?, 'admin', 'in_app', 'incident_opened', ?)
                """,
                (_notification_id(incident_id), incident_id, message),
            )
            if inserted.rowcount == 1:
                append_audit_entry(
                    connection,
                    event_type="incident.created",
                    entity_type="incident",
                    entity_id=incident_id,
                    details={
                        "detection_id": detection.id,
                        "run_id": normalized_run_id,
                        "rule_id": detection.rule_id,
                        "severity": detection.severity,
                    },
                )

    return list_incidents(database_path, normalized_run_id)


def list_incidents(
    database_path: Path, run_id: str | None = None
) -> list[Incident]:
    """List incidents, optionally restricted to one simulation run."""
    initialize_database(database_path)
    query = """
        SELECT i.*, d.run_id, d.rule_id, d.severity, d.title, d.summary,
               d.source_ref, d.destination_ref
        FROM incidents AS i
        JOIN detections AS d ON d.id = i.detection_id
    """
    parameters: tuple[str, ...] = ()
    if run_id is not None:
        query += " WHERE d.run_id = ?"
        parameters = (_required_text(run_id, "run_id"),)
    query += """
        ORDER BY CASE d.severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            ELSE 3
        END, i.created_at, i.id
    """
    with database_session(database_path) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_incident_from_row(row) for row in rows]


def get_incident(database_path: Path, incident_id: str) -> Incident:
    """Return one incident, including fields from its linked detection."""
    incident_key = _required_text(incident_id, "incident_id")
    initialize_database(database_path)
    with database_session(database_path) as connection:
        row = connection.execute(
            """
            SELECT i.*, d.run_id, d.rule_id, d.severity, d.title, d.summary,
                   d.source_ref, d.destination_ref
            FROM incidents AS i
            JOIN detections AS d ON d.id = i.detection_id
            WHERE i.id = ?
            """,
            (incident_key,),
        ).fetchone()
    if row is None:
        raise ValueError(f"unknown incident: {incident_key}")
    return _incident_from_row(row)


def acknowledge_incident(
    database_path: Path,
    incident_id: str,
    *,
    actor_id: str,
    actor_role: str,
) -> Incident:
    """Move an open incident to acknowledged as an operator or admin."""
    role = authorize_demo_action(actor_role, "acknowledge_incident")
    incident_key = _required_text(incident_id, "incident_id")
    actor = _required_text(actor_id, "actor_id")
    initialize_database(database_path)
    with database_session(database_path, immediate=True) as connection:
        row = connection.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_key,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown incident: {incident_key}")
        if row["status"] != "open":
            raise ValueError("only open incidents can be acknowledged")
        connection.execute(
            """
            UPDATE incidents
            SET status = 'acknowledged', acknowledged_by = ?,
                acknowledged_role = ?, acknowledged_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'open'
            """,
            (actor, role, incident_key),
        )
        append_audit_entry(
            connection,
            event_type="incident.acknowledged",
            entity_type="incident",
            entity_id=incident_key,
            actor_id=actor,
            actor_role=role,
            details={"from_status": "open", "to_status": "acknowledged"},
        )
    return get_incident(database_path, incident_key)


def close_incident(
    database_path: Path,
    incident_id: str,
    *,
    actor_id: str,
    actor_role: str,
) -> Incident:
    """Close an acknowledged incident as an administrator."""
    role = authorize_demo_action(actor_role, "close_incident")
    incident_key = _required_text(incident_id, "incident_id")
    actor = _required_text(actor_id, "actor_id")
    initialize_database(database_path)
    with database_session(database_path, immediate=True) as connection:
        row = connection.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_key,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown incident: {incident_key}")
        if row["status"] != "acknowledged":
            raise ValueError("only acknowledged incidents can be closed")
        active_action = connection.execute(
            """
            SELECT id FROM containment_actions
            WHERE incident_id = ? AND status IN ('pending_approval', 'approved')
            """,
            (incident_key,),
        ).fetchone()
        if active_action is not None:
            raise ValueError("decide or execute pending containment actions before closing")
        connection.execute(
            """
            UPDATE incidents
            SET status = 'closed', closed_by = ?, closed_role = ?,
                closed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'acknowledged'
            """,
            (actor, role, incident_key),
        )
        append_audit_entry(
            connection,
            event_type="incident.closed",
            entity_type="incident",
            entity_id=incident_key,
            actor_id=actor,
            actor_role=role,
            details={"from_status": "acknowledged", "to_status": "closed"},
        )
    return get_incident(database_path, incident_key)


def list_admin_notifications(
    database_path: Path, *, unread_only: bool = False
) -> list[AdminNotification]:
    """Read the local administrator inbox without sending external messages."""
    initialize_database(database_path)
    status_filter = " AND status = 'unread'" if unread_only else ""
    with database_session(database_path) as connection:
        incident_rows = connection.execute(
            """
            SELECT id, incident_id, NULL AS containment_action_id,
                   NULL AS recovery_action_id,
                   recipient_role, channel, kind, message, status,
                   read_by, read_at, created_at
            FROM admin_notifications
            WHERE recipient_role = 'admin'
            """ + status_filter
        ).fetchall()
        containment_rows = connection.execute(
            """
            SELECT id, NULL AS incident_id, containment_action_id,
                   NULL AS recovery_action_id,
                   recipient_role, channel, kind, message, status,
                   read_by, read_at, created_at
            FROM containment_approval_notifications
            WHERE recipient_role = 'admin'
            """ + status_filter
        ).fetchall()
        recovery_rows = connection.execute(
            """
            SELECT id, NULL AS incident_id, NULL AS containment_action_id,
                   recovery_action_id,
                   recipient_role, channel, kind, message, status,
                   read_by, read_at, created_at
            FROM recovery_approval_notifications
            WHERE recipient_role = 'admin'
            """ + status_filter
        ).fetchall()
    notifications = [
        _notification_from_row(row)
        for row in (*incident_rows, *containment_rows, *recovery_rows)
    ]
    return sorted(notifications, key=lambda item: (item.created_at, item.id))


def mark_notification_read(
    database_path: Path,
    notification_id: str,
    *,
    actor_id: str,
    actor_role: str,
) -> AdminNotification:
    """Mark an in-app admin notification read, with an admin role check."""
    role = authorize_demo_action(actor_role, "read_admin_notification")
    notification_key = _required_text(notification_id, "notification_id")
    actor = _required_text(actor_id, "actor_id")
    initialize_database(database_path)
    table_name: str | None = None
    with database_session(database_path, immediate=True) as connection:
        for candidate in (
            "admin_notifications",
            "containment_approval_notifications",
            "recovery_approval_notifications",
        ):
            row = connection.execute(
                f"SELECT status, kind FROM {candidate} WHERE id = ?",
                (notification_key,),
            ).fetchone()
            if row is not None:
                table_name = candidate
                if row["status"] == "unread":
                    connection.execute(
                        f"""
                        UPDATE {candidate}
                        SET status = 'read', read_by = ?, read_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND status = 'unread'
                        """,
                        (actor, notification_key),
                    )
                    append_audit_entry(
                        connection,
                        event_type="admin_notification.read",
                        entity_type="admin_notification",
                        entity_id=notification_key,
                        actor_id=actor,
                        actor_role=role,
                        details={"kind": row["kind"], "to_status": "read"},
                    )
                break
        if table_name is None:
            raise ValueError(f"unknown admin notification: {notification_key}")
    for notification in list_admin_notifications(database_path):
        if notification.id == notification_key:
            return notification
    raise ValueError(f"unknown admin notification: {notification_key}")
