"""Append-only, hash-linked records for local simulation workflow changes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from typing import Mapping
from uuid import uuid4

from .database import database_session, initialize_database


_GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    entry_id: str
    event_type: str
    actor_id: str | None
    actor_role: str | None
    entity_type: str
    entity_id: str
    details: dict[str, object]
    created_at: str
    previous_hash: str
    entry_hash: str


@dataclass(frozen=True)
class AuditChainVerification:
    valid: bool
    entries_checked: int
    last_sequence: int
    head_hash: str
    issue_sequence: int | None
    reason: str


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _entry_body(
    *,
    sequence: int,
    entry_id: str,
    event_type: str,
    actor_id: str | None,
    actor_role: str | None,
    entity_type: str,
    entity_id: str,
    details: dict[str, object],
    created_at: str,
    previous_hash: str,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "entry_id": entry_id,
        "event_type": event_type,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "details": details,
        "created_at": created_at,
        "previous_hash": previous_hash,
        "simulation_only": 1,
    }


def _entry_hash(body: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_json(dict(body)).encode("utf-8")).hexdigest()


def _entry_from_row(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        sequence=row["sequence"],
        entry_id=row["entry_id"],
        event_type=row["event_type"],
        actor_id=row["actor_id"],
        actor_role=row["actor_role"],
        entity_type=row["entity_type"],
        entity_id=row["entity_id"],
        details=json.loads(row["details_json"]),
        created_at=row["created_at"],
        previous_hash=row["previous_hash"],
        entry_hash=row["entry_hash"],
    )


def append_audit_entry(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    details: Mapping[str, object],
    actor_id: str | None = None,
    actor_role: str | None = None,
) -> AuditEntry:
    """Append one audit entry inside the caller's write transaction."""
    normalized = {
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": entity_id,
    }
    for name, value in normalized.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        normalized[name] = value.strip()
    if actor_id is not None and (not isinstance(actor_id, str) or not actor_id.strip()):
        raise ValueError("actor_id must be a non-empty string when provided")
    if actor_role is not None and (
        not isinstance(actor_role, str) or not actor_role.strip()
    ):
        raise ValueError("actor_role must be a non-empty string when provided")
    if not isinstance(details, Mapping):
        raise ValueError("details must be a mapping")
    normalized_details = dict(details)
    details_json = _canonical_json(normalized_details)

    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        UPDATE audit_chain_state
        SET last_sequence = last_sequence + 1
        WHERE id = 1
        """
    )
    state = connection.execute(
        "SELECT last_sequence, last_hash FROM audit_chain_state WHERE id = 1"
    ).fetchone()
    if state is None:
        raise RuntimeError("audit chain state is missing")

    sequence = int(state["last_sequence"])
    previous_hash = state["last_hash"]
    entry_id = uuid4().hex
    created_at = (
        datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    )
    body = _entry_body(
        sequence=sequence,
        entry_id=entry_id,
        event_type=normalized["event_type"],
        actor_id=actor_id.strip() if actor_id is not None else None,
        actor_role=actor_role.strip() if actor_role is not None else None,
        entity_type=normalized["entity_type"],
        entity_id=normalized["entity_id"],
        details=normalized_details,
        created_at=created_at,
        previous_hash=previous_hash,
    )
    entry_hash = _entry_hash(body)
    connection.execute(
        """
        INSERT INTO audit_log (
            sequence, entry_id, event_type, actor_id, actor_role,
            entity_type, entity_id, details_json, created_at,
            previous_hash, entry_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sequence,
            entry_id,
            normalized["event_type"],
            body["actor_id"],
            body["actor_role"],
            normalized["entity_type"],
            normalized["entity_id"],
            details_json,
            created_at,
            previous_hash,
            entry_hash,
        ),
    )
    updated = connection.execute(
        "UPDATE audit_chain_state SET last_hash = ? WHERE id = 1 AND last_sequence = ?",
        (entry_hash, sequence),
    )
    if updated.rowcount != 1:
        raise RuntimeError("audit chain state changed while appending an entry")

    return AuditEntry(
        sequence=sequence,
        entry_id=entry_id,
        event_type=normalized["event_type"],
        actor_id=body["actor_id"],
        actor_role=body["actor_role"],
        entity_type=normalized["entity_type"],
        entity_id=normalized["entity_id"],
        details=normalized_details,
        created_at=created_at,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )


def list_audit_entries(database_path: Path) -> list[AuditEntry]:
    """Return local audit entries in chain order."""
    initialize_database(database_path)
    with database_session(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM audit_log ORDER BY sequence"
        ).fetchall()
    return [_entry_from_row(row) for row in rows]


def verify_audit_chain(database_path: Path) -> AuditChainVerification:
    """Check entry order, previous hashes, content hashes, and the saved chain head."""
    initialize_database(database_path)
    with database_session(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM audit_log ORDER BY sequence"
        ).fetchall()
        state = connection.execute(
            "SELECT last_sequence, last_hash FROM audit_chain_state WHERE id = 1"
        ).fetchone()

    previous_hash = _GENESIS_HASH
    expected_sequence = 1
    checked = 0
    for row in rows:
        sequence = int(row["sequence"])
        if sequence != expected_sequence:
            return AuditChainVerification(
                False,
                checked,
                expected_sequence - 1,
                previous_hash,
                sequence,
                "Audit entry sequence has a gap or is out of order.",
            )
        if row["simulation_only"] != 1:
            return AuditChainVerification(
                False,
                checked,
                sequence - 1,
                previous_hash,
                sequence,
                "Audit entry is not marked simulation-only.",
            )
        if row["previous_hash"] != previous_hash:
            return AuditChainVerification(
                False,
                checked,
                sequence - 1,
                previous_hash,
                sequence,
                "Audit entry does not link to the previous hash.",
            )
        try:
            details = json.loads(row["details_json"])
        except (TypeError, json.JSONDecodeError):
            details = None
        if not isinstance(details, dict):
            return AuditChainVerification(
                False,
                checked,
                sequence - 1,
                previous_hash,
                sequence,
                "Audit entry details are not a JSON object.",
            )
        try:
            canonical_details = _canonical_json(details)
        except (TypeError, ValueError):
            canonical_details = None
        if canonical_details != row["details_json"]:
            return AuditChainVerification(
                False,
                checked,
                sequence - 1,
                previous_hash,
                sequence,
                "Audit entry details are not in canonical form.",
            )

        body = _entry_body(
            sequence=sequence,
            entry_id=row["entry_id"],
            event_type=row["event_type"],
            actor_id=row["actor_id"],
            actor_role=row["actor_role"],
            entity_type=row["entity_type"],
            entity_id=row["entity_id"],
            details=details,
            created_at=row["created_at"],
            previous_hash=row["previous_hash"],
        )
        stored_hash = row["entry_hash"]
        is_hash_text = (
            isinstance(stored_hash, str)
            and len(stored_hash) == 64
            and all(character in "0123456789abcdef" for character in stored_hash)
        )
        if not is_hash_text or not hmac.compare_digest(
            _entry_hash(body), stored_hash
        ):
            return AuditChainVerification(
                False,
                checked,
                sequence - 1,
                previous_hash,
                sequence,
                "Audit entry content hash does not match its stored hash.",
            )

        previous_hash = row["entry_hash"]
        expected_sequence += 1
        checked += 1

    if state is None:
        return AuditChainVerification(
            False,
            checked,
            checked,
            previous_hash,
            None,
            "Audit chain state is missing.",
        )
    if int(state["last_sequence"]) != checked or state["last_hash"] != previous_hash:
        return AuditChainVerification(
            False,
            checked,
            checked,
            previous_hash,
            None,
            "Saved audit chain head does not match the verified entries.",
        )
    return AuditChainVerification(
        True,
        checked,
        checked,
        previous_hash,
        None,
        "Audit chain is intact.",
    )
