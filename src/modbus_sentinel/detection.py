"""Rule-based findings for locally simulated Modbus events."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Mapping, Sequence
from uuid import NAMESPACE_URL, uuid5

from .audit import append_audit_entry
from .database import database_session, initialize_database


SWEEP_ADDRESS_THRESHOLD = 4
READ_FUNCTION_CODES = {3, 4}
WRITE_FUNCTION_CODES = {6}


@dataclass(frozen=True)
class EvidenceReference:
    event_id: str
    reason: str


@dataclass(frozen=True)
class Detection:
    id: str
    run_id: str
    rule_id: str
    severity: str
    title: str
    summary: str
    source_ref: str
    destination_ref: str
    details: dict[str, object]
    evidence: tuple[EvidenceReference, ...]


def _pair(event: Mapping[str, object]) -> tuple[str, str]:
    return str(event["source_ref"]), str(event["destination_ref"])


def _stable_detection_id(
    run_id: str, rule_id: str, source_ref: str, destination_ref: str
) -> str:
    identity = json.dumps(
        [run_id, rule_id, source_ref, destination_ref],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return uuid5(NAMESPACE_URL, f"modbus-sentinel:detection:{identity}").hex


def _make_detection(
    run_id: str,
    rule_id: str,
    severity: str,
    title: str,
    summary: str,
    pair: tuple[str, str],
    details: dict[str, object],
    evidence: Sequence[EvidenceReference],
) -> Detection:
    source_ref, destination_ref = pair
    return Detection(
        id=_stable_detection_id(run_id, rule_id, source_ref, destination_ref),
        run_id=run_id,
        rule_id=rule_id,
        severity=severity,
        title=title,
        summary=summary,
        source_ref=source_ref,
        destination_ref=destination_ref,
        details=details,
        evidence=tuple(evidence),
    )


def _validation_errors(event: Mapping[str, object]) -> list[str]:
    raw = event.get("validation_errors", "[]")
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return [raw]
    else:
        value = raw
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)] if value else []


def evaluate_events(
    run_id: str, events: Sequence[Mapping[str, object]]
) -> list[Detection]:
    """Evaluate event behavior without relying on the scenario label."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")
    if not events:
        return []

    normalized_run_id = run_id.strip()
    if any(str(event.get("run_id", normalized_run_id)) != normalized_run_id for event in events):
        raise ValueError("all events must belong to the requested run")

    findings: list[Detection] = []

    write_groups: dict[tuple[str, str], list[Mapping[str, object]]] = defaultdict(list)
    read_groups: dict[tuple[str, str], list[Mapping[str, object]]] = defaultdict(list)
    invalid_groups: dict[tuple[str, str], list[Mapping[str, object]]] = defaultdict(list)

    for event in events:
        if int(event.get("simulation_only", 1)) != 1:
            raise ValueError("detection accepts simulation-only events")
        pair = _pair(event)
        is_valid = bool(int(event["is_valid"]))
        if not is_valid:
            invalid_groups[pair].append(event)
            continue

        function_code = event.get("function_code")
        if function_code in WRITE_FUNCTION_CODES:
            write_groups[pair].append(event)
        elif function_code in READ_FUNCTION_CODES:
            read_groups[pair].append(event)

    for pair, group in sorted(write_groups.items()):
        references = tuple(
            EvidenceReference(
                event_id=str(event["id"]),
                reason=(
                    f"Function code {event['function_code']} requested a register write "
                    f"at address {event['start_address']} with value {event['register_value']}."
                ),
            )
            for event in sorted(group, key=lambda item: int(item["sequence"]))
        )
        findings.append(
            _make_detection(
                normalized_run_id,
                "modbus.write_request",
                "high",
                "Modbus write request observed",
                "A Modbus single-register write request was observed. Review whether "
                "this action is expected for the simulated asset.",
                pair,
                {
                    "request_count": len(group),
                    "function_codes": sorted(
                        {int(event["function_code"]) for event in group}
                    ),
                    "addresses": sorted(
                        {int(event["start_address"]) for event in group}
                    ),
                },
                references,
            )
        )

    for pair, group in sorted(read_groups.items()):
        addresses = sorted(
            {
                int(event["start_address"])
                for event in group
                if event.get("start_address") is not None
            }
        )
        if len(addresses) < SWEEP_ADDRESS_THRESHOLD:
            continue
        references = tuple(
            EvidenceReference(
                event_id=str(event["id"]),
                reason=(
                    f"Read function code {event['function_code']} requested start "
                    f"address {event['start_address']} for {event['quantity']} register(s)."
                ),
            )
            for event in sorted(group, key=lambda item: int(item["sequence"]))
        )
        findings.append(
            _make_detection(
                normalized_run_id,
                "modbus.address_enumeration",
                "medium",
                "Multiple register addresses read",
                "One simulated source read several distinct register addresses "
                "from the same asset during this run.",
                pair,
                {
                    "request_count": len(group),
                    "distinct_address_count": len(addresses),
                    "address_threshold": SWEEP_ADDRESS_THRESHOLD,
                    "addresses": addresses,
                },
                references,
            )
        )

    for pair, group in sorted(invalid_groups.items()):
        errors_by_event = [
            (event, _validation_errors(event))
            for event in sorted(group, key=lambda item: int(item["sequence"]))
        ]
        error_counts = Counter(
            error for _, errors in errors_by_event for error in errors
        )
        references = tuple(
            EvidenceReference(
                event_id=str(event["id"]),
                reason=(
                    "Request failed validation: " + "; ".join(errors)
                    if errors
                    else "Request was marked invalid without a recorded reason."
                ),
            )
            for event, errors in errors_by_event
        )
        findings.append(
            _make_detection(
                normalized_run_id,
                "modbus.invalid_request",
                "high",
                "Invalid Modbus request observed",
                "One or more simulated requests failed protocol or inventory validation.",
                pair,
                {
                    "invalid_event_count": len(group),
                    "validation_error_counts": dict(sorted(error_counts.items())),
                },
                references,
            )
        )

    return findings


def _save_detections(
    connection: sqlite3.Connection, detections: Sequence[Detection]
) -> None:
    for detection in detections:
        connection.execute(
            """
            INSERT INTO detections (
                id, run_id, rule_id, severity, title, summary,
                source_ref, destination_ref, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (run_id, rule_id, source_ref, destination_ref) DO UPDATE SET
                severity = excluded.severity,
                title = excluded.title,
                summary = excluded.summary,
                details_json = excluded.details_json
            """,
            (
                detection.id,
                detection.run_id,
                detection.rule_id,
                detection.severity,
                detection.title,
                detection.summary,
                detection.source_ref,
                detection.destination_ref,
                json.dumps(detection.details, sort_keys=True),
            ),
        )
        connection.execute(
            "DELETE FROM detection_evidence WHERE detection_id = ?",
            (detection.id,),
        )
        connection.executemany(
            """
            INSERT INTO detection_evidence (
                detection_id, event_id, evidence_order, reason
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (detection.id, item.event_id, order, item.reason)
                for order, item in enumerate(detection.evidence, start=1)
            ),
        )


def detect_run(database_path: Path, run_id: str) -> list[Detection]:
    """Evaluate and store findings for one previously recorded simulation run."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")
    normalized_run_id = run_id.strip()
    initialize_database(database_path)
    with database_session(database_path, immediate=True) as connection:
        rows = connection.execute(
            """
            SELECT * FROM modbus_events
            WHERE run_id = ? AND simulation_only = 1
            ORDER BY sequence, id
            """,
            (normalized_run_id,),
        ).fetchall()
        if not rows:
            raise ValueError(f"no simulated events found for run {normalized_run_id!r}")
        detections = evaluate_events(
            normalized_run_id, [dict(row) for row in rows]
        )
        _save_detections(connection, detections)
        append_audit_entry(
            connection,
            event_type="detection.run_evaluated",
            entity_type="simulation_run",
            entity_id=normalized_run_id,
            details={
                "detection_count": len(detections),
                "detection_ids": [item.id for item in detections],
                "rule_ids": sorted({item.rule_id for item in detections}),
            },
        )
    return detections


def list_detections(database_path: Path, run_id: str) -> list[Detection]:
    """Read stored findings and their event-level evidence references."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")
    normalized_run_id = run_id.strip()
    initialize_database(database_path)
    with database_session(database_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM detections
            WHERE run_id = ? AND simulation_only = 1
            ORDER BY rule_id, source_ref, destination_ref
            """,
            (normalized_run_id,),
        ).fetchall()
        detections: list[Detection] = []
        for row in rows:
            evidence_rows = connection.execute(
                """
                SELECT event_id, reason FROM detection_evidence
                WHERE detection_id = ? ORDER BY evidence_order
                """,
                (row["id"],),
            ).fetchall()
            detections.append(
                Detection(
                    id=row["id"],
                    run_id=row["run_id"],
                    rule_id=row["rule_id"],
                    severity=row["severity"],
                    title=row["title"],
                    summary=row["summary"],
                    source_ref=row["source_ref"],
                    destination_ref=row["destination_ref"],
                    details=json.loads(row["details_json"]),
                    evidence=tuple(
                        EvidenceReference(
                            event_id=evidence["event_id"],
                            reason=evidence["reason"],
                        )
                        for evidence in evidence_rows
                    ),
                )
            )
    return detections
