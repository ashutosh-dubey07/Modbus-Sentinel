"""SQLite setup and transaction helpers for the local application."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator


_MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        1,
        ("CREATE TABLE app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",),
    ),
    (
        2,
        (
            """
            CREATE TABLE network_segments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                zone TEXT NOT NULL CHECK (
                    zone IN ('enterprise', 'operations', 'control', 'safety')
                ),
                description TEXT NOT NULL DEFAULT '',
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                asset_type TEXT NOT NULL CHECK (
                    asset_type IN (
                        'plc', 'hmi', 'engineering_workstation',
                        'historian', 'sensor', 'gateway'
                    )
                ),
                segment_id TEXT NOT NULL REFERENCES network_segments(id) ON DELETE RESTRICT,
                node_ref TEXT NOT NULL UNIQUE,
                criticality TEXT NOT NULL CHECK (
                    criticality IN ('low', 'medium', 'high', 'critical')
                ),
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
            "CREATE INDEX assets_segment_id_idx ON assets(segment_id)",
        ),
    ),
    (
        3,
        (
            """
            CREATE TABLE modbus_events (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                scenario TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                offset_ms INTEGER NOT NULL CHECK (offset_ms >= 0),
                source_ref TEXT NOT NULL,
                destination_ref TEXT NOT NULL,
                source_asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
                destination_asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
                raw_frame BLOB NOT NULL,
                transaction_id INTEGER,
                unit_id INTEGER,
                function_code INTEGER,
                start_address INTEGER,
                quantity INTEGER,
                register_value INTEGER,
                is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),
                validation_errors TEXT NOT NULL DEFAULT '[]',
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (run_id, sequence)
            )
            """,
            "CREATE INDEX modbus_events_run_id_idx ON modbus_events(run_id)",
        ),
    ),
    (
        4,
        (
            """
            CREATE TABLE detections (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('low', 'medium', 'high', 'critical')
                ),
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                destination_ref TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (run_id, rule_id, source_ref, destination_ref)
            )
            """,
            "CREATE INDEX detections_run_id_idx ON detections(run_id)",
            """
            CREATE TABLE detection_evidence (
                detection_id TEXT NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
                event_id TEXT NOT NULL REFERENCES modbus_events(id) ON DELETE CASCADE,
                evidence_order INTEGER NOT NULL CHECK (evidence_order > 0),
                reason TEXT NOT NULL,
                PRIMARY KEY (detection_id, event_id),
                UNIQUE (detection_id, evidence_order)
            )
            """,
            "CREATE INDEX detection_evidence_event_id_idx ON detection_evidence(event_id)",
        ),
    ),
    (
        5,
        (
            """
            CREATE TABLE incidents (
                id TEXT PRIMARY KEY,
                detection_id TEXT NOT NULL UNIQUE
                    REFERENCES detections(id) ON DELETE RESTRICT,
                status TEXT NOT NULL DEFAULT 'open' CHECK (
                    status IN ('open', 'acknowledged', 'closed')
                ),
                acknowledged_by TEXT,
                acknowledged_role TEXT CHECK (
                    acknowledged_role IS NULL
                    OR acknowledged_role IN ('operator', 'admin')
                ),
                acknowledged_at TEXT,
                closed_by TEXT,
                closed_role TEXT CHECK (
                    closed_role IS NULL OR closed_role = 'admin'
                ),
                closed_at TEXT,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (
                    (status = 'open'
                        AND acknowledged_by IS NULL
                        AND acknowledged_role IS NULL
                        AND acknowledged_at IS NULL
                        AND closed_by IS NULL
                        AND closed_role IS NULL
                        AND closed_at IS NULL)
                    OR
                    (status = 'acknowledged'
                        AND acknowledged_by IS NOT NULL
                        AND acknowledged_role IS NOT NULL
                        AND acknowledged_at IS NOT NULL
                        AND closed_by IS NULL
                        AND closed_role IS NULL
                        AND closed_at IS NULL)
                    OR
                    (status = 'closed'
                        AND acknowledged_by IS NOT NULL
                        AND acknowledged_role IS NOT NULL
                        AND acknowledged_at IS NOT NULL
                        AND closed_by IS NOT NULL
                        AND closed_role = 'admin'
                        AND closed_at IS NOT NULL)
                )
            )
            """,
            "CREATE INDEX incidents_status_idx ON incidents(status)",
            "CREATE INDEX incidents_created_at_idx ON incidents(created_at)",
            """
            CREATE TABLE admin_notifications (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                recipient_role TEXT NOT NULL DEFAULT 'admin' CHECK (recipient_role = 'admin'),
                channel TEXT NOT NULL DEFAULT 'in_app' CHECK (channel = 'in_app'),
                kind TEXT NOT NULL CHECK (kind = 'incident_opened'),
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'read')),
                read_by TEXT,
                read_at TEXT,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (incident_id, recipient_role, kind),
                CHECK (
                    (status = 'unread' AND read_by IS NULL AND read_at IS NULL)
                    OR (status = 'read' AND read_by IS NOT NULL AND read_at IS NOT NULL)
                )
            )
            """,
            "CREATE INDEX admin_notifications_status_idx ON admin_notifications(status)",
        ),
    ),
    (
        6,
        (
            """
            CREATE TABLE containment_actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
                asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                action_type TEXT NOT NULL CHECK (action_type = 'isolate_asset'),
                status TEXT NOT NULL DEFAULT 'pending_approval' CHECK (
                    status IN ('pending_approval', 'approved', 'rejected', 'executed')
                ),
                requested_by TEXT NOT NULL,
                requested_role TEXT NOT NULL CHECK (
                    requested_role IN ('operator', 'admin')
                ),
                requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                decided_by TEXT,
                decided_role TEXT CHECK (decided_role IS NULL OR decided_role = 'admin'),
                decision_at TEXT,
                executed_at TEXT,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (
                    (status = 'pending_approval'
                        AND decided_by IS NULL AND decided_role IS NULL
                        AND decision_at IS NULL AND executed_at IS NULL)
                    OR
                    (status IN ('approved', 'rejected')
                        AND decided_by IS NOT NULL AND decided_role = 'admin'
                        AND decision_at IS NOT NULL AND executed_at IS NULL)
                    OR
                    (status = 'executed'
                        AND decided_by IS NOT NULL AND decided_role = 'admin'
                        AND decision_at IS NOT NULL AND executed_at IS NOT NULL)
                )
            )
            """,
            "CREATE INDEX containment_actions_incident_idx ON containment_actions(incident_id)",
            "CREATE INDEX containment_actions_status_idx ON containment_actions(status)",
            """
            CREATE UNIQUE INDEX containment_actions_active_idx
            ON containment_actions(incident_id, asset_id, action_type)
            WHERE status IN ('pending_approval', 'approved')
            """,
            """
            CREATE TABLE simulated_asset_state (
                asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE RESTRICT,
                state TEXT NOT NULL CHECK (state IN ('connected', 'isolated')),
                last_action_type TEXT NOT NULL CHECK (
                    last_action_type IN ('containment', 'recovery')
                ),
                last_action_id TEXT NOT NULL,
                changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1)
            )
            """,
            "CREATE INDEX simulated_asset_state_idx ON simulated_asset_state(state)",
            """
            CREATE TABLE containment_approval_notifications (
                id TEXT PRIMARY KEY,
                containment_action_id TEXT NOT NULL UNIQUE
                    REFERENCES containment_actions(id) ON DELETE CASCADE,
                recipient_role TEXT NOT NULL DEFAULT 'admin' CHECK (recipient_role = 'admin'),
                channel TEXT NOT NULL DEFAULT 'in_app' CHECK (channel = 'in_app'),
                kind TEXT NOT NULL CHECK (kind = 'containment_approval_requested'),
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'read')),
                read_by TEXT,
                read_at TEXT,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (
                    (status = 'unread' AND read_by IS NULL AND read_at IS NULL)
                    OR (status = 'read' AND read_by IS NOT NULL AND read_at IS NOT NULL)
                )
            )
            """,
            "CREATE INDEX containment_approval_notifications_status_idx ON containment_approval_notifications(status)",
        ),
    ),
    (
        7,
        (
            """
            CREATE TABLE containment_verifications (
                id TEXT PRIMARY KEY,
                containment_action_id TEXT NOT NULL
                    REFERENCES containment_actions(id) ON DELETE RESTRICT,
                asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                expected_state TEXT NOT NULL CHECK (expected_state = 'isolated'),
                observed_state TEXT NOT NULL CHECK (
                    observed_state IN ('connected', 'isolated')
                ),
                observed_last_action_type TEXT CHECK (
                    observed_last_action_type IS NULL
                    OR observed_last_action_type IN ('containment', 'recovery')
                ),
                observed_last_action_id TEXT,
                result TEXT NOT NULL CHECK (result IN ('passed', 'failed')),
                reason TEXT NOT NULL,
                checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1)
            )
            """,
            "CREATE INDEX containment_verifications_action_idx ON containment_verifications(containment_action_id)",
            "CREATE INDEX containment_verifications_result_idx ON containment_verifications(result)",
        ),
    ),
    (
        8,
        (
            """
            CREATE TABLE audit_log (
                sequence INTEGER PRIMARY KEY,
                entry_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                actor_id TEXT,
                actor_role TEXT,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
                entry_hash TEXT NOT NULL CHECK (length(entry_hash) = 64),
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1)
            )
            """,
            "CREATE INDEX audit_log_entity_idx ON audit_log(entity_type, entity_id, sequence)",
            """
            CREATE TABLE audit_chain_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
                last_hash TEXT NOT NULL CHECK (length(last_hash) = 64)
            )
            """,
            """
            INSERT INTO audit_chain_state (id, last_sequence, last_hash)
            VALUES (1, 0, '0000000000000000000000000000000000000000000000000000000000000000')
            """,
            """
            CREATE TRIGGER audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit log entries are append-only');
            END
            """,
            """
            CREATE TRIGGER audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit log entries are append-only');
            END
            """,
        ),
    ),
    (
        9,
        (
            """
            CREATE TABLE recovery_actions (
                id TEXT PRIMARY KEY,
                containment_action_id TEXT NOT NULL
                    REFERENCES containment_actions(id) ON DELETE RESTRICT,
                asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                status TEXT NOT NULL DEFAULT 'pending_approval' CHECK (
                    status IN ('pending_approval', 'approved', 'rejected', 'executed')
                ),
                requested_by TEXT NOT NULL,
                requested_role TEXT NOT NULL CHECK (
                    requested_role IN ('operator', 'admin')
                ),
                requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                decided_by TEXT,
                decided_role TEXT CHECK (decided_role IS NULL OR decided_role = 'admin'),
                decision_at TEXT,
                executed_at TEXT,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (
                    (status = 'pending_approval'
                        AND decided_by IS NULL AND decided_role IS NULL
                        AND decision_at IS NULL AND executed_at IS NULL)
                    OR
                    (status IN ('approved', 'rejected')
                        AND decided_by IS NOT NULL AND decided_role = 'admin'
                        AND decision_at IS NOT NULL AND executed_at IS NULL)
                    OR
                    (status = 'executed'
                        AND decided_by IS NOT NULL AND decided_role = 'admin'
                        AND decision_at IS NOT NULL AND executed_at IS NOT NULL)
                )
            )
            """,
            "CREATE INDEX recovery_actions_status_idx ON recovery_actions(status)",
            """
            CREATE UNIQUE INDEX recovery_actions_active_idx
            ON recovery_actions(containment_action_id)
            WHERE status IN ('pending_approval', 'approved')
            """,
            """
            CREATE TABLE recovery_approval_notifications (
                id TEXT PRIMARY KEY,
                recovery_action_id TEXT NOT NULL UNIQUE
                    REFERENCES recovery_actions(id) ON DELETE CASCADE,
                recipient_role TEXT NOT NULL DEFAULT 'admin' CHECK (recipient_role = 'admin'),
                channel TEXT NOT NULL DEFAULT 'in_app' CHECK (channel = 'in_app'),
                kind TEXT NOT NULL CHECK (kind = 'recovery_approval_requested'),
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'read')),
                read_by TEXT,
                read_at TEXT,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (
                    (status = 'unread' AND read_by IS NULL AND read_at IS NULL)
                    OR (status = 'read' AND read_by IS NOT NULL AND read_at IS NOT NULL)
                )
            )
            """,
            "CREATE INDEX recovery_approval_notifications_status_idx ON recovery_approval_notifications(status)",
            """
            CREATE TABLE recovery_verifications (
                id TEXT PRIMARY KEY,
                recovery_action_id TEXT NOT NULL
                    REFERENCES recovery_actions(id) ON DELETE RESTRICT,
                asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                expected_state TEXT NOT NULL CHECK (expected_state = 'connected'),
                observed_state TEXT NOT NULL CHECK (
                    observed_state IN ('connected', 'isolated')
                ),
                observed_last_action_type TEXT CHECK (
                    observed_last_action_type IS NULL
                    OR observed_last_action_type IN ('containment', 'recovery')
                ),
                observed_last_action_id TEXT,
                result TEXT NOT NULL CHECK (result IN ('passed', 'failed')),
                reason TEXT NOT NULL,
                checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1)
            )
            """,
            "CREATE INDEX recovery_verifications_action_idx ON recovery_verifications(recovery_action_id)",
            "CREATE INDEX recovery_verifications_result_idx ON recovery_verifications(result)",
        ),
    ),
    (
        10,
        (
            """
            CREATE TABLE evaluation_runs (
                id TEXT PRIMARY KEY,
                scenario_count INTEGER NOT NULL CHECK (scenario_count > 0),
                true_positive_count INTEGER NOT NULL CHECK (true_positive_count >= 0),
                false_positive_count INTEGER NOT NULL CHECK (false_positive_count >= 0),
                missed_detection_count INTEGER NOT NULL CHECK (missed_detection_count >= 0),
                precision REAL CHECK (precision IS NULL OR (precision >= 0 AND precision <= 1)),
                recall REAL CHECK (recall IS NULL OR (recall >= 0 AND recall <= 1)),
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1)
            )
            """,
            "CREATE INDEX evaluation_runs_created_at_idx ON evaluation_runs(created_at)",
            """
            CREATE TABLE evaluation_cases (
                id TEXT PRIMARY KEY,
                evaluation_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
                scenario TEXT NOT NULL,
                run_id TEXT NOT NULL,
                expected_rule_ids_json TEXT NOT NULL,
                observed_rule_ids_json TEXT NOT NULL,
                matched_rule_ids_json TEXT NOT NULL,
                missed_rule_ids_json TEXT NOT NULL,
                unexpected_rule_ids_json TEXT NOT NULL,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK (simulation_only = 1),
                UNIQUE (evaluation_id, scenario)
            )
            """,
            "CREATE INDEX evaluation_cases_run_id_idx ON evaluation_cases(run_id)",
        ),
    ),
)


def connect_database(path: Path) -> sqlite3.Connection:
    """Open a local SQLite connection with foreign keys enabled."""
    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database(path: Path) -> None:
    """Create the database and apply any migrations not already recorded."""
    connection = connect_database(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            applied = {
                row["version"]
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            for version, statements in _MIGRATIONS:
                if version in applied:
                    continue
                for sql in statements:
                    connection.execute(sql)
                connection.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?)", (version,)
                )
    finally:
        connection.close()


@contextmanager
def database_session(
    path: Path, *, immediate: bool = False
) -> Iterator[sqlite3.Connection]:
    """Yield a connection, optionally locking writes before reading shared state."""
    connection = connect_database(path)
    try:
        if immediate:
            connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def schema_version(path: Path) -> int:
    """Return the latest applied migration, or zero before initialization."""
    with database_session(path) as connection:
        table = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'schema_migrations'
            """
        ).fetchone()
        if table is None:
            return 0
        row = connection.execute(
            "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
        ).fetchone()
        return int(row["version"])
