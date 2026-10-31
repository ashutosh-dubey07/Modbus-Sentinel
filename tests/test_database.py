from pathlib import Path
import sqlite3

import pytest

from modbus_sentinel.database import (
    database_session,
    initialize_database,
    schema_version,
)


def test_initialize_database_is_repeatable(tmp_path: Path) -> None:
    database_path = tmp_path / "nested" / "sentinel.sqlite3"

    initialize_database(database_path)
    initialize_database(database_path)

    assert schema_version(database_path) == 10
    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {
        "schema_migrations",
        "app_metadata",
        "network_segments",
        "assets",
        "modbus_events",
        "detections",
        "detection_evidence",
        "incidents",
        "admin_notifications",
        "containment_actions",
        "simulated_asset_state",
        "containment_approval_notifications",
        "containment_verifications",
        "audit_log",
        "audit_chain_state",
        "recovery_actions",
        "recovery_approval_notifications",
        "recovery_verifications",
        "evaluation_runs",
        "evaluation_cases",
    } <= tables


def test_initialize_database_upgrades_a_phase_one_database(tmp_path: Path) -> None:
    database_path = tmp_path / "phase-one.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            "CREATE TABLE app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO schema_migrations (version) VALUES (1)")

    initialize_database(database_path)

    assert schema_version(database_path) == 10
    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {
        "network_segments",
        "assets",
        "modbus_events",
        "detections",
        "detection_evidence",
        "incidents",
        "admin_notifications",
        "containment_actions",
        "simulated_asset_state",
        "containment_approval_notifications",
        "containment_verifications",
        "audit_log",
        "audit_chain_state",
        "recovery_actions",
        "recovery_approval_notifications",
        "recovery_verifications",
        "evaluation_runs",
        "evaluation_cases",
    } <= tables


def test_database_session_commits_successful_work(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    initialize_database(database_path)

    with database_session(database_path) as connection:
        connection.execute(
            "INSERT INTO app_metadata (key, value) VALUES (?, ?)",
            ("project", "Modbus Sentinel"),
        )

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT value FROM app_metadata WHERE key = ?", ("project",)
        ).fetchone()
    assert row == ("Modbus Sentinel",)


def test_database_session_rolls_back_errors(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    initialize_database(database_path)

    with pytest.raises(RuntimeError, match="stop"):
        with database_session(database_path) as connection:
            connection.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?, ?)",
                ("project", "Modbus Sentinel"),
            )
            raise RuntimeError("stop")

    with sqlite3.connect(database_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM app_metadata").fetchone()[0]
    assert count == 0


def test_database_session_enables_foreign_keys(tmp_path: Path) -> None:
    database_path = tmp_path / "sentinel.sqlite3"
    initialize_database(database_path)

    with database_session(database_path) as connection:
        enabled = connection.execute("PRAGMA foreign_keys").fetchone()[0]

    assert enabled == 1
