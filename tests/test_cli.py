from pathlib import Path

from modbus_sentinel.cli import main
from modbus_sentinel.database import database_session
from modbus_sentinel.audit import verify_audit_chain
from modbus_sentinel.containment import get_simulated_asset_state
from modbus_sentinel.inventory import list_assets, list_segments


def test_setup_command_creates_database_and_demo_inventory(
    tmp_path: Path, capsys
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[app]\nmode = "simulation"\ndatabase_path = "data/sentinel.sqlite3"\n',
        encoding="utf-8",
    )

    result = main(["--config", str(config_path)])

    assert result == 0
    assert len(list_segments(tmp_path / "data" / "sentinel.sqlite3")) == 3
    assert len(list_assets(tmp_path / "data" / "sentinel.sqlite3")) == 5
    assert "Local simulation database ready" in capsys.readouterr().out


def test_cli_runs_a_local_scenario_and_prints_its_detection(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[app]\nmode = "simulation"\ndatabase_path = "data/sentinel.sqlite3"\n',
        encoding="utf-8",
    )

    result = main(
        ["--config", str(config_path), "--scenario", "write_attempt"]
    )

    output = capsys.readouterr().out
    assert result == 0
    assert "1 request, 1 detection" in output
    assert "[HIGH] Modbus write request observed" in output
    assert "Incident: open" in output
    assert "Admin notification: saved to local inbox" in output
    with database_session(tmp_path / "data" / "sentinel.sqlite3") as connection:
        row = connection.execute(
            "SELECT rule_id, severity FROM detections"
        ).fetchone()
        incident_count = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        notification_count = connection.execute(
            "SELECT COUNT(*) FROM admin_notifications"
        ).fetchone()[0]
        action_count = connection.execute(
            "SELECT COUNT(*) FROM containment_actions"
        ).fetchone()[0]
    assert tuple(row) == ("modbus.write_request", "high")
    assert incident_count == 1
    assert notification_count == 1
    assert action_count == 0


def test_cli_checks_the_local_audit_chain(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[app]\nmode = "simulation"\ndatabase_path = "data/sentinel.sqlite3"\n',
        encoding="utf-8",
    )
    assert main(["--config", str(config_path)]) == 0
    assert main(
        ["--config", str(config_path), "--scenario", "normal_poll"]
    ) == 0

    result = main(["--config", str(config_path), "--verify-audit"])

    output = capsys.readouterr().out
    assert result == 0
    assert "Audit chain is intact" in output
    assert "entries" in output


def test_cli_reports_missing_database_for_audit_check(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[app]\nmode = "simulation"\ndatabase_path = "data/sentinel.sqlite3"\n',
        encoding="utf-8",
    )

    result = main(["--config", str(config_path), "--verify-audit"])

    assert result == 1
    assert "database does not exist" in capsys.readouterr().err


def test_cli_runs_repeatable_end_to_end_response_demo(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[app]\nmode = "simulation"\ndatabase_path = "data/sentinel.sqlite3"\n',
        encoding="utf-8",
    )
    arguments = ["--config", str(config_path), "--response-demo"]

    first_result = main(arguments)
    first_output = capsys.readouterr().out
    second_result = main(arguments)
    second_output = capsys.readouterr().out
    database_path = tmp_path / "data" / "sentinel.sqlite3"

    assert first_result == 0
    assert second_result == 0
    assert "4 simulated requests, 1 finding" in first_output
    assert "Containment: executed, verification passed" in first_output
    assert "Recovery: executed, verification passed" in first_output
    assert "Incident: closed" in second_output
    assert get_simulated_asset_state(database_path, "eng-ws-01").state == "connected"
    assert verify_audit_chain(database_path).valid
