"""Read-only local dashboard for the simulation database."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import sqlite3
import sys
from urllib.parse import urlparse

from .audit import verify_audit_chain
from .database import database_session, initialize_database
from .evaluation import latest_evaluation
from .settings import ConfigError, load_settings


PAGE_PATH = Path(__file__).parent / "web" / "index.html"


def _evaluation_json(database_path: Path) -> dict[str, object] | None:
    result = latest_evaluation(database_path)
    if result is None:
        return None
    return {
        "id": result.id,
        "created_at": result.created_at,
        "scenario_count": result.scenario_count,
        "true_positive_count": result.true_positive_count,
        "false_positive_count": result.false_positive_count,
        "missed_detection_count": result.missed_detection_count,
        "precision": result.precision,
        "recall": result.recall,
        "evaluated_rules": result.evaluated_rules,
        "unevaluated_rules": result.unevaluated_rules,
        "cases": [
            {
                "scenario": case.scenario,
                "expected": case.expected_rule_ids,
                "observed": case.observed_rule_ids,
                "missed": case.missed_rule_ids,
                "unexpected": case.unexpected_rule_ids,
            }
            for case in result.cases
        ],
    }


def _overview(database_path: Path) -> dict[str, object]:
    initialize_database(database_path)
    with database_session(database_path) as connection:
        counts = {
            "segments": connection.execute(
                "SELECT COUNT(*) FROM network_segments WHERE simulation_only = 1"
            ).fetchone()[0],
            "assets": connection.execute(
                "SELECT COUNT(*) FROM assets WHERE simulation_only = 1"
            ).fetchone()[0],
            "events": connection.execute(
                "SELECT COUNT(*) FROM modbus_events WHERE simulation_only = 1"
            ).fetchone()[0],
            "findings": connection.execute(
                "SELECT COUNT(*) FROM detections WHERE simulation_only = 1"
            ).fetchone()[0],
            "open_incidents": connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE status != 'closed' AND simulation_only = 1"
            ).fetchone()[0],
            "isolated_assets": connection.execute(
                "SELECT COUNT(*) FROM simulated_asset_state WHERE state = 'isolated' AND simulation_only = 1"
            ).fetchone()[0],
            "recovery_requests": connection.execute(
                "SELECT COUNT(*) FROM recovery_actions WHERE simulation_only = 1"
            ).fetchone()[0],
        }
        segment_rows = connection.execute(
            "SELECT id, name, zone, description FROM network_segments ORDER BY name"
        ).fetchall()
        asset_rows = connection.execute(
            """
            SELECT a.id, a.name, a.asset_type, a.segment_id, a.node_ref,
                   a.criticality, COALESCE(s.state, 'connected') AS state
            FROM assets AS a
            LEFT JOIN simulated_asset_state AS s ON s.asset_id = a.id
            WHERE a.simulation_only = 1 ORDER BY a.name
            """
        ).fetchall()
        finding_rows = connection.execute(
            """
            SELECT id, run_id, rule_id, severity, title, summary,
                   source_ref, destination_ref, created_at
            FROM detections WHERE simulation_only = 1
            ORDER BY created_at DESC, id DESC LIMIT 10
            """
        ).fetchall()
        incident_rows = connection.execute(
            """
            SELECT i.id, i.status, i.created_at, d.severity, d.title,
                   d.source_ref, d.destination_ref
            FROM incidents AS i JOIN detections AS d ON d.id = i.detection_id
            WHERE i.simulation_only = 1
            ORDER BY i.created_at DESC, i.id DESC LIMIT 10
            """
        ).fetchall()
        recovery_rows = connection.execute(
            """
            SELECT r.id, r.asset_id, a.name AS asset_name, r.status,
                   r.requested_at, r.executed_at
            FROM recovery_actions AS r JOIN assets AS a ON a.id = r.asset_id
            WHERE r.simulation_only = 1
            ORDER BY r.created_at DESC, r.id DESC LIMIT 10
            """
        ).fetchall()

    assets_by_segment: dict[str, list[dict[str, object]]] = {}
    for row in asset_rows:
        assets_by_segment.setdefault(row["segment_id"], []).append(dict(row))
    segments = [
        {**dict(row), "assets": assets_by_segment.get(row["id"], [])}
        for row in segment_rows
    ]
    audit = verify_audit_chain(database_path)
    return {
        "ready": True,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "counts": counts,
        "segments": segments,
        "findings": [dict(row) for row in finding_rows],
        "incidents": [dict(row) for row in incident_rows],
        "recovery_actions": [dict(row) for row in recovery_rows],
        "evaluation": _evaluation_json(database_path),
        "audit": {
            "valid": audit.valid,
            "entries_checked": audit.entries_checked,
            "reason": audit.reason,
        },
    }


def _csv_cell(value: object) -> object:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _events_csv(database_path: Path) -> bytes:
    initialize_database(database_path)
    with database_session(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, run_id, scenario, sequence, source_ref, destination_ref,
                   function_code, start_address, quantity, is_valid,
                   validation_errors, raw_frame, created_at
            FROM modbus_events WHERE simulation_only = 1
            ORDER BY created_at, run_id, sequence LIMIT 5000
            """
        ).fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        (
            "event_id", "run_id", "scenario", "sequence", "source",
            "destination", "function_code", "start_address", "quantity",
            "is_valid", "validation_errors", "raw_frame_hex", "created_at",
        )
    )
    for row in rows:
        values = list(row)
        values[11] = bytes(values[11]).hex()
        writer.writerow([_csv_cell(value) for value in values])
    return output.getvalue().encode("utf-8-sig")


class _DashboardHandler(BaseHTTPRequestHandler):
    database_path: Path

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route in {"/", "/index.html"}:
            try:
                content = PAGE_PATH.read_bytes()
            except OSError:
                self._send(500, "text/plain; charset=utf-8", b"Dashboard page is missing.")
                return
            self._send(200, "text/html; charset=utf-8", content)
            return
        if route == "/api/overview":
            if not self.database_path.exists():
                payload: dict[str, object] = {"ready": False, "error": "Run project setup first."}
                self._send_json(503, payload)
                return
            try:
                self._send_json(200, _overview(self.database_path))
            except (OSError, sqlite3.Error, ValueError) as exc:
                self._send_json(503, {"ready": False, "error": str(exc)})
            return
        if route == "/reports/events.csv":
            if not self.database_path.exists():
                self._send(503, "text/plain; charset=utf-8", b"Run project setup first.")
                return
            try:
                content = _events_csv(self.database_path)
            except (OSError, sqlite3.Error) as exc:
                self._send(503, "text/plain; charset=utf-8", str(exc).encode("utf-8"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="modbus-sentinel-events.csv"')
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)
            return
        self._send(404, "text/plain; charset=utf-8", b"Not found.")

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", content)

    def _send(self, status: int, content_type: str, content: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only local Modbus Sentinel dashboard")
    parser.add_argument(
        "-c", "--config", type=Path, default=Path("config.toml"),
        help="path to TOML settings (default: config.toml)",
    )
    parser.add_argument(
        "--host", choices=("127.0.0.1",), default="127.0.0.1",
        help="loopback interface only",
    )
    parser.add_argument("--port", type=int, default=8080, help="web port (default: 8080)")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be from 1 to 65535")
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1

    handler = type(
        "ConfiguredDashboardHandler",
        (_DashboardHandler,),
        {"database_path": settings.database_path},
    )
    try:
        with HTTPServer((args.host, args.port), handler) as server:
            print(f"Dashboard is ready at http://{args.host}:{args.port}")
            print("This page reads the local simulation database. Press Ctrl+C to stop.")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("Dashboard stopped.")
    except OSError as exc:
        print(f"Could not start dashboard: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
