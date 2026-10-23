"""Local setup command for Modbus Sentinel."""

from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
import sys

from .audit import verify_audit_chain
from .detection import detect_run
from .detection_gaps import analyze_detection_gaps
from .evaluation import run_evaluation
from .events import record_scenario
from .incidents import create_incidents_for_run
from .inventory import seed_demo_inventory
from .response_demo import run_response_demo
from .settings import ConfigError, load_settings
from .simulation import SCENARIO_NAMES


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare the local simulation database and run sample scenarios"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="path to TOML settings (default: config.toml)",
    )
    workflow = parser.add_mutually_exclusive_group()
    workflow.add_argument(
        "--scenario",
        choices=SCENARIO_NAMES,
        help="run and evaluate one local simulation scenario",
    )
    workflow.add_argument(
        "--verify-audit",
        action="store_true",
        help="check the local audit hash chain",
    )
    workflow.add_argument(
        "--evaluate",
        action="store_true",
        help="run and score the built-in offline detection scenarios",
    )
    workflow.add_argument(
        "--gap-report",
        action="store_true",
        help="report missed, unexpected, and unevaluated detection rules",
    )
    workflow.add_argument(
        "--response-demo",
        action="store_true",
        help="run one complete containment and recovery workflow in simulation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    audit_result = None
    evaluation_result = None
    gap_result = None
    response_demo_result = None
    try:
        settings = load_settings(args.config)
        if args.verify_audit:
            if not settings.database_path.exists():
                print("audit error: local simulation database does not exist", file=sys.stderr)
                return 1
            audit_result = verify_audit_chain(settings.database_path)
        elif args.evaluate:
            evaluation_result = run_evaluation(settings.database_path)
        elif args.gap_report:
            if not settings.database_path.exists():
                print("gap report error: local simulation database does not exist", file=sys.stderr)
                return 1
            gap_result = analyze_detection_gaps(settings.database_path)
        elif args.response_demo:
            response_demo_result = run_response_demo(settings.database_path)
        else:
            seed_demo_inventory(settings.database_path)
        if args.scenario is not None:
            run_id, events = record_scenario(settings.database_path, args.scenario)
            detections = detect_run(settings.database_path, run_id)
            incidents = create_incidents_for_run(settings.database_path, run_id)
    except (ConfigError, OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 1

    if audit_result is not None:
        if audit_result.valid:
            print(
                f"Audit chain is intact: {audit_result.entries_checked} entries."
            )
            return 0
        issue = (
            f" at entry {audit_result.issue_sequence}"
            if audit_result.issue_sequence is not None
            else ""
        )
        print(
            f"Audit chain check failed{issue}: {audit_result.reason}",
            file=sys.stderr,
        )
        return 2

    if evaluation_result is not None:
        precision = (
            "not available"
            if evaluation_result.precision is None
            else f"{evaluation_result.precision:.0%}"
        )
        recall = (
            "not available"
            if evaluation_result.recall is None
            else f"{evaluation_result.recall:.0%}"
        )
        print(f"Evaluation {evaluation_result.id}: {evaluation_result.scenario_count} scenarios")
        print(
            f"Matched: {evaluation_result.true_positive_count}; "
            f"unexpected: {evaluation_result.false_positive_count}; "
            f"missed: {evaluation_result.missed_detection_count}"
        )
        print(f"Precision: {precision}; recall: {recall}")
        print("Scenarios:")
        for case in evaluation_result.cases:
            status = "matched" if not case.missed_rule_ids and not case.unexpected_rule_ids else "review"
            print(f"  {case.scenario}: {status}")
        if evaluation_result.unevaluated_rules:
            print("Not covered by these scenarios: " + ", ".join(evaluation_result.unevaluated_rules))
        return 0

    if gap_result is not None:
        print(f"Detection-gap report for evaluation {gap_result.evaluation_id}")
        if not gap_result.missed_by_scenario and not gap_result.unexpected_by_scenario:
            print("No missed or unexpected findings in the covered scenarios.")
        for scenario, rules in gap_result.missed_by_scenario.items():
            print(f"Missed in {scenario}: {', '.join(rules)}")
        for scenario, rules in gap_result.unexpected_by_scenario.items():
            print(f"Unexpected in {scenario}: {', '.join(rules)}")
        if gap_result.unevaluated_rules:
            print("Rules not yet evaluated: " + ", ".join(gap_result.unevaluated_rules))
        return 0

    if response_demo_result is not None:
        print(
            f"Local response demo {response_demo_result.run_id}: "
            f"{response_demo_result.event_count} simulated requests, 1 finding"
        )
        print(f"Finding: {response_demo_result.detection.title}")
        print(f"Incident: {response_demo_result.incident.status}")
        print(
            "Containment: "
            f"{response_demo_result.containment.status}, "
            f"verification {response_demo_result.containment_verification.result}"
        )
        print(
            "Recovery: "
            f"{response_demo_result.recovery.status}, "
            f"verification {response_demo_result.recovery_verification_result}"
        )
        print(
            f"Simulated asset {response_demo_result.asset_id}: "
            f"{response_demo_result.asset_state}"
        )
        print(f"Audit chain intact: {response_demo_result.audit.entries_checked} entries")
        return 0

    if args.scenario is not None:
        request_label = "request" if len(events) == 1 else "requests"
        detection_label = "detection" if len(detections) == 1 else "detections"
        print(
            f"Simulation run {run_id}: {len(events)} {request_label}, "
            f"{len(detections)} {detection_label}"
        )
        for detection in detections:
            print(f"[{detection.severity.upper()}] {detection.title}")
            print(f"  {detection.summary}")
            count = len(detection.evidence)
            evidence_label = "event" if count == 1 else "events"
            print(f"  Evidence: {count} {evidence_label} saved")
            incident = next(
                item for item in incidents if item.detection_id == detection.id
            )
            print(f"  Incident: {incident.status}")
            print("  Admin notification: saved to local inbox")
        return 0

    print(f"Local simulation database ready: {settings.database_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
