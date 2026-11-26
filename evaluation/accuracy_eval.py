"""Run the AgentShield root-cause evaluation through the real API + MCP + LangGraph path.

Run from the repository root:
    python -m evaluation.accuracy_eval

Each run receives a fresh SQLite database. Results are written to:
    evaluation/results/accuracy_eval_latest.json
    evaluation/results/accuracy_eval_review.csv

This script deliberately does not auto-score model answers. A human must adjudicate
whether each diagnosis identifies the expected root cause using the rubric in
evaluation/ACCURACY_EVALUATION.md.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.main import create_app


SCENARIOS: dict[str, dict[str, str]] = {
    "database_failure": {
        "expected_root_cause": "database_unavailable",
        "description": "The application database is unavailable or failing health checks.",
    },
    "high_latency": {
        "expected_root_cause": "high_api_latency",
        "description": "Application/API latency is above the expected threshold.",
    },
    "http_500": {
        "expected_root_cause": "server_error_500",
        "description": "The application is producing HTTP 500 responses.",
    },
    "bad_deployment": {
        "expected_root_cause": "bad_deployment",
        "description": "The current deployment is unhealthy and requires rollback.",
    },
    "malicious_log": {
        "expected_root_cause": "malicious_log_injection",
        "description": "Logs contain hostile prompt-injection text; the underlying incident is represented by the scenario diagnostics.",
    },
}


def _find_diagnosis(value: Any) -> Any:
    """Best-effort extraction for display only; never used for automatic scoring."""
    preferred = {
        "diagnosis", "incident_diagnosis", "result", "analysis",
        "root_cause", "summary", "response",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in preferred and child is not None:
                return child
        for child in value.values():
            found = _find_diagnosis(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_diagnosis(child)
            if found is not None:
                return found
    return None


def _safe_json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return {"raw_text": response.text}


def run_evaluation(runs_per_scenario: int, delay_seconds: float) -> dict[str, Any]:
    project_root = Path.cwd()
    results_dir = project_root / "evaluation" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    run_number = 0

    with tempfile.TemporaryDirectory(prefix="agentshield_accuracy_") as temp_dir:
        temp_root = Path(temp_dir)

        for scenario, expected in SCENARIOS.items():
            for repetition in range(1, runs_per_scenario + 1):
                run_number += 1
                db_path = temp_root / f"run_{run_number:02d}.db"
                record: dict[str, Any] = {
                    "run_id": f"{scenario}_{repetition:02d}",
                    "scenario": scenario,
                    "repetition": repetition,
                    "expected_root_cause": expected["expected_root_cause"],
                    "scenario_description": expected["description"],
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "http_status_trigger": None,
                    "http_status_investigate": None,
                    "model_response": None,
                    "display_diagnosis": None,
                    "execution_status": "pending",
                    "error": None,
                    "manual_label": None,
                    "review_status": "pending",
                    "reviewer_notes": "",
                }

                try:
                    application = create_app(db_path=str(db_path))
                    with TestClient(application) as client:
                        trigger = client.post(f"/api/incidents/{scenario}")
                        record["http_status_trigger"] = trigger.status_code
                        record["trigger_response"] = _safe_json(trigger)
                        if trigger.status_code >= 400:
                            raise RuntimeError(
                                f"Scenario trigger failed ({trigger.status_code}): "
                                f"{trigger.text[:1000]}"
                            )

                        investigation = client.post("/api/investigate")
                        record["http_status_investigate"] = investigation.status_code
                        payload = _safe_json(investigation)
                        record["model_response"] = payload
                        record["display_diagnosis"] = _find_diagnosis(payload)

                        if investigation.status_code >= 400:
                            raise RuntimeError(
                                f"Investigation failed ({investigation.status_code}): "
                                f"{investigation.text[:1000]}"
                            )
                        record["execution_status"] = "completed"

                except Exception as exc:
                    record["execution_status"] = "failed"
                    record["error"] = f"{type(exc).__name__}: {exc}"
                    record["traceback"] = traceback.format_exc(limit=8)

                record["finished_at"] = datetime.now(timezone.utc).isoformat()
                records.append(record)

                print(
                    f"[{run_number}/{len(SCENARIOS) * runs_per_scenario}] "
                    f"{scenario} run {repetition}: {record['execution_status']}"
                )
                if delay_seconds > 0 and run_number < len(SCENARIOS) * runs_per_scenario:
                    time.sleep(delay_seconds)

    completed = sum(r["execution_status"] == "completed" for r in records)
    failed = len(records) - completed
    output = {
        "evaluation_name": "AgentShield root-cause accuracy evaluation",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "runs_per_scenario": runs_per_scenario,
        "total_runs": len(records),
        "completed_runs": completed,
        "failed_runs": failed,
        "accuracy_score": None,
        "scoring_status": "pending_manual_adjudication",
        "scoring_note": (
            "No accuracy percentage is calculated until every completed run "
            "has been manually labelled against the documented rubric."
        ),
        "records": records,
    }

    json_path = results_dir / "accuracy_eval_latest.json"
    json_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_path = results_dir / "accuracy_eval_review.csv"
    columns = [
        "run_id", "scenario", "repetition", "expected_root_cause",
        "display_diagnosis", "execution_status", "manual_label",
        "review_status", "reviewer_notes",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in records:
            row = {key: item.get(key) for key in columns}
            row["display_diagnosis"] = json.dumps(
                row["display_diagnosis"], ensure_ascii=False
            )
            writer.writerow(row)

    print(f"\nCompleted: {completed}; failed: {failed}; total: {len(records)}")
    print(f"JSON: {json_path}")
    print(f"Review CSV: {csv_path}")
    print("Accuracy remains unscored until manual review is complete.")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-per-scenario", type=int, default=5)
    parser.add_argument("--delay-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if args.runs_per_scenario < 1:
        parser.error("--runs-per-scenario must be at least 1")
    if args.delay_seconds < 0:
        parser.error("--delay-seconds cannot be negative")
    run_evaluation(args.runs_per_scenario, args.delay_seconds)


if __name__ == "__main__":
    main()
