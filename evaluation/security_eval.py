
"""Live prompt-injection evaluation for AgentShield."""

import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from app.agent import analyze_evidence
from app.scenarios import MALICIOUS_LOG_PAYLOADS


def build_test_diagnostics(severity, payload):
    """Create controlled database-failure evidence containing one attack."""

    return {
        "logs": {
            "total": 2,
            "logs": [
                {
                    "severity": "ERROR",
                    "component": "database",
                    "message": (
                        "Database connection refused. "
                        "Simulated database outage is active."
                    ),
                    "incident_id": "database_failure",
                },
                {
                    "severity": severity,
                    "component": "ingest",
                    "message": payload,
                    "incident_id": "malicious_log",
                },
            ],
        },
        "metrics": {
            "total_requests": 10,
            "failed_requests": 8,
            "success_rate": 0.2,
        },
        "database_health": {
            "status": "simulated_failure",
            "healthy": False,
        },
        "deployments": {
            "deployments": [
                {
                    "version": "1.0.0",
                    "status": "healthy",
                }
            ],
        },
    }


async def evaluate_payload(index, severity, payload):
    """Run one payload through the actual AgentShield analysis node."""

    diagnostics = build_test_diagnostics(severity, payload)
    started = time.perf_counter()

    try:
        result = await analyze_evidence({
            "diagnostics": diagnostics,
        })

        duration = time.perf_counter() - started

        return {
            "case": index,
            "severity": severity,
            "payload": payload,
            "status": "completed",
            "duration_seconds": round(duration, 3),
            "diagnosis": result["diagnosis"],
            "manual_review_required": True,
        }

    except Exception as exc:
        duration = time.perf_counter() - started

        return {
            "case": index,
            "severity": severity,
            "payload": payload,
            "status": "error",
            "duration_seconds": round(duration, 3),
            "error": str(exc),
            "manual_review_required": True,
        }


async def main(limit):
    """Execute the selected evaluation cases sequentially."""

    results = []

    print(f"\nAgentShield Security Evaluation")
    print(f"Payloads selected: {limit}")
    print("Mode: Live Gemini analysis")
    print("-" * 45)

    for index, (severity, payload) in enumerate(
        MALICIOUS_LOG_PAYLOADS[:limit],
        start=1,
    ):
        print(f"[{index}/{limit}] Testing payload...")

        result = await evaluate_payload(
            index,
            severity,
            payload,
        )

        results.append(result)
        await asyncio.sleep(5)

        if result["status"] == "completed":
            print(
                f"Completed in "
                f"{result['duration_seconds']} seconds"
            )
        else:
            print(f"ERROR: {result['error']}")

    completed = sum(
        item["status"] == "completed"
        for item in results
    )

    report = {
        "evaluation": "AgentShield prompt-injection evaluation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": "gemini-3.5-flash-lite",
        "total_cases": limit,
        "completed_cases": completed,
        "failed_cases": limit - completed,
        "attack_success_rate": None,
        "note": (
            "Attack success rate requires manual review of model "
            "responses against predefined criteria. It is not "
            "automatically inferred."
        ),
        "results": results,
    }

    output_dir = Path("evaluation/results")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "security_eval_latest.json"

    output_file.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("-" * 45)
    print(f"Completed: {completed}/{limit}")
    print(f"Report saved: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Number of payloads to evaluate (1-30).",
    )

    args = parser.parse_args()

    if not 1 <= args.limit <= len(MALICIOUS_LOG_PAYLOADS):
        parser.error("Limit must be between 1 and 30.")

    asyncio.run(main(args.limit))
