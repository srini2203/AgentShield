
"""Approval-gated, Docker-validated remediation."""

import json
import subprocess

from app.approvals import consume_approval
from app.database import (
    BASELINE_DEPLOYMENT_VERSION,
    insert_deployment_record,
    update_app_state,
)
from app.logging_config import utc_now_iso

SANDBOX_IMAGE = "agentshield-sandbox"

ALLOWED_PATCHES = {
    "restore_database": {"db_failure_active": 0},
    "clear_latency": {
        "high_latency_active": 0,
        "latency_delay_seconds": 0.0,
    },
    "clear_http_500": {"http_500_active": 0},
    "rollback_deployment": {
        "bad_deployment_active": 0,
        "active_deployment_version": BASELINE_DEPLOYMENT_VERSION,
        "deployment_status": "healthy",
    },
    "disable_malicious_log": {"malicious_log_active": 0},
}


def execute_remediation(db_path, approval_id):
    approval = consume_approval(db_path, approval_id)
    action = approval["action"]

    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--memory", "128m",
            "--cpus", "0.5",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            SANDBOX_IMAGE,
            action,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError("Sandbox rejected remediation")

    output = json.loads(result.stdout)
    expected_patch = ALLOWED_PATCHES[action]

    if (
        output.get("status") != "validated"
        or output.get("action") != action
        or output.get("patch") != expected_patch
    ):
        raise RuntimeError("Invalid sandbox response")

    # Only trusted host-side code can modify application state.
    state = update_app_state(db_path, expected_patch)

    if action == "rollback_deployment":
        now = utc_now_iso()
        insert_deployment_record(
            db_path=db_path,
            version=BASELINE_DEPLOYMENT_VERSION,
            status="healthy",
            config_summary=(
                "timeout_ms=3000; pool_size=10; strict_validation=true"
            ),
            notes="Approved AgentShield remediation rollback",
            timestamp=now,
        )

    return {
        "status": "remediated",
        "incident": approval["incident"],
        "action": action,
        "active_incidents": [
            name for name, flag in [
                ("database_failure", "db_failure_active"),
                ("high_latency", "high_latency_active"),
                ("http_500", "http_500_active"),
                ("bad_deployment", "bad_deployment_active"),
                ("malicious_log", "malicious_log_active"),
            ]
            if state.get(flag)
        ],
        "message": "Approved remediation applied. Verify application health.",
    }
