
"""Restricted AgentShield remediation action runner."""

import json
import sys

ACTIONS = {
    "restore_database": {"db_failure_active": 0},
    "clear_latency": {
        "high_latency_active": 0,
        "latency_delay_seconds": 0.0,
    },
    "clear_http_500": {"http_500_active": 0},
    "rollback_deployment": {
        "bad_deployment_active": 0,
        "active_deployment_version": "1.0.0",
        "deployment_status": "healthy",
    },
    "disable_malicious_log": {"malicious_log_active": 0},
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ACTIONS:
        print("Rejected: invalid remediation action")
        sys.exit(1)

    print(json.dumps({
        "status": "validated",
        "action": sys.argv[1],
        "patch": ACTIONS[sys.argv[1]],
    }))
