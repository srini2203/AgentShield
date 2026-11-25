
"""Automated tests for persistent, single-use remediation approvals."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from app.approvals import (
    create_approval,
    consume_approval,
    reject_approval,
    init_approvals
)


def get_status(db_path, approval_id):
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM remediation_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()

    return row[0] if row else None


def test_create_valid_approval(tmp_path):
    db_path = tmp_path / "approvals.db"

    approval = create_approval(
        db_path, "database_failure", "restore_database"
    )

    assert approval["status"] == "pending"
    assert approval["incident"] == "database_failure"
    assert approval["action"] == "restore_database"
    assert approval["approval_id"]
    assert get_status(db_path, approval["approval_id"]) == "pending"


def test_reject_invalid_incident_action_pair(tmp_path):
    db_path = tmp_path / "approvals.db"

    with pytest.raises(ValueError, match="not allowed"):
        create_approval(
            db_path, "database_failure", "rollback_deployment"
        )


def test_rejected_approval_cannot_be_consumed(tmp_path):
    db_path = tmp_path / "approvals.db"

    approval = create_approval(
        db_path, "malicious_log", "disable_malicious_log"
    )

    assert reject_approval(db_path, approval["approval_id"]) is True
    assert get_status(db_path, approval["approval_id"]) == "rejected"

    with pytest.raises(ValueError, match="missing, rejected, or already used"):
        consume_approval(db_path, approval["approval_id"])


def test_approval_can_only_be_consumed_once(tmp_path):
    db_path = tmp_path / "approvals.db"

    approval = create_approval(
        db_path, "high_latency", "clear_latency"
    )

    result = consume_approval(db_path, approval["approval_id"])

    assert result["incident"] == "high_latency"
    assert result["action"] == "clear_latency"
    assert get_status(db_path, approval["approval_id"]) == "used"

    with pytest.raises(ValueError, match="missing, rejected, or already used"):
        consume_approval(db_path, approval["approval_id"])


def test_expired_approval_is_persisted(tmp_path):
    db_path = tmp_path / "approvals.db"

    approval = create_approval(
        db_path, "http_500", "clear_http_500"
    )

    expired_time = (
        datetime.now(timezone.utc) - timedelta(minutes=10)
    ).isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """UPDATE remediation_approvals
               SET expires_at = ?
               WHERE id = ?""",
            (expired_time, approval["approval_id"]),
        )

    with pytest.raises(ValueError, match="expired"):
        consume_approval(db_path, approval["approval_id"])

    assert get_status(db_path, approval["approval_id"]) == "expired"


def test_unknown_approval_cannot_be_consumed(tmp_path):
    db_path = tmp_path / "approvals.db"
    init_approvals(db_path)

    with pytest.raises(
        ValueError,
        match="missing, rejected, or already used",
    ):
        consume_approval(db_path, "unknown-approval-id")


def test_concurrent_consumption_allows_only_one_success(tmp_path):
    db_path = tmp_path / "approvals.db"

    approval = create_approval(
        db_path, "bad_deployment", "rollback_deployment"
    )

    approval_id = approval["approval_id"]

    def attempt_consumption():
        try:
            consume_approval(db_path, approval_id)
            return "success"
        except ValueError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(
            lambda _: attempt_consumption(),
            range(2),
        ))

    assert results.count("success") == 1
    assert results.count("rejected") == 1
    assert get_status(db_path, approval_id) == "used"
