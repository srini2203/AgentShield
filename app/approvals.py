
"""Minimal persistent, single-use approval management."""

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

APPROVAL_TTL_MINUTES = 5

ALLOWED_ACTIONS = {
    "database_failure": "restore_database",
    "high_latency": "clear_latency",
    "http_500": "clear_http_500",
    "bad_deployment": "rollback_deployment",
    "malicious_log": "disable_malicious_log",
}


def _now():
    return datetime.now(timezone.utc)


def _connect(db_path):
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_approvals(db_path):
    with _connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS remediation_approvals (
                id TEXT PRIMARY KEY,
                incident TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def create_approval(db_path, incident, action):
    if ALLOWED_ACTIONS.get(incident) != action:
        raise ValueError("Incident/action combination is not allowed")

    init_approvals(db_path)

    now = _now()
    approval_id = str(uuid.uuid4())
    expires = now + timedelta(minutes=APPROVAL_TTL_MINUTES)

    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO remediation_approvals
               VALUES (?, ?, ?, 'pending', ?, ?)""",
            (
                approval_id,
                incident,
                action,
                expires.isoformat(),
                now.isoformat(),
            ),
        )

    return {
        "approval_id": approval_id,
        "incident": incident,
        "action": action,
        "status": "pending",
        "expires_at": expires.isoformat(),
    }


def reject_approval(db_path, approval_id):
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """UPDATE remediation_approvals
               SET status = 'rejected'
               WHERE id = ? AND status = 'pending'""",
            (approval_id,),
        )
        return cursor.rowcount == 1


def consume_approval(db_path, approval_id):
    """Atomically consume a valid approval exactly once.

    Expired approvals are committed as expired before raising an error.
    """
    expired = False
    approval = None

    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT * FROM remediation_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()

        if row is None or row["status"] != "pending":
            raise ValueError(
                "Approval is missing, rejected, or already used"
            )

        expires_at = datetime.fromisoformat(row["expires_at"])

        if _now() >= expires_at:
            conn.execute(
                """UPDATE remediation_approvals
                   SET status = 'expired'
                   WHERE id = ? AND status = 'pending'""",
                (approval_id,),
            )
            expired = True
        else:
            cursor = conn.execute(
                """UPDATE remediation_approvals
                   SET status = 'used'
                   WHERE id = ? AND status = 'pending'""",
                (approval_id,),
            )

            if cursor.rowcount != 1:
                raise ValueError("Approval could not be consumed")

            approval = {
                "approval_id": row["id"],
                "incident": row["incident"],
                "action": row["action"],
            }

    # Raise only after the transaction has committed.
    if expired:
        raise ValueError("Approval has expired")

    return approval
