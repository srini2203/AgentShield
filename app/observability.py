
"""Persistent observability for AgentShield AI investigations."""

import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def init_investigation_metrics(db_path: Path | str) -> None:
    """Create the investigation metrics table if it does not exist."""

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path, timeout=10.0) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL
                    CHECK(status IN ('success', 'failure')),
                duration_ms REAL NOT NULL,
                model TEXT,
                input_tokens INTEGER,
                output_tokens INTEGER,
                total_tokens INTEGER,
                error_type TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_investigation_metrics_timestamp
            ON investigation_metrics(timestamp)
            """
        )


def record_investigation(
    db_path: Path | str,
    *,
    status: str,
    duration_ms: float,
    model: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
    error_type: Optional[str] = None,
) -> None:
    """Persist one investigation result without storing its evidence."""

    if status not in {"success", "failure"}:
        raise ValueError("Invalid investigation status.")

    if not math.isfinite(duration_ms) or duration_ms < 0:
        raise ValueError("Invalid investigation duration.")

    with sqlite3.connect(db_path, timeout=10.0) as conn:
        conn.execute(
            """
            INSERT INTO investigation_metrics (
                status,
                duration_ms,
                model,
                input_tokens,
                output_tokens,
                total_tokens,
                error_type,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                status,
                duration_ms,
                model,
                input_tokens,
                output_tokens,
                total_tokens,
                error_type,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def get_investigation_metrics(
    db_path: Path | str,
) -> dict:
    """Return aggregate investigation metrics and recent records."""

    with sqlite3.connect(db_path, timeout=5.0) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT
                status,
                duration_ms,
                model,
                input_tokens,
                output_tokens,
                total_tokens,
                error_type,
                timestamp
            FROM investigation_metrics
            ORDER BY id DESC
            """
        ).fetchall()

    records = [dict(row) for row in rows]
    durations = [row["duration_ms"] for row in records]

    total = len(records)
    successful = sum(
        row["status"] == "success" for row in records
    )
    failed = total - successful

    sorted_durations = sorted(durations)

    p95 = None
    if sorted_durations:
        p95_index = max(
            0,
            math.ceil(0.95 * len(sorted_durations)) - 1,
        )
        p95 = sorted_durations[p95_index]

    token_records = [
        row for row in records
        if any(
            row[field] is not None
            for field in (
                "input_tokens",
                "output_tokens",
                "total_tokens",
            )
        )
    ]

    def token_sum(field: str):
        values = [
            row[field]
            for row in token_records
            if row[field] is not None
        ]
        return sum(values) if values else None

    return {
        "total_investigations": total,
        "successful_investigations": successful,
        "failed_investigations": failed,
        "success_rate": (
            successful / total if total else None
        ),
        "average_duration_ms": (
            sum(durations) / total if total else None
        ),
        "p95_duration_ms": p95,
        "token_usage_records": len(token_records),
        "total_input_tokens": token_sum("input_tokens"),
        "total_output_tokens": token_sum("output_tokens"),
        "total_tokens": token_sum("total_tokens"),
        "recent_investigations": records[:20],
    }
