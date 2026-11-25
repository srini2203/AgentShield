"""SQLite database connection, schema initialization, and parameterized queries."""

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "agentshield.db"
BASELINE_DEPLOYMENT_VERSION = "1.0.0"


def resolve_db_path(db_path: Optional[Path | str] = None) -> Path:
    """Resolve the SQLite database path from argument, environment, or default."""
    if db_path is not None:
        return Path(db_path)
    env_path = os.environ.get("AGENTSHIELD_DB_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_connection(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection, ensure cleanup, and commit or roll back cleanly."""
    resolved = resolve_db_path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(resolved), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Path | str] = None) -> Path:
    """Create all required tables and seed initial baseline state if absent."""
    resolved = resolve_db_path(db_path)
    now = _utc_now_iso()

    with get_connection(resolved) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                app_version TEXT NOT NULL,
                db_failure_active INTEGER NOT NULL DEFAULT 0,
                high_latency_active INTEGER NOT NULL DEFAULT 0,
                latency_delay_seconds REAL NOT NULL DEFAULT 0.0,
                http_500_active INTEGER NOT NULL DEFAULT 0,
                bad_deployment_active INTEGER NOT NULL DEFAULT 0,
                malicious_log_active INTEGER NOT NULL DEFAULT 0,
                active_deployment_version TEXT NOT NULL DEFAULT '1.0.0',
                deployment_status TEXT NOT NULL DEFAULT 'healthy',
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS application_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                component TEXT NOT NULL,
                message TEXT NOT NULL,
                incident_id TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deployment_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                config_summary TEXT NOT NULL,
                notes TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS request_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                success INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )

        existing_state = conn.execute(
            "SELECT id FROM app_state WHERE id = 1;"
        ).fetchone()
        if existing_state is None:
            conn.execute(
                """
                INSERT INTO app_state (
                    id,
                    app_version,
                    db_failure_active,
                    high_latency_active,
                    latency_delay_seconds,
                    http_500_active,
                    bad_deployment_active,
                    malicious_log_active,
                    active_deployment_version,
                    deployment_status,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    1,
                    "0.1.0",
                    0,
                    0,
                    0.0,
                    0,
                    0,
                    0,
                    BASELINE_DEPLOYMENT_VERSION,
                    "healthy",
                    now,
                ),
            )

        deployment_count = conn.execute(
            "SELECT COUNT(*) AS cnt FROM deployment_history;"
        ).fetchone()["cnt"]
        if deployment_count == 0:
            conn.execute(
                """
                INSERT INTO deployment_history (
                    version,
                    status,
                    config_summary,
                    notes,
                    timestamp
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (
                    BASELINE_DEPLOYMENT_VERSION,
                    "healthy",
                    "timeout_ms=3000; pool_size=10; strict_validation=true",
                    "Initial baseline healthy deployment",
                    now,
                ),
            )

    return resolved


def get_app_state(db_path: Path | str) -> dict[str, Any]:
    """Fetch the current application state row from SQLite."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM app_state WHERE id = 1;").fetchone()
        if row is None:
            raise RuntimeError("Application state row is missing; database not initialized.")
        return dict(row)


def update_app_state(db_path: Path | str, updates: dict[str, Any]) -> dict[str, Any]:
    """Update allowed fields in app_state using parameterized SQL."""
    allowed_fields = {
        "db_failure_active",
        "high_latency_active",
        "latency_delay_seconds",
        "http_500_active",
        "bad_deployment_active",
        "malicious_log_active",
        "active_deployment_version",
        "deployment_status",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed_fields}
    if not filtered:
        return get_app_state(db_path)

    filtered["updated_at"] = _utc_now_iso()
    assignments = ", ".join(f"{col} = ?" for col in filtered)
    values = list(filtered.values())

    with get_connection(db_path) as conn:
        conn.execute(
            f"UPDATE app_state SET {assignments} WHERE id = 1;",
            values,
        )
        row = conn.execute("SELECT * FROM app_state WHERE id = 1;").fetchone()
        return dict(row)


def insert_application_log(
    db_path: Path | str,
    timestamp: str,
    severity: str,
    component: str,
    message: str,
    incident_id: Optional[str] = None,
) -> None:
    """Insert a structured log record into SQLite using parameterized SQL."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO application_logs (
                timestamp,
                severity,
                component,
                message,
                incident_id
            ) VALUES (?, ?, ?, ?, ?);
            """,
            (timestamp, severity, component, message, incident_id),
        )


def insert_incident_history(
    db_path: Path | str,
    scenario: str,
    action: str,
    details: str,
    timestamp: Optional[str] = None,
) -> None:
    """Record an incident activation or reset event in SQLite."""
    ts = timestamp or _utc_now_iso()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO incident_history (scenario, action, details, timestamp)
            VALUES (?, ?, ?, ?);
            """,
            (scenario, action, details, ts),
        )


def insert_deployment_record(
    db_path: Path | str,
    version: str,
    status: str,
    config_summary: str,
    notes: str,
    timestamp: Optional[str] = None,
) -> None:
    """Insert a deployment history record in SQLite."""
    ts = timestamp or _utc_now_iso()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO deployment_history (
                version,
                status,
                config_summary,
                notes,
                timestamp
            ) VALUES (?, ?, ?, ?, ?);
            """,
            (version, status, config_summary, notes, ts),
        )


def insert_request_metric(
    db_path: Path | str,
    endpoint: str,
    status_code: int,
    duration_ms: float,
    success: bool,
    timestamp: Optional[str] = None,
) -> None:
    """Insert a request metric observation into SQLite."""
    ts = timestamp or _utc_now_iso()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO request_metrics (
                endpoint,
                status_code,
                duration_ms,
                success,
                timestamp
            ) VALUES (?, ?, ?, ?, ?);
            """,
            (endpoint, status_code, round(duration_ms, 3), 1 if success else 0, ts),
        )


def get_active_incidents_from_state(state: dict[str, Any]) -> list[str]:
    """Derive the ordered list of active incident names from app_state."""
    incidents: list[str] = []
    if state.get("db_failure_active"):
        incidents.append("database_failure")
    if state.get("high_latency_active"):
        incidents.append("high_latency")
    if state.get("http_500_active"):
        incidents.append("http_500")
    if state.get("bad_deployment_active"):
        incidents.append("bad_deployment")
    if state.get("malicious_log_active"):
        incidents.append("malicious_log")
    return incidents
