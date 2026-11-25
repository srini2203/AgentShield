"""Read-only diagnostic queries for AgentShield."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Optional

from app import APP_VERSION
from app.database import get_active_incidents_from_state, resolve_db_path
from app.logging_config import utc_now_iso
from app.models import (
    ApplicationStatusResponse,
    DatabaseHealthResponse,
    DeploymentRecord,
    DeploymentsResponse,
    HealthResponse,
    LogEntry,
    LogsResponse,
    MetricsResponse,
)


def _path_to_sqlite_uri(resolved: Path) -> str:
    """Convert an absolute Path to a SQLite URI with mode=ro and nolock=1.

    - ``mode=ro``: prevents the driver from creating a missing database file
      and opens the connection in read-only mode.
    - ``nolock=1``: skips file-level locking for the read-only connection,
      which avoids Windows deadlocks when a write connection in the same
      process already holds the file lock.  This is safe because the
      connection is strictly read-only (enforced by both mode=ro and
      PRAGMA query_only).

    Converts Windows backslashes to forward slashes and percent-encodes
    characters that are special in URIs (space, #, ?, %) as required by
    the SQLite URI filename specification (section 3.1).
    """
    # Normalise to forward slashes; sqlite3 on Windows accepts both.
    posix_path = resolved.as_posix()
    # Percent-encode characters that have special meaning in a URI path.
    _ENCODE = {" ": "%20", "#": "%23", "?": "%3F", "%": "%25"}
    for char, encoded in _ENCODE.items():
        posix_path = posix_path.replace(char, encoded)
    # Ensure the path is absolute (starts with /).
    if not posix_path.startswith("/"):
        posix_path = "/" + posix_path
    return f"file:{posix_path}?mode=ro&nolock=1"


@contextmanager
def _readonly_connection(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection in URI read-only mode (mode=ro, nolock=1).

    Uses SQLite's URI filename so:
    - ``mode=ro`` prevents the driver from creating a missing database file
      and returns ``sqlite3.OperationalError`` when the file is absent.
    - ``nolock=1`` skips file-level locking, eliminating Windows deadlocks
      when a write connection in the same process already holds the lock.
    - ``PRAGMA query_only = ON`` is applied as a defence-in-depth safeguard.

    Raises ``sqlite3.OperationalError`` if the file does not exist.
    """
    resolved = resolve_db_path(db_path)
    uri = _path_to_sqlite_uri(resolved)
    # uri=True enables the SQLite URI filename.
    conn = sqlite3.connect(uri, timeout=5.0, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON;")
        yield conn
    finally:
        conn.close()


def _fetch_state_readonly(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM app_state WHERE id = 1;").fetchone()
    if row is None:
        raise RuntimeError("Application state row is missing; database not initialized.")
    return dict(row)


def compute_overall_health(state: dict[str, Any]) -> str:
    """Compute overall application health from persisted state flags."""
    if (
        state.get("db_failure_active")
        or state.get("bad_deployment_active")
        or state.get("http_500_active")
    ):
        return "unhealthy"
    if state.get("high_latency_active") or state.get("malicious_log_active"):
        return "degraded"
    return "healthy"


def get_health_summary(db_path: Path | str) -> HealthResponse:
    """Return overall application health, UTC timestamp, and version."""
    with _readonly_connection(db_path) as conn:
        state = _fetch_state_readonly(conn)
    return HealthResponse(
        status=compute_overall_health(state),
        timestamp=utc_now_iso(),
        version=state.get("app_version", APP_VERSION),
    )


def get_application_status(db_path: Path | str) -> ApplicationStatusResponse:
    """Return active incidents, deployment status, and simulation flags."""
    with _readonly_connection(db_path) as conn:
        state = _fetch_state_readonly(conn)

    active_incidents = get_active_incidents_from_state(state)
    return ApplicationStatusResponse(
        application_status=compute_overall_health(state),
        active_incidents=active_incidents,
        deployment_status=state["deployment_status"],
        active_deployment_version=state["active_deployment_version"],
        database_simulation_status=(
            "simulated_failure" if state.get("db_failure_active") else "healthy"
        ),
        latency_simulation_active=bool(state.get("high_latency_active")),
        http_500_simulation_active=bool(state.get("http_500_active")),
        malicious_log_simulation_active=bool(state.get("malicious_log_active")),
        timestamp=utc_now_iso(),
    )


def get_logs(
    db_path: Path | str,
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
) -> LogsResponse:
    """Return paginated structured log entries ordered newest first."""
    with _readonly_connection(db_path) as conn:
        if severity:
            normalized = severity.upper()
            total = conn.execute(
                "SELECT COUNT(*) AS cnt FROM application_logs WHERE severity = ?;",
                (normalized,),
            ).fetchone()["cnt"]
            rows = conn.execute(
                """
                SELECT id, timestamp, severity, component, message, incident_id
                FROM application_logs
                WHERE severity = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?;
                """,
                (normalized, limit, offset),
            ).fetchall()
        else:
            total = conn.execute(
                "SELECT COUNT(*) AS cnt FROM application_logs;"
            ).fetchone()["cnt"]
            rows = conn.execute(
                """
                SELECT id, timestamp, severity, component, message, incident_id
                FROM application_logs
                ORDER BY id DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            ).fetchall()

    entries = [LogEntry(**dict(row)) for row in rows]
    return LogsResponse(logs=entries, total=total, limit=limit, offset=offset)


def get_metrics(db_path: Path | str) -> MetricsResponse:
    """Return aggregated request metrics from SQLite."""
    with _readonly_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_requests,
                COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0) AS successful_requests,
                COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0) AS failed_requests,
                COALESCE(AVG(duration_ms), 0.0) AS average_duration_ms,
                COALESCE(SUM(CASE WHEN status_code = 500 THEN 1 ELSE 0 END), 0) AS http_500_count
            FROM request_metrics;
            """
        ).fetchone()

    return MetricsResponse(
        total_requests=int(row["total_requests"]),
        successful_requests=int(row["successful_requests"]),
        failed_requests=int(row["failed_requests"]),
        average_duration_ms=round(float(row["average_duration_ms"]), 3),
        http_500_count=int(row["http_500_count"]),
        timestamp=utc_now_iso(),
    )


def get_database_health(db_path: Path | str) -> DatabaseHealthResponse:
    """Return actual SQLite connectivity separately from simulated failure status."""
    resolved = resolve_db_path(db_path)
    sqlite_connected = False
    sqlite_status = "error"
    simulated_failure = False
    integrity = "unknown"
    table_counts: dict[str, int] = {}

    try:
        with _readonly_connection(resolved) as conn:
            conn.execute("SELECT 1;").fetchone()
            sqlite_connected = True
            sqlite_status = "connected"

            integrity_row = conn.execute("PRAGMA quick_check;").fetchone()
            integrity = str(integrity_row[0]) if integrity_row else "unknown"

            state = _fetch_state_readonly(conn)
            simulated_failure = bool(state.get("db_failure_active"))

            for table in (
                "app_state",
                "application_logs",
                "incident_history",
                "deployment_history",
                "request_metrics",
            ):
                cnt = conn.execute(f"SELECT COUNT(*) AS cnt FROM {table};").fetchone()["cnt"]
                table_counts[table] = int(cnt)
    except sqlite3.Error as exc:
        sqlite_connected = False
        sqlite_status = f"error: {exc}"

    return DatabaseHealthResponse(
        sqlite_connected=sqlite_connected,
        sqlite_status=sqlite_status,
        simulated_failure_active=simulated_failure,
        database_path=str(resolved),
        table_counts=table_counts,
        integrity_check=integrity,
        timestamp=utc_now_iso(),
    )


def get_deployments(db_path: Path | str, limit: int = 50) -> DeploymentsResponse:
    """Return recent deployment records in chronological order."""
    with _readonly_connection(db_path) as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS cnt FROM deployment_history;"
        ).fetchone()["cnt"]
        rows = conn.execute(
            """
            SELECT id, version, status, config_summary, notes, timestamp
            FROM (
                SELECT id, version, status, config_summary, notes, timestamp
                FROM deployment_history
                ORDER BY id DESC
                LIMIT ?
            )
            ORDER BY id ASC;
            """,
            (limit,),
        ).fetchall()

    records = [DeploymentRecord(**dict(row)) for row in rows]
    return DeploymentsResponse(deployments=records, total=int(total))
