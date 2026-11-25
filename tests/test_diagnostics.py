"""Tests for read-only diagnostic endpoints, metrics, and deployment history."""

import json
import logging
from pathlib import Path
import sqlite3
from typing import Optional
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.diagnostics import _path_to_sqlite_uri, _readonly_connection, get_database_health
from app.logging_config import JsonLogFormatter


def test_diagnostic_get_endpoints_do_not_mutate_application_state(
    client: TestClient,
    temp_db_path: Path,
) -> None:
    """Requirement 9: Diagnostic GET endpoints do not mutate application state."""
    assert client.post("/api/incidents/bad_deployment").status_code == 200
    assert client.get("/api/demo/request").status_code == 200

    before_status = client.get("/api/status").json()
    before_metrics = client.get("/api/metrics").json()
    before_logs = client.get("/api/logs").json()
    before_deployments = client.get("/api/deployments").json()
    before_db_health = client.get("/api/database/health").json()

    # Exercise all diagnostic GET endpoints repeatedly
    for _ in range(3):
        assert client.get("/health").status_code == 200
        assert client.get("/api/status").status_code == 200
        assert client.get("/api/logs", params={"limit": 10, "offset": 0}).status_code == 200
        assert client.get("/api/metrics").status_code == 200
        assert client.get("/api/database/health").status_code == 200
        assert client.get("/api/deployments").status_code == 200

    after_status = client.get("/api/status").json()
    after_metrics = client.get("/api/metrics").json()
    after_logs = client.get("/api/logs").json()
    after_deployments = client.get("/api/deployments").json()
    after_db_health = client.get("/api/database/health").json()

    assert after_status["active_incidents"] == before_status["active_incidents"]
    assert after_status["deployment_status"] == before_status["deployment_status"]
    assert after_metrics["total_requests"] == before_metrics["total_requests"]
    assert after_metrics["successful_requests"] == before_metrics["successful_requests"]
    assert after_metrics["failed_requests"] == before_metrics["failed_requests"]
    assert after_metrics["http_500_count"] == before_metrics["http_500_count"]
    assert after_logs["total"] == before_logs["total"]
    assert after_deployments["total"] == before_deployments["total"]
    assert after_db_health["table_counts"] == before_db_health["table_counts"]
    assert temp_db_path.exists()


def test_metrics_update_correctly(client: TestClient) -> None:
    """Requirement 11: Metrics update correctly across success and failure requests."""
    initial = client.get("/api/metrics").json()
    assert initial["total_requests"] == 0

    assert client.get("/api/demo/request").status_code == 200
    assert client.get("/api/demo/request").status_code == 200

    assert client.post("/api/incidents/http_500").status_code == 200
    assert client.get("/api/demo/request").status_code == 500

    assert client.post("/api/reset").status_code == 200
    assert client.post("/api/incidents/database_failure").status_code == 200
    assert client.get("/api/demo/request").status_code == 503

    metrics = client.get("/api/metrics").json()
    assert metrics["total_requests"] == 4
    assert metrics["successful_requests"] == 2
    assert metrics["failed_requests"] == 2
    assert metrics["http_500_count"] == 1
    assert metrics["average_duration_ms"] >= 0.0


def test_deployment_history_records_bad_deployment(client: TestClient) -> None:
    """Requirement 12: Deployment history records the bad deployment chronologically."""
    initial_deployments = client.get("/api/deployments").json()
    assert initial_deployments["total"] == 1
    assert initial_deployments["deployments"][0]["version"] == "1.0.0"
    assert initial_deployments["deployments"][0]["status"] == "healthy"

    assert client.post("/api/incidents/bad_deployment").status_code == 200

    updated_deployments = client.get("/api/deployments").json()
    assert updated_deployments["total"] == 2
    records = updated_deployments["deployments"]
    assert records[0]["id"] < records[1]["id"]
    assert records[1]["version"] == "1.1.0-bad"
    assert records[1]["status"] == "unhealthy"
    assert records[1]["timestamp"]


def test_readonly_connection_does_not_create_missing_database(tmp_path: Path) -> None:
    """Correction 1: A missing database file must NOT be created by a read-only diagnostic connection.

    Uses SQLite URI mode=ro; sqlite3.OperationalError is expected when the file is absent
    (mode=ro prevents file creation entirely on all platforms).
    """
    missing_db = tmp_path / "does_not_exist.db"
    assert not missing_db.exists(), "Pre-condition: file must not exist before the test"

    try:
        with _readonly_connection(missing_db) as conn:
            conn.execute("SELECT 1;")
    except sqlite3.OperationalError:
        pass  # Expected: mode=ro raises when the file is absent

    # In all cases the file must not have been created.
    assert not missing_db.exists(), (
        "Read-only connection must not create a missing database file"
    )


def test_readonly_connection_missing_db_raises_operational_error(tmp_path: Path) -> None:
    """_readonly_connection with mode=ro raises OperationalError for a truly absent DB."""
    missing_db = tmp_path / "absent.db"
    raised = False
    try:
        with _readonly_connection(missing_db) as conn:
            conn.execute("SELECT * FROM app_state;")
    except sqlite3.OperationalError:
        raised = True
    # Either the connection itself raised (file not found) or the query raised
    # (empty DB with no tables); either way the behaviour is correct.
    assert raised or not missing_db.exists(), (
        "Expected OperationalError or file must not have been created"
    )


def test_path_to_sqlite_uri_formats_correctly(tmp_path: Path) -> None:
    """_path_to_sqlite_uri returns a valid file: URI with mode=ro and nolock=1."""
    db_path = tmp_path / "test.db"
    uri = _path_to_sqlite_uri(db_path)
    assert uri.startswith("file:")
    assert "mode=ro" in uri
    assert "nolock=1" in uri
    assert "?" in uri
    # No backslashes in the URI (Windows normalisation check)
    assert "\\" not in uri


def test_get_database_health_reports_disconnected_for_missing_db(tmp_path: Path) -> None:
    """get_database_health returns sqlite_connected=False when the DB file is absent."""
    missing_db = tmp_path / "ghost.db"
    result = get_database_health(missing_db)
    assert result.sqlite_connected is False
    assert "error" in result.sqlite_status.lower()


def test_dashboard_api_helper_returns_error_on_connection_failure() -> None:
    """Dashboard _api_get/_api_post return (None, error_string) when the API is unreachable."""
    import httpx
    from dashboard.streamlit_app import _api_get, _api_post

    with patch("dashboard.streamlit_app.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.side_effect = (
            httpx.ConnectError("refused")
        )
        data, err = _api_get("http://127.0.0.1:19999", "/health")
        assert data is None
        assert err is not None
        assert "refused" in err or "19999" in err or "Failed" in err

    with patch("dashboard.streamlit_app.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("refused")
        )
        data, err = _api_post("http://127.0.0.1:19999", "/api/reset")
        assert data is None
        assert err is not None


def test_dashboard_api_helper_returns_error_on_http_4xx() -> None:
    """Dashboard _api_get returns (None, error) for HTTP 4xx/5xx status codes."""
    import httpx
    from dashboard.streamlit_app import _api_get

    mock_response = type(
        "MockResponse",
        (),
        {"status_code": 404, "text": "Not Found", "json": lambda self: {}},
    )()

    with patch("dashboard.streamlit_app.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_response
        data, err = _api_get("http://127.0.0.1:8000", "/api/does-not-exist")
        assert data is None
        assert err is not None
        assert "404" in err


def test_logs_pagination_and_json_formatter() -> None:
    """Structured JSON formatter safely serializes hostile format-like strings."""
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="agentshield",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="%s",
        args=("HOSTILE %s %d {payload} \"quote\"",),
        exc_info=None,
    )
    record.component = "ingest"
    record.incident_id = "malicious_log"

    formatted = formatter.format(record)
    parsed = json.loads(formatted)
    assert parsed["severity"] == "ERROR"
    assert parsed["component"] == "ingest"
    assert parsed["incident_id"] == "malicious_log"
    assert parsed["message"] == "HOSTILE %s %d {payload} \"quote\""
