"""Tests for the five incident scenarios, validation, persistence, and reset."""

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.main import create_app
from app.scenarios import MALICIOUS_LOG_PAYLOADS


@pytest.mark.parametrize(
    "scenario",
    [
        "database_failure",
        "high_latency",
        "http_500",
        "bad_deployment",
        "malicious_log",
    ],
)
def test_all_five_scenarios_can_be_activated(client: TestClient, scenario: str) -> None:
    """Requirement 2: All five scenarios can be activated."""
    response = client.post(f"/api/incidents/{scenario}")
    assert response.status_code == 200

    body = response.json()
    assert body["scenario"] == scenario
    assert body["activated"] is True
    assert scenario in body["active_incidents"]


def test_invalid_scenario_name_is_rejected(client: TestClient) -> None:
    """Requirement 10: Invalid scenario names are rejected."""
    response = client.post("/api/incidents/nonexistent_scenario")
    assert response.status_code == 400
    assert "Invalid scenario" in response.json()["detail"]


def test_database_failure_simulated_without_corrupting_sqlite(client: TestClient) -> None:
    """Requirement 3: Database failure is simulated without corrupting SQLite."""
    activate_resp = client.post("/api/incidents/database_failure")
    assert activate_resp.status_code == 200

    demo_resp = client.get("/api/demo/request")
    assert demo_resp.status_code == 503
    assert demo_resp.json()["incident"] == "database_failure"

    db_health = client.get("/api/database/health")
    assert db_health.status_code == 200
    db_data = db_health.json()
    assert db_data["sqlite_connected"] is True
    assert db_data["sqlite_status"] == "connected"
    assert db_data["simulated_failure_active"] is True
    assert db_data["integrity_check"] == "ok"


def test_high_latency_increases_measured_request_duration(client: TestClient) -> None:
    """Requirement 4: High latency increases measured request duration."""
    baseline_resp = client.get("/api/demo/request")
    assert baseline_resp.status_code == 200
    baseline_ms = baseline_resp.json()["duration_ms"]

    activate_resp = client.post("/api/incidents/high_latency")
    assert activate_resp.status_code == 200

    slow_resp = client.get("/api/demo/request")
    assert slow_resp.status_code == 200
    slow_data = slow_resp.json()
    assert slow_data["incident"] == "high_latency"
    assert slow_data["duration_ms"] >= 450.0
    assert slow_data["duration_ms"] > baseline_ms

    reset_resp = client.post("/api/reset")
    assert reset_resp.status_code == 200

    recovered_resp = client.get("/api/demo/request")
    assert recovered_resp.status_code == 200
    assert recovered_resp.json()["duration_ms"] < 200.0


def test_http_500_scenario_produces_http_500_response(client: TestClient) -> None:
    """Requirement 5: HTTP 500 scenario produces an HTTP 500 response."""
    activate_resp = client.post("/api/incidents/http_500")
    assert activate_resp.status_code == 200

    demo_resp = client.get("/api/demo/request")
    assert demo_resp.status_code == 500
    assert demo_resp.json()["incident"] == "http_500"

    metrics_resp = client.get("/api/metrics")
    assert metrics_resp.status_code == 200
    assert metrics_resp.json()["http_500_count"] == 1
    assert metrics_resp.json()["failed_requests"] == 1


def test_bad_deployment_makes_application_status_unhealthy(client: TestClient) -> None:
    """Requirement 6: Bad deployment makes application status unhealthy."""
    activate_resp = client.post("/api/incidents/bad_deployment")
    assert activate_resp.status_code == 200

    status_resp = client.get("/api/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["application_status"] == "unhealthy"
    assert status_data["deployment_status"] == "unhealthy"
    assert status_data["active_deployment_version"] == "1.1.0-bad"
    assert "bad_deployment" in status_data["active_incidents"]

    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "unhealthy"


def test_malicious_log_payload_stored_as_inert_text(client: TestClient) -> None:
    """Requirement 7: Malicious log payload is stored as inert text."""
    activate_resp = client.post("/api/incidents/malicious_log")
    assert activate_resp.status_code == 200

    logs_resp = client.get("/api/logs", params={"limit": 50})
    assert logs_resp.status_code == 200
    logs_data = logs_resp.json()

    stored_messages = {entry["message"] for entry in logs_data["logs"]}
    for expected_severity, payload in MALICIOUS_LOG_PAYLOADS:
        assert payload in stored_messages
        matching = [entry for entry in logs_data["logs"] if entry["message"] == payload]
        assert matching[0]["severity"] == expected_severity
        assert matching[0]["incident_id"] == "malicious_log"

    # Verify hostile SQL/override payloads did not corrupt application state or tables
    status_resp = client.get("/api/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["deployment_status"] == "healthy"
    assert status_resp.json()["database_simulation_status"] == "healthy"


def test_reset_restores_healthy_application_behavior(client: TestClient) -> None:
    """Requirement 8: Reset restores healthy application behavior."""
    for scenario in (
        "database_failure",
        "high_latency",
        "http_500",
        "bad_deployment",
        "malicious_log",
    ):
        assert client.post(f"/api/incidents/{scenario}").status_code == 200

    reset_resp = client.post("/api/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["active_incidents"] == []

    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    status_resp = client.get("/api/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["application_status"] == "healthy"
    assert status_data["deployment_status"] == "healthy"
    assert status_data["active_deployment_version"] == "1.0.0"
    assert status_data["database_simulation_status"] == "healthy"

    demo_resp = client.get("/api/demo/request")
    assert demo_resp.status_code == 200


def test_incident_state_persists_across_app_restart(temp_db_path: Path) -> None:
    """Application state persisted in SQLite survives app recreation."""
    app_one = create_app(db_path=temp_db_path)
    with TestClient(app_one) as client_one:
        assert client_one.post("/api/incidents/http_500").status_code == 200

    app_two = create_app(db_path=temp_db_path)
    with TestClient(app_two) as client_two:
        status_resp = client_two.get("/api/status")
        assert status_resp.status_code == 200
        assert "http_500" in status_resp.json()["active_incidents"]
        assert client_two.get("/api/demo/request").status_code == 500
