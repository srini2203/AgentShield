"""Tests for application health and baseline status."""

from datetime import datetime

from fastapi.testclient import TestClient


def test_healthy_application_returns_successful_health_check(client: TestClient) -> None:
    """Requirement 1: Healthy application returns successful health check."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    # Verify timestamp is a valid UTC ISO-8601 timestamp
    parsed_ts = datetime.fromisoformat(data["timestamp"])
    assert parsed_ts.tzinfo is not None


def test_initial_application_status_is_healthy(client: TestClient) -> None:
    """Initial /api/status reflects clean baseline state."""
    response = client.get("/api/status")
    assert response.status_code == 200

    data = response.json()
    assert data["application_status"] == "healthy"
    assert data["active_incidents"] == []
    assert data["deployment_status"] == "healthy"
    assert data["active_deployment_version"] == "1.0.0"
    assert data["database_simulation_status"] == "healthy"
