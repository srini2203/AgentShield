"""Pydantic request and response models for AgentShield Batch 1."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ScenarioName(str, Enum):
    """Supported incident simulation scenarios."""

    DATABASE_FAILURE = "database_failure"
    HIGH_LATENCY = "high_latency"
    HTTP_500 = "http_500"
    BAD_DEPLOYMENT = "bad_deployment"
    MALICIOUS_LOG = "malicious_log"


class HealthResponse(BaseModel):
    """Response schema for GET /health."""

    status: str = Field(..., description="Overall application health: healthy, degraded, or unhealthy")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")
    version: str = Field(..., description="Application version")


class ApplicationStatusResponse(BaseModel):
    """Response schema for GET /api/status."""

    application_status: str
    active_incidents: list[str]
    deployment_status: str
    active_deployment_version: str
    database_simulation_status: str
    latency_simulation_active: bool
    http_500_simulation_active: bool
    malicious_log_simulation_active: bool
    timestamp: str


class LogEntry(BaseModel):
    """Single structured log entry returned from SQLite."""

    id: int
    timestamp: str
    severity: str
    component: str
    message: str
    incident_id: Optional[str] = None


class LogsResponse(BaseModel):
    """Response schema for GET /api/logs."""

    logs: list[LogEntry]
    total: int
    limit: int
    offset: int


class MetricsResponse(BaseModel):
    """Response schema for GET /api/metrics."""

    total_requests: int
    successful_requests: int
    failed_requests: int
    average_duration_ms: float
    http_500_count: int
    timestamp: str


class DatabaseHealthResponse(BaseModel):
    """Response schema for GET /api/database/health."""

    sqlite_connected: bool
    sqlite_status: str
    simulated_failure_active: bool
    database_path: str
    table_counts: dict[str, int]
    integrity_check: str
    timestamp: str


class DeploymentRecord(BaseModel):
    """Single deployment history record."""

    id: int
    version: str
    status: str
    config_summary: str
    notes: str
    timestamp: str


class DeploymentsResponse(BaseModel):
    """Response schema for GET /api/deployments."""

    deployments: list[DeploymentRecord]
    total: int


class DemoRequestResponse(BaseModel):
    """Response schema for GET /api/demo/request."""

    status: str
    message: str
    deployment_version: str
    deployment_status: str
    duration_ms: float
    timestamp: str
    incident: Optional[str] = None


class IncidentActionResponse(BaseModel):
    """Response schema for POST /api/incidents/{scenario}."""

    scenario: str
    activated: bool
    message: str
    active_incidents: list[str]
    timestamp: str


class ResetResponse(BaseModel):
    """Response schema for POST /api/reset."""

    status: str
    message: str
    active_incidents: list[str]
    timestamp: str
