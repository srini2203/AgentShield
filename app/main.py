"""FastAPI application and endpoint registration for AgentShield Batch 1."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app import APP_VERSION
from app.database import init_db
from app.diagnostics import (
    get_application_status,
    get_database_health,
    get_deployments,
    get_health_summary,
    get_logs,
    get_metrics,
)
from app.logging_config import configure_logging
from app.models import (
    ApplicationStatusResponse,
    DatabaseHealthResponse,
    DeploymentsResponse,
    HealthResponse,
    IncidentActionResponse,
    LogsResponse,
    MetricsResponse,
    ResetResponse,
    ScenarioName,
)
from app.scenarios import activate_scenario, execute_demo_request, reset_all_scenarios


def _get_db_path(request: Request) -> Path:
    return request.app.state.db_path


def create_app(db_path: Optional[Path | str] = None) -> FastAPI:
    """Create and configure the AgentShield FastAPI application."""
    configure_logging()
    initialized_db = init_db(db_path)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.db_path = init_db(db_path)
        yield

    application = FastAPI(
        title="AgentShield Sample Application",
        description="Batch 1 reproducible incident-simulation API for AgentShield.",
        version=APP_VERSION,
        lifespan=lifespan,
    )
    application.state.db_path = initialized_db

    @application.get("/health", response_model=HealthResponse, tags=["Health"])
    def health(request: Request) -> HealthResponse:
        """Read-only overall application health check."""
        return get_health_summary(_get_db_path(request))

    @application.get(
        "/api/status",
        response_model=ApplicationStatusResponse,
        tags=["Diagnostics"],
    )
    def api_status(request: Request) -> ApplicationStatusResponse:
        """Read-only application, deployment, and active incident status."""
        return get_application_status(_get_db_path(request))

    @application.get("/api/logs", response_model=LogsResponse, tags=["Diagnostics"])
    def api_logs(
        request: Request,
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        severity: Optional[str] = Query(default=None),
    ) -> LogsResponse:
        """Read-only paginated structured application logs."""
        return get_logs(
            _get_db_path(request),
            limit=limit,
            offset=offset,
            severity=severity,
        )

    @application.get("/api/metrics", response_model=MetricsResponse, tags=["Diagnostics"])
    def api_metrics(request: Request) -> MetricsResponse:
        """Read-only request metrics summary."""
        return get_metrics(_get_db_path(request))

    @application.get(
        "/api/database/health",
        response_model=DatabaseHealthResponse,
        tags=["Diagnostics"],
    )
    def api_database_health(request: Request) -> DatabaseHealthResponse:
        """Read-only SQLite connectivity and simulated database failure status."""
        return get_database_health(_get_db_path(request))

    @application.get(
        "/api/deployments",
        response_model=DeploymentsResponse,
        tags=["Diagnostics"],
    )
    def api_deployments(
        request: Request,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DeploymentsResponse:
        """Read-only deployment history in chronological order."""
        return get_deployments(_get_db_path(request), limit=limit)

    @application.get("/api/demo/request", tags=["Demo"])
    async def api_demo_request(request: Request) -> JSONResponse:
        """Simulated application endpoint demonstrating active incident behavior."""
        status_code, payload = await execute_demo_request(_get_db_path(request))
        return JSONResponse(status_code=status_code, content=payload)

    @application.post(
        "/api/incidents/{scenario}",
        response_model=IncidentActionResponse,
        tags=["Controls"],
    )
    def api_activate_incident(
        scenario: str,
        request: Request,
    ) -> IncidentActionResponse:
        """Activate one of the five predefined incident scenarios."""
        try:
            validated_scenario = ScenarioName(scenario)
        except ValueError as exc:
            valid_values = ", ".join(item.value for item in ScenarioName)
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scenario '{scenario}'. Valid scenarios: {valid_values}.",
            ) from exc

        return activate_scenario(_get_db_path(request), validated_scenario)

    @application.post("/api/reset", response_model=ResetResponse, tags=["Controls"])
    def api_reset(request: Request) -> ResetResponse:
        """Reset all simulation flags and restore healthy application state."""
        return reset_all_scenarios(_get_db_path(request))

    return application


app = create_app()
