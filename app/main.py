
"""FastAPI application and endpoint registration for AgentShield."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import APP_VERSION
from app.agent import investigate_incident
from app.approvals import (
    create_approval,
    init_approvals,
    reject_approval,
)
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
from app.remediation import execute_remediation
from app.scenarios import (
    activate_scenario,
    execute_demo_request,
    reset_all_scenarios,
)


class ApprovalRequest(BaseModel):
    incident: str
    action: str


class RejectionRequest(BaseModel):
    approval_id: str


class ExecutionRequest(BaseModel):
    approval_id: str


def _get_db_path(request: Request) -> Path:
    return request.app.state.db_path


def create_app(db_path: Optional[Path | str] = None) -> FastAPI:
    """Create and configure the AgentShield FastAPI application."""
    configure_logging()
    initialized_db = init_db(db_path)
    init_approvals(initialized_db)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.db_path = init_db(db_path)
        init_approvals(application.state.db_path)
        yield

    application = FastAPI(
        title="AgentShield Sample Application",
        description=(
            "Incident-simulation API with a secure AI investigation agent "
            "and approval-gated remediation."
        ),
        version=APP_VERSION,
        lifespan=lifespan,
    )
    application.state.db_path = initialized_db

    @application.get(
        "/health",
        response_model=HealthResponse,
        tags=["Health"],
    )
    def health(request: Request) -> HealthResponse:
        return get_health_summary(_get_db_path(request))

    @application.get(
        "/api/status",
        response_model=ApplicationStatusResponse,
        tags=["Diagnostics"],
    )
    def api_status(request: Request) -> ApplicationStatusResponse:
        return get_application_status(_get_db_path(request))

    @application.get(
        "/api/logs",
        response_model=LogsResponse,
        tags=["Diagnostics"],
    )
    def api_logs(
        request: Request,
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        severity: Optional[str] = Query(default=None),
    ) -> LogsResponse:
        return get_logs(
            _get_db_path(request),
            limit=limit,
            offset=offset,
            severity=severity,
        )

    @application.get(
        "/api/metrics",
        response_model=MetricsResponse,
        tags=["Diagnostics"],
    )
    def api_metrics(request: Request) -> MetricsResponse:
        return get_metrics(_get_db_path(request))

    @application.get(
        "/api/database/health",
        response_model=DatabaseHealthResponse,
        tags=["Diagnostics"],
    )
    def api_database_health(request: Request) -> DatabaseHealthResponse:
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
        return get_deployments(_get_db_path(request), limit=limit)

    @application.get("/api/demo/request", tags=["Demo"])
    async def api_demo_request(request: Request) -> JSONResponse:
        status_code, payload = await execute_demo_request(
            _get_db_path(request)
        )
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
        try:
            validated_scenario = ScenarioName(scenario)
        except ValueError as exc:
            valid_values = ", ".join(item.value for item in ScenarioName)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid scenario '{scenario}'. "
                    f"Valid scenarios: {valid_values}."
                ),
            ) from exc

        return activate_scenario(
            _get_db_path(request),
            validated_scenario,
        )

    @application.post(
        "/api/investigate",
        tags=["AI Investigation"],
    )
    async def api_investigate(request: Request) -> dict:
        try:
            return await investigate_incident(
                db_path=str(_get_db_path(request))
            )
        except Exception as exc:
            logging.getLogger(__name__).exception(
                "AgentShield incident investigation failed"
            )
            raise HTTPException(
                status_code=500,
                detail=(
                    "Incident investigation failed. "
                    "Check application logs."
                ),
            ) from exc

    @application.post(
        "/api/approvals",
        tags=["Remediation"],
    )
    def api_create_approval(
        payload: ApprovalRequest,
        request: Request,
    ):
        try:
            return create_approval(
                _get_db_path(request),
                payload.incident,
                payload.action,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

    @application.post(
        "/api/approvals/reject",
        tags=["Remediation"],
    )
    def api_reject_approval(
        payload: RejectionRequest,
        request: Request,
    ):
        rejected = reject_approval(
            _get_db_path(request),
            payload.approval_id,
        )

        if not rejected:
            raise HTTPException(
                status_code=404,
                detail="Pending approval not found",
            )

        return {"status": "rejected"}

    @application.post(
        "/api/remediation/execute",
        tags=["Remediation"],
    )
    def api_execute_remediation(
        payload: ExecutionRequest,
        request: Request,
    ):
        try:
            return execute_remediation(
                _get_db_path(request),
                payload.approval_id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            logging.getLogger(__name__).exception(
                "Remediation validation failed"
            )
            raise HTTPException(
                status_code=500,
                detail="Remediation validation failed",
            ) from exc

    @application.post(
        "/api/reset",
        response_model=ResetResponse,
        tags=["Controls"],
    )
    def api_reset(request: Request) -> ResetResponse:
        return reset_all_scenarios(_get_db_path(request))

    return application


app = create_app()
