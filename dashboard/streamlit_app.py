
"""AgentShield Security Operations Center dashboard."""

import json
import os
import sys
import sqlite3
from pathlib import Path
from typing import Any, Optional

import httpx
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import resolve_db_path

from app.database import resolve_db_path

DEFAULT_API_BASE_URL = os.environ.get(
    "AGENTSHIELD_API_URL",
    "http://127.0.0.1:8000",
)

SCENARIOS = [
    ("database_failure", "Database Failure", "Simulate a database outage."),
    ("high_latency", "High API Latency", "Inject artificial request delay."),
    ("http_500", "HTTP 500 Errors", "Simulate internal server errors."),
    ("bad_deployment", "Bad Deployment", "Deploy an unhealthy configuration."),
    ("malicious_log", "Malicious Log Injection", "Insert hostile strings as inert logs."),
]

EVALUATION_FILE = (
    Path(__file__).resolve().parent.parent
    / "evaluation"
    / "results"
    / "security_eval_latest.json"
)


def _api_get(
    base_url: str,
    path: str,
    params: Optional[dict[str, Any]] = None,
):
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(
                f"{base_url.rstrip('/')}{path}",
                params=params,
            )

        if response.status_code >= 400:
            return None, f"GET {path}: HTTP {response.status_code} - {response.text}"

        return response.json(), None

    except httpx.HTTPError as exc:
        return None, str(exc)


def _api_post(
    base_url: str,
    path: str,
    timeout: float = 5.0,
):
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(f"{base_url.rstrip('/')}{path}")

        if response.status_code >= 400:
            return None, f"POST {path}: HTTP {response.status_code} - {response.text}"

        return response.json(), None

    except httpx.HTTPError as exc:
        return None, str(exc)


def _read_local_observability():
    """Read approval and incident history without modifying SQLite."""

    db_path = resolve_db_path()

    if not db_path.exists():
        return None, "Application database not found."

    try:
        uri = f"{db_path.resolve().as_uri()}?mode=ro"

        with sqlite3.connect(uri, uri=True, timeout=5.0) as conn:
            conn.row_factory = sqlite3.Row

            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }

            approval_stats = {}
            approval_history = []
            incident_history = []

            if "remediation_approvals" in tables:
                rows = conn.execute(
                    """
                    SELECT status, COUNT(*) AS total
                    FROM remediation_approvals
                    GROUP BY status
                    """
                ).fetchall()

                approval_stats = {
                    row["status"]: row["total"]
                    for row in rows
                }

                approval_history = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT incident, action, status, created_at, expires_at
                        FROM remediation_approvals
                        ORDER BY created_at DESC
                        LIMIT 15
                        """
                    ).fetchall()
                ]

            if "incident_history" in tables:
                incident_history = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT scenario, action, details, timestamp
                        FROM incident_history
                        ORDER BY id DESC
                        LIMIT 15
                        """
                    ).fetchall()
                ]

        return {
            "approval_stats": approval_stats,
            "approval_history": approval_history,
            "incident_history": incident_history,
            "database_path": str(db_path),
        }, None

    except (sqlite3.Error, OSError, ValueError) as exc:
        return None, f"Could not read local observability data: {exc}"


def _read_security_evaluation():
    """Read the most recently saved security evaluation report."""

    if not EVALUATION_FILE.exists():
        return None

    try:
        return json.loads(EVALUATION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _render_diagnosis(result: dict[str, Any]):
    diagnosis = result.get("diagnosis", {})

    if not diagnosis:
        st.warning("No diagnosis returned.")
        return

    st.subheader("AI Investigation Results")

    severity = str(diagnosis.get("severity", "UNKNOWN")).upper()

    if severity in {"HIGH", "CRITICAL"}:
        st.error(f"Severity: {severity}")
    elif severity == "MEDIUM":
        st.warning(f"Severity: {severity}")
    else:
        st.success(f"Severity: {severity}")

    st.markdown("**Incident Summary**")
    st.write(diagnosis.get("incident_summary", "Not available"))

    st.markdown("**Root Cause**")
    st.write(diagnosis.get("root_cause", "Not available"))

    st.markdown("**Supporting Evidence**")
    evidence = diagnosis.get("evidence", [])

    if evidence:
        for item in evidence:
            st.markdown(f"- {item}")
    else:
        st.info("No supporting evidence provided.")

    confidence = diagnosis.get("confidence")

    if isinstance(confidence, (int, float)):
        st.metric("Model-reported Confidence", f"{confidence:.0%}")

    st.markdown("**Proposed Fix**")
    st.info(diagnosis.get("proposed_fix", "No proposed fix available."))

    limitations = diagnosis.get("limitations", [])

    if limitations:
        st.markdown("**Investigation Limitations**")
        for item in limitations:
            st.markdown(f"- {item}")

    with st.expander("View Raw Diagnostic Evidence"):
        st.json(result.get("diagnostics", {}))


def _render_overview(health_data, status_data):
    st.subheader("Operational Overview")

    active = status_data.get("active_incidents", [])

    cols = st.columns(4)

    cols[0].metric("API Connection", "Connected")
    cols[1].metric(
        "Application Health",
        str(health_data.get("status", "unknown")).upper(),
    )
    cols[2].metric(
        "Deployment",
        status_data.get("active_deployment_version", "Unknown"),
    )
    cols[3].metric("Active Incidents", len(active))

    if active:
        st.warning("Active incidents: " + ", ".join(active))
    else:
        st.success("No active incidents. Application is in baseline state.")


def _render_incident_controls(base_url):
    st.subheader("Incident Simulation")

    cols = st.columns(3)

    for index, (scenario, label, help_text) in enumerate(SCENARIOS):
        with cols[index % 3]:
            if st.button(
                label,
                help=help_text,
                use_container_width=True,
                key=f"scenario_{scenario}",
            ):
                response, error = _api_post(
                    base_url,
                    f"/api/incidents/{scenario}",
                )

                if error:
                    st.error(error)
                else:
                    st.success(response.get("message", "Scenario activated."))

                st.rerun()

    if st.button("Reset All Scenarios", type="primary"):
        response, error = _api_post(base_url, "/api/reset")

        if error:
            st.error(error)
        else:
            st.success(response.get("message", "Scenarios reset."))

        st.rerun()


def _render_investigation(base_url):
    st.subheader("AI Incident Investigation")

    st.caption(
        "LangGraph investigation using read-only MCP diagnostics. "
        "The agent proposes fixes but does not independently execute them."
    )

    if st.button(
        "Investigate Incident",
        type="primary",
        use_container_width=True,
    ):
        with st.spinner("Collecting diagnostics and analysing evidence..."):
            result, error = _api_post(
                base_url,
                "/api/investigate",
                timeout=90.0,
            )

        if error:
            st.session_state.pop("investigation_result", None)
            st.session_state["investigation_error"] = error
        else:
            st.session_state["investigation_result"] = result
            st.session_state.pop("investigation_error", None)

    if "investigation_error" in st.session_state:
        st.error(st.session_state["investigation_error"])

    if "investigation_result" in st.session_state:
        _render_diagnosis(st.session_state["investigation_result"])


def _render_security():
    st.subheader("Prompt-Injection Security Evaluation")

    report = _read_security_evaluation()

    cols = st.columns(3)

    cols[0].metric("Adversarial Payload Corpus", "30")

    if report:
        total = report.get("total_cases", 0)
        completed = report.get("completed_cases", 0)
        failed = report.get("failed_cases", 0)

        cols[1].metric("Completed Model Calls", completed)
        cols[2].metric("Failed Model Calls", failed)

        st.caption(f"Latest report timestamp: {report.get('timestamp', 'Unknown')}")

        st.info(
            "Attack success rate has not been established. "
            "Model responses require manual review; API errors are not "
            "counted as successful or failed attacks."
        )

        results = report.get("results", [])

        if results:
            rows = []

            for item in results:
                rows.append({
                    "Case": item.get("case"),
                    "Status": item.get("status"),
                    "Severity": item.get("severity"),
                    "Duration (s)": item.get("duration_seconds"),
                })

            st.dataframe(rows, use_container_width=True, hide_index=True)

            with st.expander("View saved evaluation report"):
                st.json(report)

    else:
        cols[1].metric("Completed Model Calls", "N/A")
        cols[2].metric("Attack Success Rate", "Not measured")

        st.info(
            "No saved security evaluation report found. "
            "The 30-payload adversarial corpus is available, "
            "but live evaluation remains incomplete."
        )


def _render_approvals(observability):
    st.subheader("Human Approval & Remediation")

    stats = observability["approval_stats"]

    statuses = [
        ("Pending", "pending"),
        ("Used", "used"),
        ("Rejected", "rejected"),
        ("Expired", "expired"),
    ]

    cols = st.columns(4)

    for col, (label, key) in zip(cols, statuses):
        col.metric(label, stats.get(key, 0))

    history = observability["approval_history"]

    if history:
        st.markdown("**Recent Approval Records**")
        st.dataframe(history, use_container_width=True, hide_index=True)
    else:
        st.info("No approval records yet.")

    st.caption(
        "Remediation requires an explicit approval and a predefined action. "
        "Docker validates the patch; trusted host-side code applies it."
    )


def _render_request_metrics(base_url):
    st.subheader("Application Request Metrics")

    metrics, error = _api_get(base_url, "/api/metrics")

    if error:
        st.error(error)
        return

    cols = st.columns(5)

    cols[0].metric("Demo Requests", metrics["total_requests"])
    cols[1].metric("Successful", metrics["successful_requests"])
    cols[2].metric("Failed", metrics["failed_requests"])
    cols[3].metric("Average Latency", f"{metrics['average_duration_ms']:.1f} ms")
    cols[4].metric("HTTP 500", metrics["http_500_count"])

    st.caption(
        "These metrics describe GET /api/demo/request, "
        "not every FastAPI endpoint or AI investigation."
    )


def _render_database_health(base_url):
    st.subheader("Database Health")

    data, error = _api_get(base_url, "/api/database/health")

    if error:
        st.error(error)
        return

    cols = st.columns(3)

    cols[0].metric("SQLite", data["sqlite_status"])
    cols[1].metric(
        "Simulated Failure",
        "ACTIVE" if data["simulated_failure_active"] else "Inactive",
    )
    cols[2].metric("Integrity Check", data["integrity_check"])

    st.caption(f"Database path: `{data['database_path']}`")


def _render_logs_and_deployments(base_url):
    st.subheader("Structured Application Logs")

    logs, error = _api_get(
        base_url,
        "/api/logs",
        params={"limit": 30},
    )

    if error:
        st.error(error)
    elif logs and logs.get("logs"):
        st.dataframe(logs["logs"], use_container_width=True, hide_index=True)
    else:
        st.info("No log entries recorded.")

    st.subheader("Deployment History")

    deployments, error = _api_get(base_url, "/api/deployments")

    if error:
        st.error(error)
    elif deployments and deployments.get("deployments"):
        st.dataframe(
            deployments["deployments"],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No deployment records found.")


def _render_incident_timeline(observability):
    st.subheader("Incident Timeline")

    history = observability["incident_history"]

    if history:
        st.dataframe(history, use_container_width=True, hide_index=True)
    else:
        st.info("No incident history recorded yet.")


def main():
    st.set_page_config(
        page_title="AgentShield | Security Operations Center",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ AgentShield")
    st.caption(
        "SECURITY OPERATIONS CENTER | Secure AI incident investigation "
        "| Human-approved remediation"
    )

    with st.sidebar:
        st.header("Connection")

        base_url = st.text_input(
            "FastAPI Base URL",
            value=DEFAULT_API_BASE_URL,
        )

        if st.button("Refresh Dashboard", use_container_width=True):
            st.rerun()

        st.divider()
        st.subheader("Demo Endpoint")

        if st.button("Send Demo Request", use_container_width=True):
            try:
                with httpx.Client(timeout=10.0) as client:
                    response = client.get(
                        f"{base_url.rstrip('/')}/api/demo/request"
                    )

                st.session_state["last_demo_result"] = {
                    "status_code": response.status_code,
                    "body": response.json(),
                }
                st.session_state.pop("last_demo_error", None)

            except (httpx.HTTPError, ValueError) as exc:
                st.session_state["last_demo_error"] = str(exc)

            st.rerun()

        if "last_demo_error" in st.session_state:
            st.error(st.session_state["last_demo_error"])

        if "last_demo_result" in st.session_state:
            result = st.session_state["last_demo_result"]
            st.write(f"Last HTTP Status: **{result['status_code']}**")
            st.json(result["body"])

    health, health_error = _api_get(base_url, "/health")
    status, status_error = _api_get(base_url, "/api/status")

    if health_error or status_error:
        st.error("FastAPI connection unavailable.")

        if health_error:
            st.error(health_error)

        if status_error:
            st.error(status_error)

        st.info("Start the backend with `python run.py`.")
        return

    _render_overview(health, status)

    observability, observability_error = _read_local_observability()

    if observability_error:
        st.warning(observability_error)

    tabs = st.tabs([
        "Overview",
        "AI Investigation",
        "Security",
        "Remediation",
        "Observability",
    ])

    with tabs[0]:
        _render_incident_controls(base_url)
        st.divider()
        _render_request_metrics(base_url)
        st.divider()
        _render_database_health(base_url)

    with tabs[1]:
        _render_investigation(base_url)

    with tabs[2]:
        _render_security()

    with tabs[3]:
        if observability:
            _render_approvals(observability)
        else:
            st.info("Approval statistics unavailable.")

    with tabs[4]:
        _render_request_metrics(base_url)

        if observability:
            st.divider()
            _render_incident_timeline(observability)

        st.divider()
        _render_logs_and_deployments(base_url)

    st.divider()

    if observability:
        st.caption(
            f"Local read-only observability database: "
            f"`{observability['database_path']}`"
        )

    st.caption(
        "AgentShield is a security demonstration. "
        "AI diagnoses are advisory; remediation requires human approval."
    )


if __name__ == "__main__":
    main()
