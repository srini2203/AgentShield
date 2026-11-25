"""Local demonstration Streamlit dashboard for AgentShield Batch 1."""

import os
from typing import Any, Optional

import httpx
import streamlit as st

DEFAULT_API_BASE_URL = os.environ.get("AGENTSHIELD_API_URL", "http://127.0.0.1:8000")

SCENARIOS: list[tuple[str, str, str]] = [
    ("database_failure", "1. Database Failure", "Simulate DB outage while keeping SQLite intact."),
    ("high_latency", "2. High API Latency", "Inject bounded artificial delay into demo requests."),
    ("http_500", "3. HTTP 500 Errors", "Cause demo endpoint to return HTTP 500 errors."),
    ("bad_deployment", "4. Bad Deployment", "Roll out an unhealthy deployment configuration."),
    ("malicious_log", "5. Malicious Log Injection", "Insert representative hostile strings as inert logs."),
]


def _api_get(base_url: str, path: str, params: Optional[dict[str, Any]] = None) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Perform a GET request to the FastAPI backend and return (json, error)."""
    url = f"{base_url.rstrip('/')}{path}"
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(url, params=params)
        if response.status_code >= 400:
            return None, f"GET {path} returned HTTP {response.status_code}: {response.text}"
        return response.json(), None
    except httpx.HTTPError as exc:
        return None, f"Failed to connect to {url}: {exc}"


def _api_post(base_url: str, path: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """Perform a POST request to the FastAPI backend and return (json, error)."""
    url = f"{base_url.rstrip('/')}{path}"
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(url)
        if response.status_code >= 400:
            return None, f"POST {path} returned HTTP {response.status_code}: {response.text}"
        return response.json(), None
    except httpx.HTTPError as exc:
        return None, f"Failed to connect to {url}: {exc}"


def main() -> None:
    st.set_page_config(
        page_title="AgentShield — Local Incident Simulation Dashboard",
        layout="wide",
    )

    st.title("AgentShield — Incident Simulation Dashboard")
    st.caption(
        "Local demonstration dashboard (Batch 1) for controlling and inspecting "
        "reproducible, SQLite-backed operational incidents. Incidents are simulated "
        "locally; AI investigation is not enabled in this batch."
    )

    with st.sidebar:
        st.header("Connection")
        api_base_url = st.text_input("FastAPI Base URL", value=DEFAULT_API_BASE_URL)
        if st.button("Refresh Dashboard", use_container_width=True):
            st.rerun()

        st.divider()
        st.subheader("Demo Endpoint")
        if st.button("Send Demo Request", use_container_width=True):
            demo_url = f"{api_base_url.rstrip('/')}/api/demo/request"
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.get(demo_url)
                st.session_state["last_demo_result"] = {
                    "status_code": resp.status_code,
                    "body": resp.json(),
                }
            except httpx.HTTPError as exc:
                st.session_state["last_demo_error"] = f"Demo request failed: {exc}"
            st.rerun()

        if "last_demo_error" in st.session_state:
            st.error(st.session_state.pop("last_demo_error"))
        if "last_demo_result" in st.session_state:
            result = st.session_state["last_demo_result"]
            st.write(f"Last Demo HTTP Status: **{result['status_code']}**")
            st.json(result["body"])

    health_data, health_err = _api_get(api_base_url, "/health")
    status_data, status_err = _api_get(api_base_url, "/api/status")

    if health_err or status_err:
        st.error("API Connection: Disconnected")
        if health_err:
            st.error(health_err)
        if status_err:
            st.error(status_err)
        st.info("Start the FastAPI server with `python run.py` and click Refresh Dashboard.")
        return

    assert health_data is not None and status_data is not None

    # Top status overview
    col_conn, col_health, col_deploy, col_incidents = st.columns(4)
    with col_conn:
        st.metric("API Connection", "Connected")
    with col_health:
        st.metric("Application Health", health_data["status"].upper())
    with col_deploy:
        st.metric(
            "Deployment",
            f"{status_data['active_deployment_version']} ({status_data['deployment_status']})",
        )
    with col_incidents:
        active = status_data["active_incidents"]
        st.metric("Active Incidents", len(active))

    if active:
        st.warning(f"Active Incidents: {', '.join(active)}")
    else:
        st.success("Active Incidents: None (baseline healthy state)")

    st.divider()

    # Incident controls
    st.subheader("Incident Controls")
    control_cols = st.columns(6)
    for idx, (scenario_key, label, help_text) in enumerate(SCENARIOS):
        with control_cols[idx]:
            if st.button(label, help=help_text, use_container_width=True):
                resp, err = _api_post(api_base_url, f"/api/incidents/{scenario_key}")
                if err:
                    st.session_state["action_error"] = err
                else:
                    st.session_state["action_notice"] = resp["message"]
                st.rerun()

    with control_cols[5]:
        if st.button("Reset All", type="primary", use_container_width=True):
            resp, err = _api_post(api_base_url, "/api/reset")
            if err:
                st.session_state["action_error"] = err
            else:
                st.session_state["action_notice"] = resp["message"]
            st.rerun()

    if "action_error" in st.session_state:
        st.error(st.session_state.pop("action_error"))
    if "action_notice" in st.session_state:
        st.info(st.session_state.pop("action_notice"))

    st.divider()

    # Metrics and Database Health
    metrics_data, metrics_err = _api_get(api_base_url, "/api/metrics")
    db_health_data, db_health_err = _api_get(api_base_url, "/api/database/health")

    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Demo Request Metrics")
        st.caption(
            "Counts only requests to `GET /api/demo/request`, not every FastAPI endpoint."
        )
        if metrics_err:
            st.error(metrics_err)
        elif metrics_data:
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Demo Total", metrics_data["total_requests"])
            m2.metric("Success", metrics_data["successful_requests"])
            m3.metric("Failed", metrics_data["failed_requests"])
            m4.metric("Avg ms", f"{metrics_data['average_duration_ms']:.1f}")
            m5.metric("HTTP 500", metrics_data["http_500_count"])

    with col_right:
        st.subheader("Database Health")
        if db_health_err:
            st.error(db_health_err)
        elif db_health_data:
            d1, d2, d3 = st.columns(3)
            d1.metric("SQLite Status", db_health_data["sqlite_status"])
            d2.metric(
                "Simulated Failure",
                "ACTIVE" if db_health_data["simulated_failure_active"] else "Inactive",
            )
            d3.metric("Integrity", db_health_data["integrity_check"])
            st.caption(f"Database path: `{db_health_data['database_path']}`")

    st.divider()

    # Logs and Deployment History
    logs_data, logs_err = _api_get(api_base_url, "/api/logs", params={"limit": 30})
    deployments_data, deployments_err = _api_get(api_base_url, "/api/deployments")

    st.subheader("Recent Structured Logs")
    if logs_err:
        st.error(logs_err)
    elif logs_data:
        if logs_data["logs"]:
            st.dataframe(logs_data["logs"], use_container_width=True, hide_index=True)
        else:
            st.info("No log entries recorded yet.")

    st.subheader("Deployment History")
    if deployments_err:
        st.error(deployments_err)
    elif deployments_data:
        if deployments_data["deployments"]:
            st.dataframe(
                deployments_data["deployments"],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No deployment records found.")


if __name__ == "__main__":
    main()
