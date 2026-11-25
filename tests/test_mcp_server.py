
"""Tests for AgentShield's read-only MCP diagnostic tools."""

import asyncio
import sqlite3

import pytest

from app.database import init_db
from app.mcp_server import mcp


@pytest.fixture
def mcp_test_db(tmp_path, monkeypatch):
    """Create an isolated database for MCP tests."""
    db_path = tmp_path / "agentshield_mcp_test.db"
    init_db(db_path)

    monkeypatch.setenv("AGENTSHIELD_DB_PATH", str(db_path))
    return db_path


def call_tool(name, arguments=None):
    """Execute a registered MCP tool asynchronously."""
    return asyncio.run(
        mcp._tool_manager.call_tool(
            name,
            arguments or {},
        )
    )


def database_snapshot(db_path):
    """Capture all rows from the application tables."""
    tables = (
        "app_state",
        "application_logs",
        "incident_history",
        "deployment_history",
        "request_metrics",
    )

    snapshot = {}

    with sqlite3.connect(db_path) as conn:
        for table in tables:
            snapshot[table] = conn.execute(
                f"SELECT * FROM {table} ORDER BY id;"
            ).fetchall()

    return snapshot


def test_all_four_mcp_tools_execute(mcp_test_db):
    """Verify that all registered diagnostic tools return data."""

    logs = call_tool("get_application_logs", {"limit": 10})
    metrics = call_tool("get_application_metrics")
    database = call_tool("get_database_health_status")
    deployments = call_tool("get_deployment_history", {"limit": 10})

    assert isinstance(logs, dict)
    assert "logs" in logs
    assert "total" in logs

    assert isinstance(metrics, dict)
    assert "total_requests" in metrics

    assert isinstance(database, dict)
    assert database["sqlite_connected"] is True
    assert database["integrity_check"] == "ok"

    assert isinstance(deployments, dict)
    assert "deployments" in deployments
    assert len(deployments["deployments"]) >= 1


def test_invalid_log_limit_is_rejected(mcp_test_db):
    with pytest.raises(Exception):
        call_tool("get_application_logs", {"limit": 101})


def test_zero_log_limit_is_rejected(mcp_test_db):
    with pytest.raises(Exception):
        call_tool("get_application_logs", {"limit": 0})


def test_negative_log_offset_is_rejected(mcp_test_db):
    with pytest.raises(Exception):
        call_tool("get_application_logs", {"offset": -1})


def test_invalid_log_severity_is_rejected(mcp_test_db):
    with pytest.raises(Exception):
        call_tool(
            "get_application_logs",
            {"severity": "EXECUTE"},
        )


def test_invalid_deployment_limit_is_rejected(mcp_test_db):
    with pytest.raises(Exception):
        call_tool("get_deployment_history", {"limit": 101})


def test_diagnostic_tools_do_not_modify_database(mcp_test_db):
    """Verify that diagnostic tool execution leaves SQLite unchanged."""

    before = database_snapshot(mcp_test_db)

    call_tool("get_application_logs")
    call_tool("get_application_metrics")
    call_tool("get_database_health_status")
    call_tool("get_deployment_history")

    after = database_snapshot(mcp_test_db)

    assert before == after
