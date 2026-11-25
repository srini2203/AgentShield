
"""Security tests for AgentShield's investigation agent."""

import asyncio

import pytest
from pydantic import ValidationError

import app.agent as agent
from app.scenarios import MALICIOUS_LOG_PAYLOADS


# ---------------------------------------------------------
# 1. MCP response normalization
# ---------------------------------------------------------

def test_normalize_mcp_json_text():
    result = [
        {
            "type": "text",
            "text": '{"status": "healthy", "count": 5}',
        }
    ]

    normalized = agent._normalize_mcp_result(result, "test_tool")

    assert normalized == {"status": "healthy", "count": 5}


def test_normalize_mcp_dictionary():
    result = {"status": "healthy"}

    assert agent._normalize_mcp_result(
        result, "test_tool"
    ) == result


def test_reject_invalid_mcp_json():
    with pytest.raises(ValueError, match="Invalid JSON"):
        agent._normalize_mcp_result(
            [{"type": "text", "text": "not valid json"}],
            "test_tool",
        )


def test_reject_multiple_mcp_text_blocks():
    result = [
        {"type": "text", "text": '{"a": 1}'},
        {"type": "text", "text": '{"b": 2}'},
    ]

    with pytest.raises(ValueError, match="exactly one"):
        agent._normalize_mcp_result(result, "test_tool")


def test_reject_non_text_mcp_content():
    result = [{"type": "image", "data": "unexpected"}]

    with pytest.raises(ValueError, match="Unexpected MCP content"):
        agent._normalize_mcp_result(result, "test_tool")


def test_reject_mcp_json_array():
    result = [{"type": "text", "text": '[1, 2, 3]'}]

    with pytest.raises(ValueError, match="JSON object"):
        agent._normalize_mcp_result(result, "test_tool")


# ---------------------------------------------------------
# 2. Untrusted evidence sanitization
# ---------------------------------------------------------

def test_remove_invisible_control_characters():
    result = agent._sanitize_evidence(
        "hello\x00world\u200b!"
    )

    assert result == "helloworld!"


def test_limit_untrusted_string_length():
    result = agent._sanitize_evidence(
        "A" * 3000
    )

    assert len(result) == agent.MAX_EVIDENCE_STRING_LENGTH


def test_reject_excessively_nested_evidence():
    value = "deep"

    for _ in range(agent.MAX_EVIDENCE_DEPTH + 2):
        value = [value]

    with pytest.raises(ValueError, match="nesting depth"):
        agent._sanitize_evidence(value)


def test_reject_oversized_evidence_list():
    value = ["item"] * (
        agent.MAX_EVIDENCE_LIST_ITEMS + 1
    )

    with pytest.raises(ValueError, match="too many items"):
        agent._sanitize_evidence(value)


def test_reject_unsupported_evidence_type():
    with pytest.raises(ValueError, match="Unsupported diagnostic"):
        agent._sanitize_evidence(object())


def test_reject_non_string_dictionary_key():
    with pytest.raises(ValueError, match="invalid key"):
        agent._sanitize_evidence({123: "value"})


def test_reject_non_finite_numbers():
    diagnostics = valid_diagnostics()
    diagnostics["metrics"]["value"] = float("nan")

    with pytest.raises(ValueError):
        agent._validate_diagnostics(diagnostics)


# ---------------------------------------------------------
# 3. Diagnostic structure validation
# ---------------------------------------------------------

def valid_diagnostics():
    return {
        "logs": {"logs": [], "total": 0},
        "metrics": {"total_requests": 0},
        "database_health": {"status": "healthy"},
        "deployments": {"deployments": []},
    }


def test_accept_valid_diagnostic_structure():
    result = agent._validate_diagnostics(
        valid_diagnostics()
    )

    assert set(result) == {
        "logs",
        "metrics",
        "database_health",
        "deployments",
    }


def test_reject_missing_diagnostic_section():
    diagnostics = valid_diagnostics()
    diagnostics.pop("logs")

    with pytest.raises(ValueError, match="structure"):
        agent._validate_diagnostics(diagnostics)


def test_reject_unexpected_diagnostic_section():
    diagnostics = valid_diagnostics()
    diagnostics["unauthorized"] = {"command": "test"}

    with pytest.raises(ValueError, match="structure"):
        agent._validate_diagnostics(diagnostics)


def test_reject_oversized_diagnostic_payload():
    diagnostics = valid_diagnostics()
    diagnostics["logs"]["large"] = "A" * 2000

    # Several bounded fields are needed to exceed the total limit.
    diagnostics["logs"]["extra"] = [
        "B" * agent.MAX_EVIDENCE_STRING_LENGTH
        for _ in range(60)
    ]

    with pytest.raises(ValueError, match="allowed size"):
        agent._validate_diagnostics(diagnostics)


# ---------------------------------------------------------
# 4. Strict diagnosis schema
# ---------------------------------------------------------

def valid_diagnosis():
    return {
        "incident_summary": "Database failure detected.",
        "severity": "HIGH",
        "root_cause": "Simulated database outage.",
        "evidence": ["Database failure flag is active."],
        "confidence": 0.95,
        "proposed_fix": "Review and deactivate the simulation.",
        "limitations": [],
    }


def test_accept_valid_diagnosis():
    diagnosis = agent.IncidentDiagnosis.model_validate(
        valid_diagnosis()
    )

    assert diagnosis.severity == "HIGH"


def test_reject_invalid_severity():
    result = valid_diagnosis()
    result["severity"] = "EXTREME"

    with pytest.raises(ValidationError):
        agent.IncidentDiagnosis.model_validate(result)


def test_reject_extra_diagnosis_fields():
    result = valid_diagnosis()
    result["unauthorized_action"] = "execute command"

    with pytest.raises(ValidationError):
        agent.IncidentDiagnosis.model_validate(result)


def test_reject_confidence_outside_range():
    result = valid_diagnosis()
    result["confidence"] = 1.5

    with pytest.raises(ValidationError):
        agent.IncidentDiagnosis.model_validate(result)


def test_reject_empty_evidence():
    result = valid_diagnosis()
    result["evidence"] = []

    with pytest.raises(ValidationError):
        agent.IncidentDiagnosis.model_validate(result)


def test_reject_empty_proposed_fix():
    result = valid_diagnosis()
    result["proposed_fix"] = ""

    with pytest.raises(ValidationError):
        agent.IncidentDiagnosis.model_validate(result)


# ---------------------------------------------------------
# 5. Deterministic MCP tool authorization
# ---------------------------------------------------------

class FakeTool:
    def __init__(self, name):
        self.name = name
        self.invoked = False

    async def ainvoke(self, arguments):
        self.invoked = True
        return [{"type": "text", "text": "{}"}]


class FakeMCPClient:
    def __init__(self, servers, tools):
        self.tools = tools

    async def get_tools(self):
        return self.tools


def test_reject_unauthorized_mcp_tool(monkeypatch):
    tools = [
        FakeTool("get_application_logs"),
        FakeTool("get_application_metrics"),
        FakeTool("get_database_health_status"),
        FakeTool("get_deployment_history"),
        FakeTool("execute_shell"),
    ]

    monkeypatch.setattr(
        agent,
        "MultiServerMCPClient",
        lambda servers: FakeMCPClient(servers, tools),
    )

    with pytest.raises(RuntimeError, match="allowlist"):
        asyncio.run(agent.collect_diagnostics("test.db"))

    assert not any(tool.invoked for tool in tools)


def test_reject_missing_mcp_tool(monkeypatch):
    tools = [
        FakeTool("get_application_logs"),
        FakeTool("get_application_metrics"),
    ]

    monkeypatch.setattr(
        agent,
        "MultiServerMCPClient",
        lambda servers: FakeMCPClient(servers, tools),
    )

    with pytest.raises(RuntimeError, match="allowlist"):
        asyncio.run(agent.collect_diagnostics("test.db"))

    assert not any(tool.invoked for tool in tools)


# ---------------------------------------------------------
# 6. Malicious log payload corpus
# ---------------------------------------------------------

def test_malicious_payload_corpus_contains_at_least_25_entries():
    assert len(MALICIOUS_LOG_PAYLOADS) >= 25


def test_all_malicious_payloads_are_inert_string_data():
    for severity, payload in MALICIOUS_LOG_PAYLOADS:
        assert severity in {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        }

        assert isinstance(payload, str)
        assert payload.strip()


def test_malicious_payloads_can_be_processed_as_untrusted_data():
    sanitized = agent._sanitize_evidence(
        [
            {"severity": severity, "message": payload}
            for severity, payload in MALICIOUS_LOG_PAYLOADS
        ]
    )

    assert len(sanitized) == len(MALICIOUS_LOG_PAYLOADS)

    assert all(
        isinstance(item["message"], str)
        for item in sanitized
    )

def test_sanitizer_rejects_non_finite_numbers():
    with pytest.raises(ValueError, match="non-finite"):
        agent._sanitize_evidence(float("nan"))


def test_sanitizer_rejects_colliding_dictionary_keys():
    value = {
        "status": "healthy",
        "sta\u200btus": "compromised",
    }

    with pytest.raises(ValueError, match="colliding keys"):
        agent._sanitize_evidence(value)
