
"""Tests for AgentShield investigation observability."""

import pytest

from app.observability import (
    get_investigation_metrics,
    init_investigation_metrics,
    record_investigation,
)
from app.agent import _extract_token_usage


def test_metrics_table_initializes(temp_db_path):
    init_investigation_metrics(temp_db_path)

    metrics = get_investigation_metrics(temp_db_path)

    assert metrics["total_investigations"] == 0
    assert metrics["success_rate"] is None


def test_record_successful_investigation(temp_db_path):
    init_investigation_metrics(temp_db_path)

    record_investigation(
        temp_db_path,
        status="success",
        duration_ms=1200.5,
        model="gemini-3.5-flash-lite",
        input_tokens=100,
        output_tokens=50,
        total_tokens=150,
    )

    metrics = get_investigation_metrics(temp_db_path)

    assert metrics["total_investigations"] == 1
    assert metrics["successful_investigations"] == 1
    assert metrics["failed_investigations"] == 0
    assert metrics["success_rate"] == 1.0
    assert metrics["average_duration_ms"] == 1200.5
    assert metrics["total_input_tokens"] == 100
    assert metrics["total_output_tokens"] == 50
    assert metrics["total_tokens"] == 150


def test_record_failed_investigation(temp_db_path):
    init_investigation_metrics(temp_db_path)

    record_investigation(
        temp_db_path,
        status="failure",
        duration_ms=500.0,
        error_type="RuntimeError",
    )

    metrics = get_investigation_metrics(temp_db_path)

    assert metrics["failed_investigations"] == 1
    assert metrics["successful_investigations"] == 0
    assert metrics["success_rate"] == 0.0
    assert metrics["recent_investigations"][0]["error_type"] == "RuntimeError"


def test_missing_token_usage_is_not_recorded_as_zero(temp_db_path):
    init_investigation_metrics(temp_db_path)

    record_investigation(
        temp_db_path,
        status="success",
        duration_ms=800.0,
    )

    metrics = get_investigation_metrics(temp_db_path)

    assert metrics["token_usage_records"] == 0
    assert metrics["total_tokens"] is None


def test_average_and_p95_latency(temp_db_path):
    init_investigation_metrics(temp_db_path)

    for duration in (100.0, 200.0, 300.0, 400.0):
        record_investigation(
            temp_db_path,
            status="success",
            duration_ms=duration,
        )

    metrics = get_investigation_metrics(temp_db_path)

    assert metrics["average_duration_ms"] == 250.0
    assert metrics["p95_duration_ms"] == 400.0


def test_reject_invalid_status(temp_db_path):
    init_investigation_metrics(temp_db_path)

    with pytest.raises(ValueError, match="Invalid investigation status"):
        record_investigation(
            temp_db_path,
            status="unknown",
            duration_ms=100.0,
        )


def test_reject_invalid_duration(temp_db_path):
    init_investigation_metrics(temp_db_path)

    with pytest.raises(ValueError, match="Invalid investigation duration"):
        record_investigation(
            temp_db_path,
            status="success",
            duration_ms=float("nan"),
        )


def test_extract_langchain_token_usage():
    usage = _extract_token_usage({
        "usage_metadata": {
            "input_tokens": 120,
            "output_tokens": 80,
            "total_tokens": 200,
        }
    })

    assert usage == {
        "input_tokens": 120,
        "output_tokens": 80,
        "total_tokens": 200,
    }


def test_extract_gemini_token_usage():
    usage = _extract_token_usage({
        "response_metadata": {
            "token_usage": {
                "prompt_token_count": 120,
                "candidates_token_count": 80,
                "total_token_count": 200,
            }
        }
    })

    assert usage == {
        "input_tokens": 120,
        "output_tokens": 80,
        "total_tokens": 200,
    }


def test_missing_provider_usage_returns_none():
    assert _extract_token_usage({}) is None
