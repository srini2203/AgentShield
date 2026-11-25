
"""Integration tests for approval-gated remediation."""

import json
from types import SimpleNamespace

import pytest

from app.approvals import create_approval, init_approvals
from app.database import get_app_state, init_db, update_app_state
from app.remediation import execute_remediation


def setup_database(tmp_path):
    db_path = tmp_path / "remediation_test.db"
    init_db(db_path)
    init_approvals(db_path)
    return db_path


def activate_database_failure(db_path):
    update_app_state(db_path, {"db_failure_active": 1})


def valid_sandbox_response():
    return SimpleNamespace(
        returncode=0,
        stdout=json.dumps({
            "status": "validated",
            "action": "restore_database",
            "patch": {"db_failure_active": 0},
        }),
        stderr="",
    )


def test_approved_remediation_updates_application_state(
    tmp_path, monkeypatch
):
    db_path = setup_database(tmp_path)
    activate_database_failure(db_path)

    approval = create_approval(
        db_path, "database_failure", "restore_database"
    )

    monkeypatch.setattr(
        "app.remediation.subprocess.run",
        lambda *args, **kwargs: valid_sandbox_response(),
    )

    result = execute_remediation(db_path, approval["approval_id"])

    state = get_app_state(db_path)

    assert result["status"] == "remediated"
    assert result["incident"] == "database_failure"
    assert result["action"] == "restore_database"
    assert state["db_failure_active"] == 0


def test_invalid_sandbox_response_does_not_change_state(
    tmp_path, monkeypatch
):
    db_path = setup_database(tmp_path)
    activate_database_failure(db_path)

    approval = create_approval(
        db_path, "database_failure", "restore_database"
    )

    invalid_response = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({
            "status": "validated",
            "action": "restore_database",
            "patch": {"db_failure_active": 0, "unexpected": 1},
        }),
        stderr="",
    )

    monkeypatch.setattr(
        "app.remediation.subprocess.run",
        lambda *args, **kwargs: invalid_response,
    )

    with pytest.raises(RuntimeError, match="Invalid sandbox response"):
        execute_remediation(db_path, approval["approval_id"])

    state = get_app_state(db_path)
    assert state["db_failure_active"] == 1


def test_docker_failure_does_not_change_application_state(
    tmp_path, monkeypatch
):
    db_path = setup_database(tmp_path)
    activate_database_failure(db_path)

    approval = create_approval(
        db_path, "database_failure", "restore_database"
    )

    failed_result = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="Docker execution failed",
    )

    monkeypatch.setattr(
        "app.remediation.subprocess.run",
        lambda *args, **kwargs: failed_result,
    )

    with pytest.raises(RuntimeError, match="Sandbox rejected remediation"):
        execute_remediation(db_path, approval["approval_id"])

    state = get_app_state(db_path)
    assert state["db_failure_active"] == 1


def test_remediation_approval_cannot_be_replayed(
    tmp_path, monkeypatch
):
    db_path = setup_database(tmp_path)
    activate_database_failure(db_path)

    approval = create_approval(
        db_path, "database_failure", "restore_database"
    )

    calls = []

    def mock_docker(*args, **kwargs):
        calls.append(1)
        return valid_sandbox_response()

    monkeypatch.setattr(
        "app.remediation.subprocess.run",
        mock_docker,
    )

    first_result = execute_remediation(
        db_path, approval["approval_id"]
    )

    assert first_result["status"] == "remediated"

    with pytest.raises(
        ValueError,
        match="missing, rejected, or already used",
    ):
        execute_remediation(db_path, approval["approval_id"])

    assert len(calls) == 1
    assert get_app_state(db_path)["db_failure_active"] == 0
