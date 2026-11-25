"""Pytest fixtures providing isolated temporary SQLite databases."""

from pathlib import Path
from typing import Iterator

from fastapi.testclient import TestClient
import pytest

from app.main import create_app


@pytest.fixture()
def temp_db_path(tmp_path: Path) -> Path:
    """Return a path to an isolated temporary SQLite database file."""
    return tmp_path / "test_agentshield.db"


@pytest.fixture()
def client(temp_db_path: Path) -> Iterator[TestClient]:
    """Create a FastAPI TestClient backed by an isolated temporary SQLite database."""
    application = create_app(db_path=temp_db_path)
    with TestClient(application) as test_client:
        yield test_client
