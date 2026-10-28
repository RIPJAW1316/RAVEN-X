"""Minimal FastAPI availability baseline using isolated test storage."""

import os
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.api import main
from backend.core.database.database import DatabaseManager


def _protected_database_dir() -> Path:
    from backend.infrastructure.security.windows_files import protect_private_directory
    root = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "ws01-api-tests" / uuid4().hex
    root.mkdir(parents=True)
    if os.name == "nt":
        protect_private_directory(root)
    return root


def test_health_endpoint_reports_application_availability(tmp_path, monkeypatch):
    database_path = _protected_database_dir() / "api_test.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  sqlite_path: '{database_path.as_posix()}'\n",
        encoding="utf-8",
    )
    manager = DatabaseManager(str(config_path))
    monkeypatch.setattr(main, "db_manager", manager)
    monkeypatch.setattr(main, "config", {"monitoring": {"real_time_enabled": False}})

    with TestClient(main.app) as client:
        response = client.get("/health")

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "healthy"
        assert "services" in payload
