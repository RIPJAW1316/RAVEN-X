"""Persistence baseline tests using a database isolated from user data."""

import logging
import asyncio
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.pool import NullPool, StaticPool

from backend.core.database.database import DatabaseManager, DEFAULT_CONFIG_PATH, PROJECT_ROOT
from backend.core.database.models import Scan, Vulnerability


def test_scan_and_vulnerability_lifecycle_uses_isolated_sqlite(tmp_path):
    database_path = tmp_path / "raven_x_test.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  sqlite_path: '{database_path.as_posix()}'\n"
        "  echo: false\n",
        encoding="utf-8",
    )
    manager = DatabaseManager(str(config_path))
    manager.initialize_sync_engine()
    manager.create_tables()

    with manager.get_db() as session:
        scan = Scan(scan_type="quick", status="running", system_info={"hostname": "test-host"})
        session.add(scan)
        session.flush()
        scan_id = scan.id
        session.add(
            Vulnerability(
                scan_id=scan_id,
                severity="high",
                category="Firewall",
                title="Windows Firewall Disabled",
                details="The public profile is disabled.",
                component="Windows Defender Firewall",
            )
        )

    with manager.get_db() as session:
        persisted_scan = session.get(Scan, scan_id)
        assert persisted_scan is not None
        assert persisted_scan.vulnerabilities[0].title == "Windows Firewall Disabled"
        persisted_scan.status = "completed"

    with manager.get_db() as session:
        assert session.get(Scan, scan_id).status == "completed"

    manager.close()


def _manager_with_sqlite_path(tmp_path, sqlite_path):
    config_path = tmp_path / "database-config.yaml"
    config_path.write_text(
        "database:\n  type: sqlite\n  sqlite_path: '%s'\n" % sqlite_path,
        encoding="utf-8",
    )
    return DatabaseManager(config_path)


def test_file_sqlite_uses_distinct_connections_and_busy_timeout(tmp_path):
    manager = _manager_with_sqlite_path(tmp_path, (tmp_path / "pool.db").as_posix())
    manager.initialize_sync_engine()
    assert isinstance(manager.engine.pool, NullPool)
    with manager.engine.connect() as first, manager.engine.connect() as second:
        assert first.connection.driver_connection is not second.connection.driver_connection
        assert first.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 30000
    manager.close()


def test_async_file_sqlite_uses_distinct_connections_and_busy_timeout(tmp_path):
    manager = _manager_with_sqlite_path(tmp_path, (tmp_path / "async-pool.db").as_posix())
    manager.initialize_async_engine()
    assert isinstance(manager.async_engine.pool, NullPool)
    async def check():
        async with manager.async_engine.connect() as connection:
            result = await connection.exec_driver_sql("PRAGMA busy_timeout")
            assert result.scalar_one() == 30000
        await manager.close_async()
    asyncio.run(check())


def test_memory_sqlite_retains_static_pool(tmp_path):
    manager = _manager_with_sqlite_path(tmp_path, ":memory:")
    manager.initialize_sync_engine()
    manager.initialize_async_engine()
    assert isinstance(manager.engine.pool, StaticPool)
    assert isinstance(manager.async_engine.pool, StaticPool)
    manager.close()
    asyncio.run(manager.close_async())


def test_async_schema_upgrade_restores_existing_session_verifier_index(tmp_path):
    manager = _manager_with_sqlite_path(tmp_path, (tmp_path / "existing-sessions.db").as_posix())
    manager.create_tables()
    with manager.engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ix_human_sessions_token_verifier")
    manager.initialize_async_engine()
    asyncio.run(manager.create_tables_async())
    with manager.engine.connect() as connection:
        names = {row[1] for row in connection.exec_driver_sql("PRAGMA index_list(human_sessions)").all()}
    assert "ix_human_sessions_token_verifier" in names
    asyncio.run(manager.close_async())
    manager.close()


def test_default_config_and_database_paths_do_not_depend_on_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("RAVENX_CONFIG_PATH", raising=False)
    monkeypatch.delenv("RAVENX_DATABASE_PATH", raising=False)
    monkeypatch.chdir(tmp_path)
    manager = DatabaseManager()
    assert manager.config_path == DEFAULT_CONFIG_PATH
    assert (PROJECT_ROOT / "data" / "raven_x.db").as_posix() in manager.get_database_url()


def test_deployment_config_and_sqlite_path_overrides(tmp_path, monkeypatch):
    config_path = tmp_path / "deployment.yaml"
    config_path.write_text("database:\n  type: sqlite\n  sqlite_path: ignored.db\n", encoding="utf-8")
    database_path = tmp_path / "state" / "deployment.db"
    monkeypatch.setenv("RAVENX_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("RAVENX_DATABASE_PATH", str(database_path))
    manager = DatabaseManager()
    assert manager.config_path == config_path.resolve()
    assert database_path.as_posix() in manager.get_database_url()


def test_invalid_database_configuration_does_not_fall_back_to_another_database(tmp_path):
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("application:\n  environment: production\n", encoding="utf-8")
    with pytest.raises(ValueError, match="database configuration"):
        DatabaseManager(config_path)


def test_postgresql_password_is_not_written_to_database_logs(caplog):
    manager = DatabaseManager()
    manager.config = {
        "type": "postgresql", "echo": False,
        "postgresql": {"host": "localhost", "port": 5432, "database": "db",
                       "username": "operator", "password": "RAVENX_TEST_SENTINEL"},
    }
    with caplog.at_level(logging.INFO, logger="backend.core.database.database"):
        with patch("backend.core.database.database.create_engine", return_value=MagicMock()), \
                patch("backend.core.database.database.sessionmaker", return_value=MagicMock()):
            manager.initialize_sync_engine()
    assert "RAVENX_TEST_SENTINEL" not in caplog.text
