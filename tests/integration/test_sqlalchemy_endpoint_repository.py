"""Isolated SQLite integration tests for durable endpoint registry records."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, select

from backend.application.endpoint import EndpointRegistry, UnknownEndpointError
from backend.application.ports.endpoint_repository import DuplicateEndpointError
from backend.core.database.database import DatabaseManager
from backend.core.database.models import EndpointRecord, Scan
from backend.domain.endpoint import AgentInfo, Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.scanner import (
    CapabilityAvailability,
    CapabilityObservation,
    ScannerCapability,
    TargetCapabilities,
)
from backend.infrastructure.persistence.endpoint_mappers import record_to_endpoint
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


def _manager(tmp_path):
    config_path = tmp_path / "endpoint_repository.yaml"
    database_path = tmp_path / "endpoint_repository.db"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  sqlite_path: '{database_path.as_posix()}'\n",
        encoding="utf-8",
    )
    manager = DatabaseManager(str(config_path))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def _endpoint():
    capability = ScannerCapability("windows.firewall.read")
    return Endpoint(
        endpoint_id=EndpointId("123e4567-e89b-12d3-a456-426614174000"),
        hostname="raven-host",
        platform=PlatformInfo("Windows", "Windows 11", "x86_64"),
        capabilities=TargetCapabilities(
            frozenset({capability}),
            (CapabilityObservation(capability, CapabilityAvailability.SUPPORTED, "test", "available"),),
        ),
        agent=AgentInfo("2.0.0", "1", NOW),
        created_at=NOW,
        metadata={"device_model": "Test Device"},
    )


def test_endpoint_registry_survives_reload_updates_and_revocation(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyEndpointRepository(manager)
    registry = EndpointRegistry(repository)
    endpoint = _endpoint()
    registry.register(endpoint)

    renamed = registry.update(replace(endpoint, hostname="renamed-host", updated_at=NOW + timedelta(minutes=1)))
    capabilities = TargetCapabilities(frozenset({ScannerCapability("windows.powershell")}))
    discovered = registry.update_capabilities(endpoint.endpoint_id, capabilities, NOW + timedelta(minutes=2))
    active = registry.update_status(endpoint.endpoint_id, EndpointStatus.ACTIVE, NOW + timedelta(minutes=3))
    revoked = registry.revoke(endpoint.endpoint_id, NOW + timedelta(minutes=4))

    manager.close()
    reloaded_manager = DatabaseManager(str(tmp_path / "endpoint_repository.yaml"))
    reloaded_manager.initialize_sync_engine()
    reloaded_repository = SQLAlchemyEndpointRepository(reloaded_manager)
    restored = reloaded_repository.get(endpoint.endpoint_id)

    assert renamed.endpoint_id == endpoint.endpoint_id
    assert discovered.endpoint_id == endpoint.endpoint_id
    assert active.endpoint_id == endpoint.endpoint_id
    assert revoked.endpoint_id == endpoint.endpoint_id
    assert restored.endpoint_id == endpoint.endpoint_id
    assert restored.hostname == "renamed-host"
    assert restored.capabilities == capabilities
    assert restored.status is EndpointStatus.REVOKED
    assert restored.agent == endpoint.agent
    reloaded_manager.close()


def test_endpoint_schema_is_additive_and_duplicate_missing_and_corrupt_records_fail_explicitly(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyEndpointRepository(manager)
    registry = EndpointRegistry(repository)
    endpoint = _endpoint()
    registry.register(endpoint)

    assert {"scans", "vulnerabilities", "endpoints"} <= set(inspect(manager.engine).get_table_names())
    with manager.get_db() as session:
        session.add(Scan(id="existing-scan", scan_type="full", status="running"))
    with manager.get_db() as session:
        assert session.execute(select(Scan).where(Scan.id == "existing-scan")).scalar_one().status == "running"

    with pytest.raises(DuplicateEndpointError):
        registry.register(endpoint)
    assert repository.get(EndpointId("123e4567-e89b-12d3-a456-426614174001")) is None
    with pytest.raises(UnknownEndpointError):
        registry.revoke(EndpointId("123e4567-e89b-12d3-a456-426614174001"), NOW + timedelta(minutes=1))

    with manager.get_db() as session:
        session.add(
            EndpointRecord(
                endpoint_id="invalid-uuid",
                hostname="bad",
                platform="Windows",
                status="invalid-status",
                capabilities=[],
                capability_observations=[],
                endpoint_metadata={},
                created_at=NOW.replace(tzinfo=None),
            )
        )
    with pytest.raises(ValueError, match="status"):
        with manager.get_db() as session:
            corrupt_record = session.execute(
                select(EndpointRecord).where(EndpointRecord.endpoint_id == "invalid-uuid")
            ).scalar_one()
            record_to_endpoint(corrupt_record)

    manager.close()
