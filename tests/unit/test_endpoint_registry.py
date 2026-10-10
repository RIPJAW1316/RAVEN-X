"""Endpoint registry application-service tests without SQLAlchemy."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from backend.application.endpoint import EndpointRegistry, UnknownEndpointError
from backend.application.ports.endpoint_repository import DuplicateEndpointError
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.scanner import ScannerCapability, TargetCapabilities


NOW = datetime(2026, 8, 23, 9, 0, tzinfo=timezone.utc)


class FakeEndpointRepository:
    def __init__(self):
        self.endpoints = {}

    def add(self, endpoint):
        if endpoint.endpoint_id in self.endpoints:
            raise DuplicateEndpointError("duplicate")
        self.endpoints[endpoint.endpoint_id] = endpoint

    def get(self, endpoint_id):
        return self.endpoints.get(endpoint_id)

    def list(self, status=None):
        endpoints = sorted(self.endpoints.values(), key=lambda item: str(item.endpoint_id))
        return tuple(item for item in endpoints if status is None or item.status is status)

    def update(self, endpoint):
        if endpoint.endpoint_id not in self.endpoints:
            raise KeyError(endpoint.endpoint_id)
        self.endpoints[endpoint.endpoint_id] = endpoint

    def exists(self, endpoint_id):
        return endpoint_id in self.endpoints


def _endpoint():
    return Endpoint(
        EndpointId("123e4567-e89b-12d3-a456-426614174000"),
        "raven-host",
        PlatformInfo("Windows", "Windows 11", "x86_64"),
        created_at=NOW,
    )


def test_registry_registers_updates_resolves_and_revokes_with_stable_identity():
    registry = EndpointRegistry(FakeEndpointRepository())
    endpoint = _endpoint()
    registry.register(endpoint)

    updated = registry.update(replace(endpoint, hostname="renamed-host", updated_at=NOW + timedelta(minutes=1)))
    capabilities = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")}))
    with_capabilities = registry.update_capabilities(endpoint.endpoint_id, capabilities, NOW + timedelta(minutes=2))
    active = registry.update_status(endpoint.endpoint_id, EndpointStatus.ACTIVE, NOW + timedelta(minutes=3))
    revoked = registry.revoke(endpoint.endpoint_id, NOW + timedelta(minutes=4))
    target = registry.resolve_assessment_target(endpoint.endpoint_id)

    assert updated.endpoint_id == endpoint.endpoint_id
    assert with_capabilities.capabilities == capabilities
    assert active.status is EndpointStatus.ACTIVE
    assert revoked.status is EndpointStatus.REVOKED
    assert registry.get(endpoint.endpoint_id).status is EndpointStatus.REVOKED
    assert target.target_id == str(endpoint.endpoint_id)
    assert registry.list(EndpointStatus.REVOKED) == (revoked,)


def test_registry_rejects_duplicate_registration_and_reports_unknown_identity():
    registry = EndpointRegistry(FakeEndpointRepository())
    endpoint = _endpoint()
    registry.register(endpoint)

    with pytest.raises(DuplicateEndpointError):
        registry.register(endpoint)
    with pytest.raises(UnknownEndpointError):
        registry.resolve_assessment_target(EndpointId("123e4567-e89b-12d3-a456-426614174001"))
