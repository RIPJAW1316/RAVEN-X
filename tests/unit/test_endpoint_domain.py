"""Endpoint identity-domain tests without persistence, transport, or host access."""

import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.application.scanner.compatibility import evaluate_compatibility
from backend.application.scanner.legacy_adapters import FIREWALL_MANIFEST
from backend.domain.endpoint import AgentInfo, Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.scanner import CompatibilityStatus, ScannerCapability, TargetCapabilities


ENDPOINT_ID = "123e4567-e89b-12d3-a456-426614174000"
CREATED_AT = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)


def _endpoint(**changes):
    values = {
        "endpoint_id": EndpointId(ENDPOINT_ID),
        "hostname": "raven-workstation",
        "platform": PlatformInfo("Windows", "Windows 11", "x86_64"),
        "capabilities": TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")})),
        "created_at": CREATED_AT,
        "metadata": {"device_model": "Test Device"},
    }
    values.update(changes)
    return Endpoint(**values)


def test_endpoint_id_parses_to_stable_serializable_uuid_value():
    endpoint_id = EndpointId(ENDPOINT_ID.upper())

    assert str(endpoint_id) == ENDPOINT_ID
    assert endpoint_id.value == ENDPOINT_ID


@pytest.mark.parametrize("value", ("not-a-uuid", "", 42))
def test_endpoint_id_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="UUID"):
        EndpointId(value)


def test_endpoint_identity_is_independent_of_mutable_hostname():
    endpoint = _endpoint()
    renamed = replace(endpoint, hostname="renamed-workstation")

    assert renamed.endpoint_id == endpoint.endpoint_id
    assert renamed.hostname == "renamed-workstation"


def test_endpoint_represents_platform_agent_last_seen_and_deterministic_serialization():
    agent = AgentInfo("2.0.0", "1", installed_at=CREATED_AT)
    endpoint = _endpoint(agent=agent, last_seen=CREATED_AT + timedelta(minutes=5))

    serialized = endpoint.to_dict()

    assert serialized == endpoint.to_dict()
    assert serialized["endpoint_id"] == ENDPOINT_ID
    assert serialized["platform"] == {"name": "Windows", "version": "Windows 11", "architecture": "x86_64"}
    assert serialized["agent"]["agent_version"] == "2.0.0"
    assert serialized["last_seen"] == "2026-08-18T12:05:00+00:00"


def test_endpoint_lifecycle_distinguishes_offline_and_terminal_revoked():
    endpoint = _endpoint()
    active = endpoint.transition_to(EndpointStatus.ACTIVE, CREATED_AT + timedelta(minutes=1))
    offline = active.transition_to(EndpointStatus.OFFLINE, CREATED_AT + timedelta(minutes=2))
    revoked = offline.transition_to(EndpointStatus.REVOKED, CREATED_AT + timedelta(minutes=3))

    assert offline.status is EndpointStatus.OFFLINE
    assert revoked.status is EndpointStatus.REVOKED
    with pytest.raises(ValueError, match="cannot transition"):
        revoked.transition_to(EndpointStatus.ACTIVE, CREATED_AT + timedelta(minutes=4))


def test_capability_snapshot_changes_do_not_change_endpoint_identity_or_scanner_compatibility():
    endpoint = _endpoint(capabilities=TargetCapabilities())
    discovered = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")}))

    updated = endpoint.with_capabilities(discovered, CREATED_AT + timedelta(minutes=1))
    compatibility = evaluate_compatibility(FIREWALL_MANIFEST, updated.to_assessment_target(), updated.capabilities)

    assert updated.endpoint_id == endpoint.endpoint_id
    assert updated.capabilities is discovered
    assert compatibility.status is CompatibilityStatus.COMPATIBLE


def test_endpoint_maps_identity_and_platform_metadata_to_assessment_target():
    endpoint = _endpoint()

    target = endpoint.to_assessment_target()

    assert target.target_id == ENDPOINT_ID
    assert target.hostname == endpoint.hostname
    assert target.platform == "Windows"
    assert target.platform_version == "Windows 11"
    assert target.metadata["endpoint_id"] == ENDPOINT_ID
    assert target.metadata["architecture"] == "x86_64"


@pytest.mark.parametrize(
    "factory",
    (
        lambda: PlatformInfo(""),
        lambda: AgentInfo("", "1"),
        lambda: AgentInfo("2.0.0", ""),
        lambda: Endpoint(EndpointId(ENDPOINT_ID), "", PlatformInfo("Windows"), created_at=CREATED_AT),
        lambda: Endpoint(EndpointId(ENDPOINT_ID), "host", PlatformInfo("Windows"), status="active", created_at=CREATED_AT),
        lambda: Endpoint(ENDPOINT_ID, "host", PlatformInfo("Windows"), created_at=CREATED_AT),
        lambda: Endpoint(
            EndpointId(ENDPOINT_ID),
            "host",
            PlatformInfo("Windows"),
            created_at=datetime(2026, 8, 18, 12, 0),
        ),
    ),
)
def test_endpoint_domain_rejects_invalid_required_values_and_naive_timestamps(factory):
    with pytest.raises(ValueError):
        factory()


def test_endpoint_domain_imports_only_standard_library_and_existing_domain_modules():
    source_path = Path(__file__).resolve().parents[2] / "backend" / "domain" / "endpoint" / "models.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert imported_roots <= {"dataclasses", "datetime", "enum", "typing", "uuid", "assessment", "scanner"}
