"""Domain-to-persistence mapping tests for endpoint records."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.core.database.models import EndpointRecord
from backend.domain.endpoint import AgentInfo, Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.scanner import (
    CapabilityAvailability,
    CapabilityObservation,
    ScannerCapability,
    TargetCapabilities,
)
from backend.infrastructure.persistence.endpoint_mappers import endpoint_to_record, record_to_endpoint


CREATED_AT = datetime(2026, 8, 23, 8, 0, tzinfo=timezone.utc)


def _endpoint():
    capability = ScannerCapability("windows.firewall.read")
    return Endpoint(
        endpoint_id=EndpointId("123e4567-e89b-12d3-a456-426614174000"),
        hostname="raven-host",
        platform=PlatformInfo("Windows", "Windows 11", "x86_64"),
        status=EndpointStatus.ACTIVE,
        capabilities=TargetCapabilities(
            frozenset({capability}),
            (CapabilityObservation(capability, CapabilityAvailability.SUPPORTED, "test", "available"),),
        ),
        agent=AgentInfo("2.0.0", "1", CREATED_AT),
        created_at=CREATED_AT,
        updated_at=CREATED_AT + timedelta(minutes=1),
        last_seen=CREATED_AT + timedelta(minutes=2),
        metadata={"device_model": "Test Device"},
    )


def test_endpoint_mapper_round_trips_identity_state_metadata_and_aware_timestamps():
    endpoint = _endpoint()

    record = endpoint_to_record(endpoint)
    restored = record_to_endpoint(record)

    assert record.endpoint_id == str(endpoint.endpoint_id)
    assert record.created_at.tzinfo is None
    assert restored == endpoint


@pytest.mark.parametrize(
    "field_name,value,error",
    (
        ("endpoint_id", "invalid", "UUID"),
        ("status", "invalid", "status"),
        ("capabilities", {"not": "a list"}, "capabilities"),
        ("capability_observations", ["not a mapping"], "observation"),
    ),
)
def test_endpoint_mapper_rejects_corrupt_persisted_data(field_name, value, error):
    record = endpoint_to_record(_endpoint())
    setattr(record, field_name, value)

    with pytest.raises(ValueError, match=error):
        record_to_endpoint(record)
