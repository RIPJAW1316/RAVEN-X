"""Explicit mapping between the pure endpoint domain and SQLAlchemy records."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from ...core.database.models import EndpointRecord
from ...domain.endpoint import AgentInfo, Endpoint, EndpointId, EndpointStatus, PlatformInfo
from ...domain.scanner import (
    CapabilityAvailability,
    CapabilityObservation,
    ScannerCapability,
    TargetCapabilities,
)


def endpoint_to_record(endpoint: Endpoint) -> EndpointRecord:
    """Map a domain endpoint to the additive persistence representation."""
    return EndpointRecord(
        endpoint_id=str(endpoint.endpoint_id),
        organization_id=str(endpoint.organization_id) if endpoint.organization_id else None,
        hostname=endpoint.hostname,
        platform=endpoint.platform.name,
        platform_version=endpoint.platform.version,
        architecture=endpoint.platform.architecture,
        status=endpoint.status.value,
        agent_version=endpoint.agent.agent_version if endpoint.agent else None,
        protocol_version=endpoint.agent.protocol_version if endpoint.agent else None,
        agent_installed_at=_to_storage_time(endpoint.agent.installed_at) if endpoint.agent else None,
        capabilities=sorted(capability.value for capability in endpoint.capabilities.values),
        capability_observations=[_observation_to_dict(item) for item in endpoint.capabilities.observations],
        endpoint_metadata=dict(endpoint.metadata),
        created_at=_to_storage_time(endpoint.created_at),
        updated_at=_to_storage_time(endpoint.updated_at),
        last_seen=_to_storage_time(endpoint.last_seen),
        revoked_at=_to_storage_time(endpoint.updated_at or endpoint.created_at)
        if endpoint.status is EndpointStatus.REVOKED
        else None,
    )


def record_to_endpoint(record: EndpointRecord) -> Endpoint:
    """Map a persisted endpoint record back to the pure domain or fail visibly."""
    try:
        status = EndpointStatus(record.status)
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid persisted endpoint status: {record.status!r}") from error

    agent = _agent_from_record(record)
    capabilities = TargetCapabilities(
        values=frozenset(ScannerCapability(value) for value in _required_list(record.capabilities, "capabilities")),
        observations=tuple(_observation_from_dict(item) for item in _required_list(
            record.capability_observations,
            "capability observations",
        )),
    )
    metadata = record.endpoint_metadata
    if not isinstance(metadata, Mapping):
        raise ValueError("persisted endpoint metadata must be a mapping")

    return Endpoint(
        endpoint_id=EndpointId(record.endpoint_id),
        organization_id=record.organization_id,
        hostname=record.hostname,
        platform=PlatformInfo(record.platform, record.platform_version, record.architecture),
        status=status,
        capabilities=capabilities,
        agent=agent,
        created_at=_from_storage_time(record.created_at, "created_at", required=True),
        updated_at=_from_storage_time(record.updated_at, "updated_at"),
        last_seen=_from_storage_time(record.last_seen, "last_seen"),
        metadata=dict(metadata),
    )


def apply_endpoint_record(record: EndpointRecord, endpoint: Endpoint) -> None:
    """Replace mutable columns while preserving the established record identity."""
    mapped = endpoint_to_record(endpoint)
    for field_name in (
        "hostname",
        "platform",
        "platform_version",
        "architecture",
        "status",
        "agent_version",
        "protocol_version",
        "agent_installed_at",
        "capabilities",
        "capability_observations",
        "endpoint_metadata",
        "created_at",
        "updated_at",
        "last_seen",
        "revoked_at",
    ):
        setattr(record, field_name, getattr(mapped, field_name))


def _to_storage_time(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _from_storage_time(value: Optional[datetime], field_name: str, required: bool = False) -> Optional[datetime]:
    if value is None:
        if required:
            raise ValueError(f"persisted endpoint {field_name} is required")
        return None
    if not isinstance(value, datetime):
        raise ValueError(f"persisted endpoint {field_name} must be a datetime")
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _required_list(value: Any, field_name: str) -> List[Any]:
    if not isinstance(value, list):
        raise ValueError(f"persisted endpoint {field_name} must be a list")
    return value


def _observation_to_dict(observation: CapabilityObservation) -> Dict[str, str]:
    return {
        "capability": observation.capability.value,
        "availability": observation.availability.value,
        "source": observation.source,
        "reason": observation.reason,
    }


def _observation_from_dict(value: Any) -> CapabilityObservation:
    if not isinstance(value, Mapping):
        raise ValueError("persisted capability observation must be a mapping")
    try:
        return CapabilityObservation(
            capability=ScannerCapability(value["capability"]),
            availability=CapabilityAvailability(value["availability"]),
            source=value["source"],
            reason=value["reason"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("persisted capability observation is malformed") from error


def _agent_from_record(record: EndpointRecord) -> Optional[AgentInfo]:
    values = (record.agent_version, record.protocol_version, record.agent_installed_at)
    if all(value is None for value in values):
        return None
    if not record.agent_version or not record.protocol_version:
        raise ValueError("persisted agent metadata requires both version fields")
    return AgentInfo(
        agent_version=record.agent_version,
        protocol_version=record.protocol_version,
        installed_at=_from_storage_time(record.agent_installed_at, "agent_installed_at"),
    )
