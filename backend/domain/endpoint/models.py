"""Pure endpoint identity contracts; no enrollment, storage, or transport."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional
from uuid import UUID, uuid4

from ..assessment import AssessmentTarget
from ..scanner import CapabilityObservation, TargetCapabilities


class EndpointStatus(str, Enum):
    NEW = "new"
    ACTIVE = "active"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    REVOKED = "revoked"


@dataclass(frozen=True)
class EndpointId:
    """Stable Raven-X-managed identity, independent of machine attributes."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise ValueError("endpoint ID must be a UUID string")
        try:
            normalized = str(UUID(self.value))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("endpoint ID must be a valid UUID string") from error
        object.__setattr__(self, "value", normalized)

    @classmethod
    def new(cls) -> "EndpointId":
        """Create an explicit new identity; persistence/enrollment is deferred."""
        return cls(str(uuid4()))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class PlatformInfo:
    name: str
    version: Optional[str] = None
    architecture: Optional[str] = None

    def __post_init__(self) -> None:
        _require_text("platform name", self.name)
        _validate_optional_text("platform version", self.version)
        _validate_optional_text("platform architecture", self.architecture)


@dataclass(frozen=True)
class AgentInfo:
    agent_version: str
    protocol_version: str
    installed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        _require_text("agent version", self.agent_version)
        _require_text("protocol version", self.protocol_version)
        _validate_timestamp("agent installed_at", self.installed_at)


@dataclass(frozen=True)
class Endpoint:
    """Managed-machine domain identity with mutable descriptive state."""

    endpoint_id: EndpointId
    hostname: str
    platform: PlatformInfo
    status: EndpointStatus = EndpointStatus.NEW
    capabilities: TargetCapabilities = field(default_factory=TargetCapabilities)
    agent: Optional[AgentInfo] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    # None is an explicit legacy/unassigned endpoint; enterprise creation must set this.
    organization_id: Optional[Any] = None

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_id, EndpointId):
            raise ValueError("endpoint_id must be an EndpointId")
        _require_text("hostname", self.hostname)
        if not isinstance(self.platform, PlatformInfo):
            raise ValueError("platform must be a PlatformInfo")
        if not isinstance(self.status, EndpointStatus):
            raise ValueError("endpoint status must be an EndpointStatus")
        if not isinstance(self.capabilities, TargetCapabilities):
            raise ValueError("capabilities must be TargetCapabilities")
        if self.organization_id is not None:
            object.__setattr__(self, "organization_id", _parse_organization_id(self.organization_id))
        if self.agent is not None and not isinstance(self.agent, AgentInfo):
            raise ValueError("agent must be AgentInfo or None")
        _validate_timestamp("created_at", self.created_at, required=True)
        _validate_timestamp("updated_at", self.updated_at)
        _validate_timestamp("last_seen", self.last_seen)
        for field_name, value in (("updated_at", self.updated_at), ("last_seen", self.last_seen)):
            if value is not None and value < self.created_at:
                raise ValueError(f"{field_name} cannot precede created_at")

    def transition_to(self, status: EndpointStatus, updated_at: datetime) -> "Endpoint":
        """Apply the minimal explicit lifecycle transitions for the identity domain."""
        if not isinstance(status, EndpointStatus):
            raise ValueError("endpoint status must be an EndpointStatus")
        _validate_timestamp("updated_at", updated_at, required=True)
        if updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if status not in _ALLOWED_TRANSITIONS[self.status]:
            raise ValueError(f"endpoint cannot transition from {self.status.value} to {status.value}")
        return replace(self, status=status, updated_at=updated_at)

    def with_capabilities(self, capabilities: TargetCapabilities, updated_at: datetime) -> "Endpoint":
        """Return an updated capability snapshot without changing endpoint identity."""
        _validate_timestamp("updated_at", updated_at, required=True)
        if updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return replace(self, capabilities=capabilities, updated_at=updated_at)

    def to_assessment_target(self) -> AssessmentTarget:
        """Resolve assessable machine attributes without treating a target as an endpoint."""
        metadata: Dict[str, Any] = dict(self.metadata)
        metadata["endpoint_id"] = str(self.endpoint_id)
        if self.organization_id is not None:
            metadata["organization_id"] = str(self.organization_id)
        if self.platform.architecture is not None:
            metadata["architecture"] = self.platform.architecture
        return AssessmentTarget(
            target_id=str(self.endpoint_id),
            hostname=self.hostname,
            platform=self.platform.name,
            platform_version=self.platform.version,
            metadata=metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic, JSON-compatible endpoint domain data."""
        return {
            "endpoint_id": str(self.endpoint_id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "hostname": self.hostname,
            "platform": {
                "name": self.platform.name,
                "version": self.platform.version,
                "architecture": self.platform.architecture,
            },
            "status": self.status.value,
            "capabilities": sorted(capability.value for capability in self.capabilities.values),
            "capability_observations": [_observation_to_dict(item) for item in self.capabilities.observations],
            "agent": _agent_to_dict(self.agent),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": dict(self.metadata),
        }


_ALLOWED_TRANSITIONS = {
    EndpointStatus.NEW: frozenset({EndpointStatus.ACTIVE, EndpointStatus.REVOKED}),
    EndpointStatus.ACTIVE: frozenset({EndpointStatus.DEGRADED, EndpointStatus.OFFLINE, EndpointStatus.REVOKED}),
    EndpointStatus.DEGRADED: frozenset({EndpointStatus.ACTIVE, EndpointStatus.OFFLINE, EndpointStatus.REVOKED}),
    EndpointStatus.OFFLINE: frozenset({EndpointStatus.ACTIVE, EndpointStatus.REVOKED}),
    EndpointStatus.REVOKED: frozenset(),
}


def _require_text(field_name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _parse_organization_id(value: Any):
    """Reuse the shared OrganizationId without adding infrastructure imports."""
    organization_module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
    return organization_module.OrganizationId.parse(value)


def _validate_optional_text(field_name: str, value: Optional[str]) -> None:
    if value is not None:
        _require_text(field_name, value)


def _validate_timestamp(field_name: str, value: Optional[datetime], required: bool = False) -> None:
    if value is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def _observation_to_dict(observation: CapabilityObservation) -> Dict[str, str]:
    return {
        "capability": observation.capability.value,
        "availability": observation.availability.value,
        "source": observation.source,
        "reason": observation.reason,
    }


def _agent_to_dict(agent: Optional[AgentInfo]) -> Optional[Dict[str, Optional[str]]]:
    if agent is None:
        return None
    return {
        "agent_version": agent.agent_version,
        "protocol_version": agent.protocol_version,
        "installed_at": agent.installed_at.isoformat() if agent.installed_at else None,
    }
