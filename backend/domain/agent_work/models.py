"""Durable delivery values distinct from remote assessment workflow state."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping, Optional
from uuid import UUID, uuid4

from ..endpoint import EndpointId
from ...protocol.agent import CorrelationId, MessageId


class AgentWorkStatus(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    ACKNOWLEDGED = "acknowledged"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class WorkId:
    value: UUID

    def __post_init__(self):
        object.__setattr__(self, "value", UUID(str(self.value)))

    @classmethod
    def new(cls):
        return cls(uuid4())

    def __str__(self):
        return str(self.value)


@dataclass(frozen=True)
class AgentWorkItem:
    work_id: WorkId
    endpoint_id: EndpointId
    assessment_id: str
    message_id: MessageId
    correlation_id: CorrelationId
    message_type: str
    protocol_version: str
    envelope: Mapping[str, object]
    status: AgentWorkStatus
    created_at: datetime
    available_at: datetime
    expires_at: Optional[datetime] = None
    leased_at: Optional[datetime] = None
    lease_expires_at: Optional[datetime] = None
    lease_token_hash: Optional[str] = None
    attempt_count: int = 0
    acknowledged_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_error: Optional[str] = None
    organization_id: Optional[object] = None

    def __post_init__(self):
        if not isinstance(self.work_id, WorkId):
            object.__setattr__(self, "work_id", WorkId(self.work_id))
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if not isinstance(self.message_id, MessageId):
            object.__setattr__(self, "message_id", MessageId(self.message_id))
        if not isinstance(self.correlation_id, CorrelationId):
            object.__setattr__(self, "correlation_id", CorrelationId(self.correlation_id))
        if self.organization_id is not None:
            module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
            object.__setattr__(self, "organization_id", module.OrganizationId.parse(self.organization_id))
        object.__setattr__(self, "status", AgentWorkStatus(self.status))
        if not self.assessment_id.strip() or not self.message_type.strip() or not self.protocol_version.strip():
            raise ValueError("work identity and protocol metadata are required")
        for value, name in ((self.created_at, "created_at"), (self.available_at, "available_at"),
                            (self.expires_at, "expires_at"), (self.leased_at, "leased_at"),
                            (self.lease_expires_at, "lease_expires_at"), (self.acknowledged_at, "acknowledged_at"),
                            (self.completed_at, "completed_at")):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"{name} must be timezone-aware")
        if self.attempt_count < 0:
            raise ValueError("attempt_count must not be negative")

    def to_dict(self):
        return {
            "work_id": str(self.work_id), "endpoint_id": str(self.endpoint_id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "assessment_id": self.assessment_id, "message_id": str(self.message_id),
            "correlation_id": str(self.correlation_id), "status": self.status.value,
        }


@dataclass(frozen=True)
class LeasedAgentWork:
    item: AgentWorkItem
    lease_token: str

    def __post_init__(self):
        if not self.lease_token:
            raise ValueError("lease token must not be empty")

    def __repr__(self):
        return f"LeasedAgentWork(work_id={self.item.work_id!s}, lease_token=<redacted>)"
