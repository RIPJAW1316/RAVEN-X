"""Infrastructure-independent enrollment domain values."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional
from uuid import UUID, uuid4

from ..endpoint import AgentInfo, EndpointId, EndpointStatus, PlatformInfo
from ..organization import OrganizationId
from ..scanner import TargetCapabilities


def _aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True)
class EnrollmentId:
    value: UUID

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", UUID(str(self.value)))

    @classmethod
    def new(cls) -> "EnrollmentId":
        return cls(uuid4())

    @classmethod
    def parse(cls, value: str) -> "EnrollmentId":
        return cls(UUID(value))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class CredentialId:
    value: UUID

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", UUID(str(self.value)))

    @classmethod
    def new(cls) -> "CredentialId":
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


class EnrollmentStatus(str, Enum):
    PENDING = "pending"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CredentialKind(str, Enum):
    OPAQUE = "opaque"


@dataclass(frozen=True)
class EnrollmentRequest:
    """Untrusted machine metadata supplied during enrollment."""

    hostname: str
    platform: PlatformInfo
    capabilities: TargetCapabilities = field(default_factory=TargetCapabilities)
    agent: Optional[AgentInfo] = None
    request_id: str = ""
    nonce: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.hostname.strip():
            raise ValueError("hostname must not be empty")
        if not isinstance(self.platform, PlatformInfo):
            raise ValueError("platform must be PlatformInfo")
        if not isinstance(self.capabilities, TargetCapabilities):
            raise ValueError("capabilities must be TargetCapabilities")
        if self.agent is not None and not isinstance(self.agent, AgentInfo):
            raise ValueError("agent must be AgentInfo")


@dataclass(frozen=True)
class EnrollmentAuthorization:
    enrollment_id: EnrollmentId
    token_verifier: str
    status: EnrollmentStatus
    created_at: datetime
    expires_at: datetime
    consumed_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    organization_id: Optional[OrganizationId] = None

    def __post_init__(self) -> None:
        if not self.token_verifier:
            raise ValueError("token_verifier must not be empty")
        _aware(self.created_at, "created_at")
        _aware(self.expires_at, "expires_at")
        for value, name in ((self.consumed_at, "consumed_at"), (self.revoked_at, "revoked_at")):
            if value is not None:
                _aware(value, name)
        if self.organization_id is not None:
            object.__setattr__(self, "organization_id", OrganizationId.parse(self.organization_id))

    def is_usable(self, now: datetime) -> bool:
        _aware(now, "now")
        return self.status is EnrollmentStatus.PENDING and now < self.expires_at


@dataclass(frozen=True)
class EndpointCredential:
    credential_id: CredentialId
    endpoint_id: EndpointId
    kind: CredentialKind
    verifier: str
    status: CredentialStatus
    issued_at: datetime
    expires_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.verifier:
            raise ValueError("credential verifier must not be empty")
        _aware(self.issued_at, "issued_at")
        if self.expires_at is not None:
            _aware(self.expires_at, "expires_at")
        if self.rotated_at is not None:
            _aware(self.rotated_at, "rotated_at")
        if self.revoked_at is not None:
            _aware(self.revoked_at, "revoked_at")

    def is_usable(self, now: datetime) -> bool:
        _aware(now, "now")
        return self.status is CredentialStatus.ACTIVE and (
            self.expires_at is None or now < self.expires_at
        )
