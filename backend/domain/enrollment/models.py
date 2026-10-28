"""Infrastructure-independent enrollment domain values."""

from dataclasses import dataclass, field, replace
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


class CredentialRevocationKind(str, Enum):
    """Why a credential is being revoked.

    COMPROMISE and ADMINISTRATIVE both invalidate the named credential and
    every renewal descendant on the same endpoint. They are not rotation:
    ``rotate_credential`` replaces one ACTIVE credential and does not contain
    a suspected leak of an earlier ancestor.
    """

    COMPROMISE = "compromise"
    ADMINISTRATIVE = "administrative"


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
class CredentialRenewal:
    """Server lineage linking one endpoint credential to its single successor.

    No secret material is held here. ``predecessor_valid_until`` is fixed when
    the renewal is first committed and is never extended; the predecessor can
    only lose authority earlier (confirmation or revocation), never regain it.
    """

    predecessor_credential_id: CredentialId
    successor_credential_id: CredentialId
    endpoint_id: EndpointId
    issued_at: datetime
    predecessor_valid_until: datetime
    organization_id: Optional[OrganizationId] = None
    confirmed_at: Optional[datetime] = None
    predecessor_closed_at: Optional[datetime] = None
    closed_reason: Optional[str] = None

    def __post_init__(self) -> None:
        for name in ("predecessor_credential_id", "successor_credential_id"):
            value = getattr(self, name)
            if not isinstance(value, CredentialId):
                object.__setattr__(self, name, CredentialId(value))
        if self.predecessor_credential_id == self.successor_credential_id:
            raise ValueError("a credential cannot renew itself")
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(str(self.endpoint_id)))
        if self.organization_id is not None:
            object.__setattr__(self, "organization_id", OrganizationId.parse(self.organization_id))
        _aware(self.issued_at, "issued_at")
        _aware(self.predecessor_valid_until, "predecessor_valid_until")
        if self.predecessor_valid_until < self.issued_at:
            raise ValueError("predecessor_valid_until cannot precede issued_at")
        for value, name in ((self.confirmed_at, "confirmed_at"), (self.predecessor_closed_at, "predecessor_closed_at")):
            if value is not None:
                _aware(value, name)

    def predecessor_is_open(self, now: datetime) -> bool:
        _aware(now, "now")
        return self.predecessor_closed_at is None and now < self.predecessor_valid_until


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
    # Renewal lineage, populated by repositories from CredentialRenewal rows.
    replaces_credential_id: Optional[CredentialId] = None
    renewal_confirmed_at: Optional[datetime] = None
    successor_credential_id: Optional[CredentialId] = None
    predecessor_valid_until: Optional[datetime] = None
    predecessor_closed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.verifier:
            raise ValueError("credential verifier must not be empty")
        _aware(self.issued_at, "issued_at")
        for value, name in (
            (self.expires_at, "expires_at"), (self.rotated_at, "rotated_at"), (self.revoked_at, "revoked_at"),
            (self.renewal_confirmed_at, "renewal_confirmed_at"),
            (self.predecessor_valid_until, "predecessor_valid_until"),
            (self.predecessor_closed_at, "predecessor_closed_at"),
        ):
            if value is not None:
                _aware(value, name)
        for name in ("replaces_credential_id", "successor_credential_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, CredentialId):
                object.__setattr__(self, name, CredentialId(value))

    def with_renewal_lineage(self, *, as_successor: Optional[CredentialRenewal] = None,
                             as_predecessor: Optional[CredentialRenewal] = None) -> "EndpointCredential":
        return replace(
            self,
            replaces_credential_id=as_successor.predecessor_credential_id if as_successor else None,
            renewal_confirmed_at=as_successor.confirmed_at if as_successor else None,
            successor_credential_id=as_predecessor.successor_credential_id if as_predecessor else None,
            predecessor_valid_until=as_predecessor.predecessor_valid_until if as_predecessor else None,
            predecessor_closed_at=as_predecessor.predecessor_closed_at if as_predecessor else None,
        )

    @property
    def awaiting_renewal_confirmation(self) -> bool:
        return self.replaces_credential_id is not None and self.renewal_confirmed_at is None

    def is_usable(self, now: datetime) -> bool:
        """ACTIVE until expiry; a renewed (ROTATED) predecessor only inside its fixed, open window."""
        _aware(now, "now")
        if self.revoked_at is not None or self.status in (CredentialStatus.REVOKED, CredentialStatus.EXPIRED):
            return False
        if self.expires_at is not None and now >= self.expires_at:
            return False
        if self.status is CredentialStatus.ACTIVE:
            return True
        return (
            self.status is CredentialStatus.ROTATED
            and self.successor_credential_id is not None
            and self.predecessor_valid_until is not None
            and self.predecessor_closed_at is None
            and now < self.predecessor_valid_until
        )
