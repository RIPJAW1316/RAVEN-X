"""Transport- and persistence-independent human identity value types."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional
from uuid import UUID, uuid4


@dataclass(frozen=True)
class UserId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self):
        object.__setattr__(self, "value", UUID(str(self.value)))

    @classmethod
    def new(cls): return cls(uuid4())
    @classmethod
    def parse(cls, value): return cls(value)
    def __str__(self): return str(self.value)
    def to_dict(self): return str(self)


class UserStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class CredentialKind(str, Enum):
    PASSWORD = "password"


def canonicalize_email(email: str) -> str:
    if not isinstance(email, str) or not email.strip():
        raise ValueError("email is required")
    value = email.strip().casefold()
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise ValueError("email must contain a valid login identifier")
    return value


@dataclass
class User:
    user_id: UserId
    email: str
    display_name: str
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_authenticated_at: Optional[datetime] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.user_id = UserId.parse(self.user_id)
        self.email = canonicalize_email(self.email)
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError("display_name is required")
        self.display_name = self.display_name.strip()
        self.status = UserStatus(self.status)
        for stamp in (self.created_at, self.updated_at, self.last_authenticated_at):
            if stamp is not None and (stamp.tzinfo is None or stamp.utcoffset() is None):
                raise ValueError("user timestamps must be timezone-aware")
        self.metadata = dict(self.metadata or {})
        if any(any(word in str(key).lower() for word in ("password", "secret", "verifier", "token")) for key in self.metadata):
            raise ValueError("user metadata cannot contain authentication secrets")

    def to_dict(self):
        return {"user_id": str(self.user_id), "email": self.email, "display_name": self.display_name,
                "status": self.status.value, "created_at": self.created_at.astimezone(timezone.utc).isoformat(),
                "updated_at": self.updated_at.astimezone(timezone.utc).isoformat(),
                "last_authenticated_at": self.last_authenticated_at.astimezone(timezone.utc).isoformat() if self.last_authenticated_at else None,
                "metadata": dict(self.metadata)}


@dataclass(frozen=True, repr=False)
class HumanCredential:
    credential_id: UUID
    user_id: UserId
    kind: CredentialKind
    verifier: str
    created_at: datetime
    updated_at: datetime
    revoked_at: Optional[datetime] = None

    def __post_init__(self):
        object.__setattr__(self, "credential_id", UUID(str(self.credential_id)))
        object.__setattr__(self, "user_id", UserId.parse(self.user_id))
        object.__setattr__(self, "kind", CredentialKind(self.kind))
        if not self.verifier or not isinstance(self.verifier, str):
            raise ValueError("credential verifier is required")

    def __repr__(self):
        return f"HumanCredential(credential_id={self.credential_id!s}, user_id={self.user_id!s}, kind={self.kind.value!r}, verifier='<redacted>')"

    def to_dict(self):
        return {"credential_id": str(self.credential_id), "user_id": str(self.user_id), "kind": self.kind.value,
                "created_at": self.created_at.astimezone(timezone.utc).isoformat(), "revoked_at": self.revoked_at.astimezone(timezone.utc).isoformat() if self.revoked_at else None}


@dataclass(repr=False)
class UserSession:
    session_id: UUID
    user_id: UserId
    token_verifier: str
    created_at: datetime
    expires_at: datetime
    authentication_method: CredentialKind = CredentialKind.PASSWORD
    revoked_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None

    def __post_init__(self):
        self.session_id = UUID(str(self.session_id))
        self.user_id = UserId.parse(self.user_id)
        self.authentication_method = CredentialKind(self.authentication_method)
        if not self.token_verifier:
            raise ValueError("session verifier is required")
        for stamp in (self.created_at, self.expires_at, self.revoked_at, self.last_used_at):
            if stamp is not None and (stamp.tzinfo is None or stamp.utcoffset() is None):
                raise ValueError("session timestamps must be timezone-aware")

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def __repr__(self):
        return f"UserSession(session_id={self.session_id!s}, user_id={self.user_id!s}, expires_at={self.expires_at!r}, revoked_at={self.revoked_at!r})"

    def to_dict(self):
        return {"session_id": str(self.session_id), "user_id": str(self.user_id), "created_at": self.created_at.astimezone(timezone.utc).isoformat(),
                "expires_at": self.expires_at.astimezone(timezone.utc).isoformat(), "revoked_at": self.revoked_at.astimezone(timezone.utc).isoformat() if self.revoked_at else None,
                "last_used_at": self.last_used_at.astimezone(timezone.utc).isoformat() if self.last_used_at else None,
                "authentication_method": self.authentication_method.value}
