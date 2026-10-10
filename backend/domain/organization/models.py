"""Organization identity and membership data; no authorization or persistence."""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID, uuid4
from ..user import UserId

@dataclass(frozen=True)
class OrganizationId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self, "value", str(UUID(str(self.value))))
        except (TypeError, ValueError, AttributeError) as error: raise ValueError("organization ID must be a valid UUID") from error
    @classmethod
    def new(cls): return cls(str(uuid4()))
    @classmethod
    def parse(cls, value): return cls(value)
    def __str__(self): return self.value

@dataclass(frozen=True)
class MembershipId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self, "value", str(UUID(str(self.value))))
        except (TypeError, ValueError, AttributeError) as error: raise ValueError("membership ID must be a valid UUID") from error
    @classmethod
    def new(cls): return cls(str(uuid4()))
    @classmethod
    def parse(cls, value): return cls(value)
    def __str__(self): return self.value

class OrganizationStatus(str, Enum): ACTIVE="active"; SUSPENDED="suspended"; REVOKED="revoked"
class MembershipStatus(str, Enum): ACTIVE="active"; SUSPENDED="suspended"; REVOKED="revoked"

def _time(value, name):
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError(f"{name} must be timezone-aware")

def _metadata(value):
    result=dict(value or {})
    if any(any(word in str(k).lower() for word in ("password", "secret", "token", "verifier", "permission", "role")) for k in result):
        raise ValueError("organization metadata cannot contain security policy or secrets")
    return result

@dataclass(frozen=True)
class Organization:
    organization_id: OrganizationId
    name: str
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Mapping[str, Any] = field(default_factory=dict)
    def __post_init__(self):
        object.__setattr__(self, "organization_id", OrganizationId.parse(self.organization_id))
        if not isinstance(self.name,str) or not self.name.strip(): raise ValueError("organization name is required")
        object.__setattr__(self, "name", self.name.strip()); object.__setattr__(self,"status",OrganizationStatus(self.status))
        _time(self.created_at,"created_at"); _time(self.updated_at,"updated_at")
        if self.updated_at < self.created_at: raise ValueError("updated_at cannot precede created_at")
        object.__setattr__(self,"metadata",_metadata(self.metadata))
    def transition_to(self,status,updated_at):
        status=OrganizationStatus(status); _time(updated_at,"updated_at")
        allowed={OrganizationStatus.ACTIVE:{OrganizationStatus.SUSPENDED,OrganizationStatus.REVOKED},OrganizationStatus.SUSPENDED:{OrganizationStatus.ACTIVE,OrganizationStatus.REVOKED},OrganizationStatus.REVOKED:set()}
        if status not in allowed[self.status]: raise ValueError(f"organization cannot transition from {self.status.value} to {status.value}")
        return replace(self,status=status,updated_at=updated_at)
    def to_dict(self): return {"organization_id":str(self.organization_id),"name":self.name,"status":self.status.value,"created_at":self.created_at.astimezone(timezone.utc).isoformat(),"updated_at":self.updated_at.astimezone(timezone.utc).isoformat(),"metadata":dict(self.metadata)}

@dataclass(frozen=True)
class OrganizationMembership:
    membership_id: MembershipId
    user_id: UserId
    organization_id: OrganizationId
    status: MembershipStatus = MembershipStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Mapping[str, Any] = field(default_factory=dict)
    def __post_init__(self):
        object.__setattr__(self,"membership_id",MembershipId.parse(self.membership_id)); object.__setattr__(self,"user_id",UserId.parse(self.user_id)); object.__setattr__(self,"organization_id",OrganizationId.parse(self.organization_id)); object.__setattr__(self,"status",MembershipStatus(self.status))
        _time(self.created_at,"created_at"); _time(self.updated_at,"updated_at")
        if self.updated_at < self.created_at: raise ValueError("updated_at cannot precede created_at")
        object.__setattr__(self,"metadata",_metadata(self.metadata))
    def transition_to(self,status,updated_at):
        status=MembershipStatus(status); _time(updated_at,"updated_at")
        allowed={MembershipStatus.ACTIVE:{MembershipStatus.SUSPENDED,MembershipStatus.REVOKED},MembershipStatus.SUSPENDED:{MembershipStatus.ACTIVE,MembershipStatus.REVOKED},MembershipStatus.REVOKED:set()}
        if status not in allowed[self.status]: raise ValueError(f"membership cannot transition from {self.status.value} to {status.value}")
        return replace(self,status=status,updated_at=updated_at)
    def to_dict(self): return {"membership_id":str(self.membership_id),"user_id":str(self.user_id),"organization_id":str(self.organization_id),"status":self.status.value,"created_at":self.created_at.astimezone(timezone.utc).isoformat(),"updated_at":self.updated_at.astimezone(timezone.utc).isoformat(),"metadata":dict(self.metadata)}
