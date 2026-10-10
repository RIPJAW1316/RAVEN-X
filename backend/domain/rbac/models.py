"""RBAC identity and lifecycle values; no persistence or policy side effects."""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, FrozenSet
from uuid import UUID, uuid4
from ..organization import MembershipId, OrganizationId
from ..security import AuthorizationAction

@dataclass(frozen=True)
class RoleId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self,"value",str(UUID(str(self.value))))
        except (TypeError,ValueError,AttributeError) as error: raise ValueError("role ID must be a valid UUID") from error
    @classmethod
    def new(cls): return cls(str(uuid4()))
    @classmethod
    def parse(cls,value): return cls(value)
    def __str__(self): return self.value

@dataclass(frozen=True)
class RoleBindingId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self,"value",str(UUID(str(self.value))))
        except (TypeError,ValueError,AttributeError) as error: raise ValueError("role binding ID must be a valid UUID") from error
    @classmethod
    def new(cls): return cls(str(uuid4()))
    @classmethod
    def parse(cls,value): return cls(value)
    def __str__(self): return self.value

class RoleStatus(str,Enum): ACTIVE="active"; DISABLED="disabled"; REVOKED="revoked"
class RoleBindingStatus(str,Enum): ACTIVE="active"; DISABLED="disabled"; REVOKED="revoked"

@dataclass(frozen=True, order=True)
class Permission:
    value: str
    def __post_init__(self):
        if not isinstance(self.value,str) or not self.value.strip(): raise ValueError("permission is required")
        try: normalized=AuthorizationAction(self.value).value
        except (ValueError,TypeError) as error: raise ValueError(f"unknown permission: {self.value}") from error
        object.__setattr__(self,"value",normalized)
    def __str__(self): return self.value

def _time(value,name):
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError(f"{name} must be timezone-aware")
def _metadata(value):
    result=dict(value or {})
    if any(any(word in str(k).lower() for word in ("password","secret","token","verifier","permission")) for k in result): raise ValueError("RBAC metadata cannot contain secrets or policy data")
    return result

@dataclass(frozen=True)
class Role:
    role_id: RoleId
    organization_id: OrganizationId
    name: str
    description: str = ""
    permissions: FrozenSet[Permission] = field(default_factory=frozenset)
    status: RoleStatus = RoleStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    metadata: Mapping[str,Any] = field(default_factory=dict)
    def __post_init__(self):
        object.__setattr__(self,"role_id",RoleId.parse(self.role_id)); object.__setattr__(self,"organization_id",OrganizationId.parse(self.organization_id)); object.__setattr__(self,"status",RoleStatus(self.status))
        if not isinstance(self.name,str) or not self.name.strip(): raise ValueError("role name is required")
        object.__setattr__(self,"name",self.name.strip()); object.__setattr__(self,"permissions",frozenset(p if isinstance(p,Permission) else Permission(p) for p in self.permissions)); _time(self.created_at,"created_at"); _time(self.updated_at,"updated_at")
        if self.updated_at<self.created_at: raise ValueError("updated_at cannot precede created_at")
        object.__setattr__(self,"metadata",_metadata(self.metadata))
    def with_permissions(self,permissions,updated_at): _time(updated_at,"updated_at"); return replace(self,permissions=frozenset(p if isinstance(p,Permission) else Permission(p) for p in permissions),updated_at=updated_at)
    def transition_to(self,status,updated_at):
        status=RoleStatus(status); _time(updated_at,"updated_at"); allowed={RoleStatus.ACTIVE:{RoleStatus.DISABLED,RoleStatus.REVOKED},RoleStatus.DISABLED:{RoleStatus.ACTIVE,RoleStatus.REVOKED},RoleStatus.REVOKED:set()}
        if status not in allowed[self.status]: raise ValueError(f"role cannot transition from {self.status.value} to {status.value}")
        return replace(self,status=status,updated_at=updated_at)
    def to_dict(self): return {"role_id":str(self.role_id),"organization_id":str(self.organization_id),"name":self.name,"description":self.description,"permissions":sorted(str(p) for p in self.permissions),"status":self.status.value,"created_at":self.created_at.astimezone(timezone.utc).isoformat(),"updated_at":self.updated_at.astimezone(timezone.utc).isoformat(),"metadata":dict(self.metadata)}

@dataclass(frozen=True)
class RoleBinding:
    role_binding_id: RoleBindingId
    organization_id: OrganizationId
    membership_id: MembershipId
    role_id: RoleId
    status: RoleBindingStatus = RoleBindingStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    metadata: Mapping[str,Any] = field(default_factory=dict)
    def __post_init__(self):
        object.__setattr__(self,"role_binding_id",RoleBindingId.parse(self.role_binding_id)); object.__setattr__(self,"organization_id",OrganizationId.parse(self.organization_id)); object.__setattr__(self,"membership_id",MembershipId.parse(self.membership_id)); object.__setattr__(self,"role_id",RoleId.parse(self.role_id)); object.__setattr__(self,"status",RoleBindingStatus(self.status)); _time(self.created_at,"created_at"); _time(self.updated_at,"updated_at")
        if self.updated_at<self.created_at: raise ValueError("updated_at cannot precede created_at")
        object.__setattr__(self,"metadata",_metadata(self.metadata))
    def transition_to(self,status,updated_at):
        status=RoleBindingStatus(status); _time(updated_at,"updated_at"); allowed={RoleBindingStatus.ACTIVE:{RoleBindingStatus.DISABLED,RoleBindingStatus.REVOKED},RoleBindingStatus.DISABLED:{RoleBindingStatus.ACTIVE,RoleBindingStatus.REVOKED},RoleBindingStatus.REVOKED:set()}
        if status not in allowed[self.status]: raise ValueError(f"role binding cannot transition from {self.status.value} to {status.value}")
        return replace(self,status=status,updated_at=updated_at)
    def to_dict(self): return {"role_binding_id":str(self.role_binding_id),"organization_id":str(self.organization_id),"membership_id":str(self.membership_id),"role_id":str(self.role_id),"status":self.status.value,"created_at":self.created_at.astimezone(timezone.utc).isoformat(),"updated_at":self.updated_at.astimezone(timezone.utc).isoformat(),"metadata":dict(self.metadata)}
