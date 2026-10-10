"""Tenant-owned static endpoint groups and dynamic saved fleet scopes."""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4
from .endpoint import EndpointId
from .organization import OrganizationId
from .fleet import FleetQuery

@dataclass(frozen=True)
class EndpointGroupId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self,"value",str(UUID(str(self.value))))
        except (TypeError,ValueError,AttributeError) as e: raise ValueError("group ID must be a valid UUID") from e
    @classmethod
    def new(cls): return cls(str(uuid4()))
    def __str__(self): return self.value

@dataclass(frozen=True)
class SavedFleetScopeId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self,"value",str(UUID(str(self.value))))
        except (TypeError,ValueError,AttributeError) as e: raise ValueError("scope ID must be a valid UUID") from e
    @classmethod
    def new(cls): return cls(str(uuid4()))
    def __str__(self): return self.value

class GroupStatus(str,Enum): ACTIVE="active"; REVOKED="revoked"
class ScopeStatus(str,Enum): ACTIVE="active"; REVOKED="revoked"

def _aware(x,n):
    if x.tzinfo is None or x.utcoffset() is None: raise ValueError(f"{n} must be timezone-aware")

@dataclass(frozen=True)
class EndpointGroup:
    group_id: EndpointGroupId
    organization_id: OrganizationId
    name: str
    description: str = ""
    status: GroupStatus = GroupStatus.ACTIVE
    created_by: str|None = None
    created_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    def __post_init__(self):
        object.__setattr__(self,"group_id",EndpointGroupId(self.group_id.value if isinstance(self.group_id,EndpointGroupId) else self.group_id)); object.__setattr__(self,"organization_id",OrganizationId.parse(self.organization_id)); object.__setattr__(self,"status",GroupStatus(self.status))
        if not isinstance(self.name,str) or not self.name.strip() or len(self.name.strip())>200: raise ValueError("group name is required and must be <= 200 characters")
        if len(self.description or "")>2000: raise ValueError("group description is too long")
        object.__setattr__(self,"name",self.name.strip()); object.__setattr__(self,"description",self.description or ""); _aware(self.created_at,"created_at"); _aware(self.updated_at,"updated_at")
    def revoke(self,now): _aware(now,"updated_at"); return replace(self,status=GroupStatus.REVOKED,updated_at=now)
    def to_dict(self): return {"group_id":str(self.group_id),"organization_id":str(self.organization_id),"name":self.name,"description":self.description,"status":self.status.value,"created_by":self.created_by,"created_at":self.created_at.isoformat(),"updated_at":self.updated_at.isoformat()}

@dataclass(frozen=True)
class SavedFleetScope:
    scope_id: SavedFleetScopeId
    organization_id: OrganizationId
    name: str
    fleet_query: FleetQuery
    description: str = ""
    status: ScopeStatus = ScopeStatus.ACTIVE
    created_by: str|None = None
    created_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda:datetime.now(timezone.utc))
    query_version: int = 1
    def __post_init__(self):
        object.__setattr__(self,"scope_id",SavedFleetScopeId(self.scope_id.value if isinstance(self.scope_id,SavedFleetScopeId) else self.scope_id)); object.__setattr__(self,"organization_id",OrganizationId.parse(self.organization_id)); object.__setattr__(self,"status",ScopeStatus(self.status))
        if not isinstance(self.name,str) or not self.name.strip() or len(self.name.strip())>200: raise ValueError("scope name is required and must be <= 200 characters")
        if len(self.description or "")>2000: raise ValueError("scope description is too long")
        if self.query_version!=1: raise ValueError("unsupported saved fleet query version")
        if not isinstance(self.fleet_query,FleetQuery): raise ValueError("fleet_query must be FleetQuery")
        object.__setattr__(self,"name",self.name.strip()); object.__setattr__(self,"description",self.description or ""); _aware(self.created_at,"created_at"); _aware(self.updated_at,"updated_at")
    def revoke(self,now): _aware(now,"updated_at"); return replace(self,status=ScopeStatus.REVOKED,updated_at=now)
    def to_dict(self): return {"scope_id":str(self.scope_id),"organization_id":str(self.organization_id),"name":self.name,"description":self.description,"status":self.status.value,"created_by":self.created_by,"created_at":self.created_at.isoformat(),"updated_at":self.updated_at.isoformat(),"query_version":self.query_version,"criteria":_query_dict(self.fleet_query)}

def _query_dict(q):
    return {"search":q.search,"statuses":[x.value for x in q.statuses],"presence_states":[x.value for x in q.presence_states],"platforms":list(q.platforms),"architectures":list(q.architectures),"agent_versions":list(q.agent_versions),"sort_by":q.sort_by.value,"direction":q.direction.value}
def fleet_query_from_dict(v):
    if not isinstance(v,dict): raise ValueError("criteria must be an object")
    return FleetQuery(search=v.get("search", ""), statuses=tuple(v.get("statuses",())), presence_states=tuple(v.get("presence_states",())), platforms=tuple(v.get("platforms",())), architectures=tuple(v.get("architectures",())), agent_versions=tuple(v.get("agent_versions",())), sort_by=v.get("sort_by","created_at"), direction=v.get("direction","desc"))

@dataclass(frozen=True)
class EndpointGroupSummary:
    group: EndpointGroup
    member_count: int
    def to_dict(self):
        result=self.group.to_dict(); result["member_count"]=self.member_count; return result
