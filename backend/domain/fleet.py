"""Explicit, bounded tenant fleet query and response contracts."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from .endpoint import EndpointStatus
from .presence import PresenceState

class FleetSortField(str, Enum):
    HOSTNAME = "hostname"
    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    STATUS = "status"
    LAST_SEEN = "last_seen"
    PLATFORM = "platform"
    AGENT_VERSION = "agent_version"

class SortDirection(str, Enum): ASC = "asc"; DESC = "desc"

@dataclass(frozen=True)
class FleetQuery:
    search: str = ""
    statuses: tuple[EndpointStatus, ...] = ()
    presence_states: tuple[PresenceState, ...] = ()
    platforms: tuple[str, ...] = ()
    architectures: tuple[str, ...] = ()
    agent_versions: tuple[str, ...] = ()
    sort_by: FleetSortField = FleetSortField.CREATED_AT
    direction: SortDirection = SortDirection.DESC
    limit: int = 50
    offset: int = 0

    def __post_init__(self):
        search = (self.search or "").strip()
        if len(search) > 100: raise ValueError("search must be at most 100 characters")
        object.__setattr__(self, "search", search)
        for name, enum in (("statuses", EndpointStatus), ("presence_states", PresenceState)):
            values=tuple(enum(x) for x in getattr(self,name));
            if len(values)>10: raise ValueError(f"{name} supports at most 10 values")
            object.__setattr__(self,name,tuple(dict.fromkeys(values)))
        for name in ("platforms", "architectures", "agent_versions"):
            values=tuple(str(x).strip() for x in getattr(self,name) if str(x).strip())
            if len(values)>10 or any(len(x)>100 for x in values): raise ValueError(f"{name} contains too many or long values")
            object.__setattr__(self,name,tuple(dict.fromkeys(values)))
        object.__setattr__(self,"sort_by",FleetSortField(self.sort_by)); object.__setattr__(self,"direction",SortDirection(self.direction))
        if self.limit <= 0 or self.limit > 200: raise ValueError("limit must be between 1 and 200")
        if self.offset < 0: raise ValueError("offset must be non-negative")

@dataclass(frozen=True)
class FleetEndpointSummary:
    endpoint_id: str
    hostname: str
    lifecycle_status: EndpointStatus
    presence_state: PresenceState = PresenceState.UNKNOWN
    last_seen_at: Optional[object] = None
    platform: str = ""
    platform_version: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: Optional[str] = None
    created_at: Optional[object] = None
    updated_at: Optional[object] = None

    def to_dict(self):
        def iso(v): return v.isoformat() if v is not None else None
        return {"endpoint_id": self.endpoint_id, "hostname": self.hostname, "lifecycle_status": self.lifecycle_status.value,
                "status": self.lifecycle_status.value, "presence_state": self.presence_state.value, "last_seen_at": iso(self.last_seen_at),
                "platform": self.platform, "platform_version": self.platform_version, "architecture": self.architecture,
                "agent_version": self.agent_version, "created_at": iso(self.created_at), "updated_at": iso(self.updated_at)}

@dataclass(frozen=True)
class FleetPage:
    items: tuple[FleetEndpointSummary, ...]
    limit: int
    offset: int
    total: int
    @property
    def returned(self): return len(self.items)
    def to_dict(self): return {"items":[x.to_dict() for x in self.items],"limit":self.limit,"offset":self.offset,"returned":self.returned,"total":self.total}
