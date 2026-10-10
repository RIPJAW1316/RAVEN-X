from copy import deepcopy
from threading import RLock

from ...application.ports.endpoint_repository import DuplicateEndpointError
from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.organization import OrganizationId
from ...domain.fleet import FleetEndpointSummary, FleetPage, FleetSortField, SortDirection
from ...domain.presence import PresenceState


class InMemoryEndpointRepository:
    """Deterministic endpoint store; global get is reserved for internal paths."""
    def __init__(self):
        self._items = {}
        self._lock = RLock()

    def add(self, endpoint):
        key = EndpointId(endpoint.endpoint_id.value if hasattr(endpoint.endpoint_id, "value") else endpoint.endpoint_id)
        if key in self._items:
            raise DuplicateEndpointError("endpoint already exists")
        self._items[key] = deepcopy(endpoint)

    def get(self, endpoint_id):
        return deepcopy(self._items.get(EndpointId(endpoint_id.value if hasattr(endpoint_id, "value") else endpoint_id)))

    def list(self, status=None):
        values = sorted(self._items.values(), key=lambda x: (x.created_at, str(x.endpoint_id)))
        return tuple(deepcopy(x) for x in values if status is None or x.status is EndpointStatus(status))

    def update(self, endpoint):
        key = EndpointId(endpoint.endpoint_id.value if hasattr(endpoint.endpoint_id, "value") else endpoint.endpoint_id)
        if key not in self._items:
            raise KeyError("endpoint does not exist")
        existing = self._items[key]
        if existing.organization_id != endpoint.organization_id:
            raise ValueError("endpoint organization ownership is immutable")
        if existing.status is EndpointStatus.REVOKED and endpoint.status is not EndpointStatus.REVOKED:
            raise ValueError("revoked endpoint cannot be reactivated")
        self._items[key] = deepcopy(endpoint)

    def transition_status_for_organization(self, endpoint_id, organization_id, allowed_from, target, updated_at):
        key = EndpointId(str(endpoint_id))
        with self._lock:
            current = self._items.get(key)
            if current is None or current.organization_id != OrganizationId.parse(organization_id):
                raise KeyError("endpoint not found")
            if current.status not in frozenset(EndpointStatus(item) for item in allowed_from):
                raise ValueError("endpoint lifecycle conflict")
            updated = current.transition_to(EndpointStatus(target), updated_at)
            self._items[key] = deepcopy(updated)
            return deepcopy(updated)

    def exists(self, endpoint_id):
        return EndpointId(endpoint_id.value if hasattr(endpoint_id, "value") else endpoint_id) in self._items

    def get_for_organization(self, endpoint_id, organization_id):
        endpoint = self.get(endpoint_id)
        return endpoint if endpoint is not None and endpoint.organization_id == OrganizationId.parse(organization_id) else None

    def list_for_organization(self, organization_id, status=None):
        oid = OrganizationId.parse(organization_id)
        return tuple(x for x in self.list(status) if x.organization_id == oid)

    def exists_for_organization(self, endpoint_id, organization_id):
        return self.get_for_organization(endpoint_id, organization_id) is not None

    def query_for_organization(self, organization_id, query, *, presence_repository=None):
        oid=OrganizationId.parse(organization_id); items=[]
        for endpoint in self._items.values():
            if endpoint.organization_id != oid: continue
            if query.search and query.search.casefold() not in endpoint.hostname.casefold(): continue
            if query.statuses and endpoint.status not in query.statuses: continue
            if query.platforms and endpoint.platform.name not in query.platforms: continue
            if query.architectures and (endpoint.platform.architecture not in query.architectures): continue
            if query.agent_versions and (endpoint.agent is None or endpoint.agent.agent_version not in query.agent_versions): continue
            p=presence_repository.get(str(endpoint.endpoint_id)) if presence_repository is not None else None
            state=p.state if p is not None and p.organization_id in (None,str(oid)) else PresenceState.UNKNOWN
            if query.presence_states and state not in query.presence_states: continue
            items.append(FleetEndpointSummary(str(endpoint.endpoint_id),endpoint.hostname,endpoint.status,state,p.last_seen_at if p else None,endpoint.platform.name,endpoint.platform.version,endpoint.platform.architecture,endpoint.agent.agent_version if endpoint.agent else None,endpoint.created_at,endpoint.updated_at))
        key=lambda x: {FleetSortField.HOSTNAME:x.hostname.casefold(),FleetSortField.CREATED_AT:x.created_at or "",FleetSortField.UPDATED_AT:x.updated_at or "",FleetSortField.STATUS:x.lifecycle_status.value,FleetSortField.LAST_SEEN:x.last_seen_at or "",FleetSortField.PLATFORM:x.platform.casefold(),FleetSortField.AGENT_VERSION:x.agent_version or ""}[query.sort_by]
        items.sort(key=lambda x:(key(x),x.endpoint_id),reverse=query.direction is SortDirection.DESC)
        return FleetPage(tuple(items[query.offset:query.offset+query.limit]),query.limit,query.offset,len(items))
