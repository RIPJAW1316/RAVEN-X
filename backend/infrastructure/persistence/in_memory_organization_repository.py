from copy import deepcopy
from ...domain.organization import Organization, OrganizationId, OrganizationStatus
from ...application.ports.organization_repository import DuplicateOrganizationError
class InMemoryOrganizationRepository:
    def __init__(self): self._items={}
    def add(self, organization):
        key=OrganizationId.parse(organization.organization_id)
        if key in self._items: raise DuplicateOrganizationError("organization already exists")
        self._items[key]=deepcopy(organization)
    def get(self, organization_id): return deepcopy(self._items.get(OrganizationId.parse(organization_id)))
    def list(self,status=None): return tuple(deepcopy(v) for v in sorted(self._items.values(),key=lambda x:(x.created_at,str(x.organization_id))) if status is None or v.status is OrganizationStatus(status))
    def update(self, organization):
        key=OrganizationId.parse(organization.organization_id)
        if key not in self._items: raise KeyError("organization does not exist")
        self._items[key]=deepcopy(organization)
    def exists(self, organization_id): return OrganizationId.parse(organization_id) in self._items
    add_organization=add; get_organization=get
