from datetime import datetime, timezone
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.fleet import FleetQuery
from backend.domain.group_scope import GroupStatus
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_group_scope_repository import InMemoryEndpointGroupRepository, InMemorySavedFleetScopeRepository
from backend.application.fleet.groups import TenantEndpointGroupService, TenantSavedFleetScopeService
from backend.application.fleet.service import TenantFleetQueryService
from backend.application.organization.context import OrganizationContext
from backend.domain.security import SecurityPrincipal
from backend.domain.user import UserId
NOW=datetime(2026,1,1,tzinfo=timezone.utc)
class Allow:
    def authorize(self,r): return type("D",(),{"allowed":True,"reason_code":"allowed"})()
def ep(o,n): return Endpoint(EndpointId.new(),n,PlatformInfo("Windows"),organization_id=o,created_at=NOW,updated_at=NOW)
def test_static_group_membership_and_scope_resolution_are_distinct():
    o=OrganizationId.new(); u=UserId.new(); c=OrganizationContext(o,"m",u,resolved_at=NOW); p=SecurityPrincipal.human(u); e=ep(o,"prod-1"); er=InMemoryEndpointRepository(); er.add(e)
    gr=InMemoryEndpointGroupRepository(); gs=TenantEndpointGroupService(gr,er,Allow(),clock=lambda:NOW); g=gs.create(p,c,"Production"); gs.add_members(p,c,g.group_id,[e.endpoint_id]); assert gs.get(p,c,g.group_id).member_count==1
    scope_repo=InMemorySavedFleetScopeRepository(); scope=TenantSavedFleetScopeService(scope_repo,TenantFleetQueryService(er,Allow()),Allow(),clock=lambda:NOW); s=scope.create(p,c,"Prod",FleetQuery(search="prod")); assert scope.resolve(p,c,s.scope_id,FleetQuery()).total==1
    assert g.status is GroupStatus.ACTIVE and s.organization_id==o
