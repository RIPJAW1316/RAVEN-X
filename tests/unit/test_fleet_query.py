from datetime import datetime, timezone
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.fleet import FleetQuery, FleetSortField, SortDirection
from backend.domain.presence import EndpointPresence, PresenceState
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository

NOW=datetime(2026,1,1,tzinfo=timezone.utc)
def ep(org,name,status=EndpointStatus.ACTIVE): return Endpoint(EndpointId.new(),name,PlatformInfo("Windows","11","x86_64"),status=status,organization_id=org,created_at=NOW,updated_at=NOW)
class Presence:
    def __init__(self,items): self.items={x.endpoint_id:x for x in items}
    def get(self,e): return self.items.get(str(e))
def test_fleet_query_filters_paginates_and_sorts():
    org=OrganizationId.new(); other=OrganizationId.new(); a=ep(org,"alpha-win"); b=ep(org,"beta-win",EndpointStatus.REVOKED); c=ep(org,"ALPHA-db"); r=InMemoryEndpointRepository()
    for x in (a,b,c,ep(other,"alpha-other")): r.add(x)
    p=Presence([EndpointPresence(str(a.endpoint_id),str(org),PresenceState.ONLINE,last_seen_at=NOW)])
    page=r.query_for_organization(org,FleetQuery(search="alpha",sort_by=FleetSortField.HOSTNAME,direction=SortDirection.ASC,limit=1),presence_repository=p)
    assert page.total==2 and page.returned==1 and page.items[0].hostname=="ALPHA-db"
def test_presence_unknown_and_status_or_filter():
    org=OrganizationId.new(); a=ep(org,"a"); b=ep(org,"b",EndpointStatus.REVOKED); r=InMemoryEndpointRepository(); r.add(a); r.add(b)
    q=FleetQuery(presence_states=(PresenceState.UNKNOWN,),statuses=(EndpointStatus.ACTIVE,EndpointStatus.REVOKED))
    page=r.query_for_organization(org,q); assert page.total==2
