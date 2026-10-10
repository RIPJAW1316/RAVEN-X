from datetime import timezone
from sqlalchemy import select, func
from ...core.database.models import EndpointGroupRecord,EndpointGroupMembershipRecord,SavedFleetScopeRecord
from ...domain.group_scope import *
from ...domain.endpoint import EndpointId

def _s(v): return v.astimezone(timezone.utc).replace(tzinfo=None)
def _l(v): return v.replace(tzinfo=timezone.utc)
def _g(r): return EndpointGroup(EndpointGroupId(r.group_id),r.organization_id,r.name,r.description,GroupStatus(r.status),r.created_by,_l(r.created_at),_l(r.updated_at))
def _scope(r): return SavedFleetScope(SavedFleetScopeId(r.scope_id),r.organization_id,r.name,fleet_query_from_dict(r.criteria_json),r.description,ScopeStatus(r.status),r.created_by,_l(r.created_at),_l(r.updated_at),r.query_version)

class SQLAlchemyEndpointGroupRepository:
    def __init__(self,db): self.db=db
    def add(self,g):
        with self.db.get_db() as s:
            s.add(EndpointGroupRecord(group_id=str(g.group_id),organization_id=str(g.organization_id),name=g.name,description=g.description,status=g.status.value,created_by=g.created_by,created_at=_s(g.created_at),updated_at=_s(g.updated_at))); s.flush()
    def get(self,i):
        with self.db.get_db() as s:
            r=s.get(EndpointGroupRecord,str(i)); return _g(r) if r else None
    def update(self,g):
        with self.db.get_db() as s:
            r=s.get(EndpointGroupRecord,str(g.group_id));
            if not r: raise KeyError("group not found")
            r.name=g.name; r.description=g.description; r.status=g.status.value; r.updated_at=_s(g.updated_at)
    def list_for_organization(self,o):
        with self.db.get_db() as s:
            rows=s.execute(select(EndpointGroupRecord,func.count(EndpointGroupMembershipRecord.endpoint_id)).outerjoin(EndpointGroupMembershipRecord,EndpointGroupMembershipRecord.group_id==EndpointGroupRecord.group_id).where(EndpointGroupRecord.organization_id==str(o)).group_by(EndpointGroupRecord.group_id).order_by(EndpointGroupRecord.created_at)).all(); return tuple(EndpointGroupSummary(_g(r),int(c)) for r,c in rows)
    def add_members(self,g,endpoint_ids,added_by=None,organization_id=None):
        with self.db.get_db() as s:
            for e in endpoint_ids: s.add(EndpointGroupMembershipRecord(group_id=str(g),endpoint_id=str(e),organization_id=str(organization_id),added_at=_s(__import__('datetime').datetime.now(__import__('datetime').timezone.utc)),added_by=added_by))
    def remove_members(self,g,endpoint_ids):
        with self.db.get_db() as s:
            for e in endpoint_ids:
                r=s.get(EndpointGroupMembershipRecord,(str(g),str(e)))
                if r: s.delete(r)
    def list_members(self,g,limit=50,offset=0):
        with self.db.get_db() as s: return tuple(r.endpoint_id for r in s.execute(select(EndpointGroupMembershipRecord).where(EndpointGroupMembershipRecord.group_id==str(g)).order_by(EndpointGroupMembershipRecord.endpoint_id).offset(offset).limit(limit)).scalars())
    def contains(self,g,e):
        with self.db.get_db() as s: return s.get(EndpointGroupMembershipRecord,(str(g),str(e))) is not None
    def count(self,g):
        with self.db.get_db() as s: return int(s.scalar(select(func.count()).select_from(EndpointGroupMembershipRecord).where(EndpointGroupMembershipRecord.group_id==str(g))) or 0)

class SQLAlchemySavedFleetScopeRepository:
    def __init__(self,db): self.db=db
    def add(self,x):
        with self.db.get_db() as s: s.add(SavedFleetScopeRecord(scope_id=str(x.scope_id),organization_id=str(x.organization_id),name=x.name,description=x.description,status=x.status.value,query_version=x.query_version,criteria_json={"search":x.fleet_query.search,"statuses":[i.value for i in x.fleet_query.statuses],"presence_states":[i.value for i in x.fleet_query.presence_states],"platforms":list(x.fleet_query.platforms),"architectures":list(x.fleet_query.architectures),"agent_versions":list(x.fleet_query.agent_versions),"sort_by":x.fleet_query.sort_by.value,"direction":x.fleet_query.direction.value},created_by=x.created_by,created_at=_s(x.created_at),updated_at=_s(x.updated_at)))
    def get(self,i):
        with self.db.get_db() as s:
            r=s.get(SavedFleetScopeRecord,str(i)); return _scope(r) if r else None
    def update(self,x):
        with self.db.get_db() as s:
            r=s.get(SavedFleetScopeRecord,str(x.scope_id));
            if not r: raise KeyError("scope not found")
            r.name=x.name; r.description=x.description; r.status=x.status.value; r.criteria_json={"search":x.fleet_query.search,"statuses":[i.value for i in x.fleet_query.statuses],"presence_states":[i.value for i in x.fleet_query.presence_states],"platforms":list(x.fleet_query.platforms),"architectures":list(x.fleet_query.architectures),"agent_versions":list(x.fleet_query.agent_versions),"sort_by":x.fleet_query.sort_by.value,"direction":x.fleet_query.direction.value}; r.updated_at=_s(x.updated_at)
    def list_for_organization(self,o):
        with self.db.get_db() as s: return tuple(_scope(r) for r in s.execute(select(SavedFleetScopeRecord).where(SavedFleetScopeRecord.organization_id==str(o)).order_by(SavedFleetScopeRecord.created_at)).scalars())
