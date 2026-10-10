from dataclasses import replace
from datetime import datetime, timezone
from ...domain.group_scope import *
from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent, SecurityAuditOutcome

class TenantEndpointGroupService:
    def __init__(self,repo,endpoints,authorizer,*,clock=None,max_members=200,metrics=None,audit_sink=None): self.repo=repo; self.endpoints=endpoints; self.auth=authorizer; self.clock=clock; self.max_members=max_members; self.metrics=metrics; self.audit_sink=audit_sink
    def _check(self,p,c,a,i=None):
        if p.principal_type.value!="human" or c is None: raise PermissionError("human context required")
        d=self.auth.authorize(AuthorizationRequest(p,a,AuthorizationResource("endpoint_group",str(i) if i else None,{"organization_id":str(c.organization_id)}),organization_context=c))
        if not d.allowed: raise PermissionError(d.reason_code)
    def create(self,p,c,name,description=""):
        self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_CREATE); now=self._now(); g=EndpointGroup(EndpointGroupId.new(),c.organization_id,name,description,created_by=p.principal_id,created_at=now,updated_at=now); self.repo.add(g); self._metric("endpoint_group.mutations"); self._audit("endpoint_group.create",p,g); return g
    def list(self,p,c): self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_READ); return self.repo.list_for_organization(c.organization_id)
    def get(self,p,c,i):
        self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_READ,i); g=self.repo.get(i)
        if g is None or g.organization_id!=c.organization_id: raise KeyError("group not found")
        return EndpointGroupSummary(g,self.repo.count(i))
    def update(self,p,c,i,name=None,description=None):
        current=self.get(p,c,i).group
        if current.status is GroupStatus.REVOKED: raise ValueError("group is revoked")
        self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_UPDATE,i); updated=replace(current,name=name if name is not None else current.name,description=description if description is not None else current.description,updated_at=self._now()); self.repo.update(updated); self._metric("endpoint_group.mutations"); self._audit("endpoint_group.update",p,updated); return updated
    def add_members(self,p,c,i,endpoint_ids):
        g=self.get(p,c,i).group
        if g.status is GroupStatus.REVOKED: raise ValueError("group is revoked")
        self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_MEMBERSHIP_UPDATE,i); ids=tuple(endpoint_ids or ())
        if not ids or len(ids)>self.max_members or self.repo.count(i)+len(ids)>self.max_members: raise ValueError("member limit exceeded")
        endpoints=[]
        for value in ids:
            e=self.endpoints.get_for_organization(value if isinstance(value, EndpointId) else EndpointId(value),c.organization_id)
            if e is None or e.status is EndpointStatus.REVOKED: raise ValueError("invalid endpoint membership")
            if self.repo.contains(i,e.endpoint_id): continue
            endpoints.append(e.endpoint_id)
        self.repo.add_members(i,endpoints,p.principal_id,c.organization_id); self._metric("endpoint_group.mutations"); self._audit("endpoint_group.members_added",p,g,{"count":len(endpoints)}); return self.get(p,c,i)
    def remove_members(self,p,c,i,endpoint_ids):
        g=self.get(p,c,i).group
        if g.status is GroupStatus.REVOKED: raise ValueError("group is revoked")
        self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_MEMBERSHIP_UPDATE,i); values=tuple(endpoint_ids or ()); self.repo.remove_members(i,values); self._metric("endpoint_group.mutations"); self._audit("endpoint_group.members_removed",p,g,{"count":len(values)}); return self.get(p,c,i)
    def members(self,p,c,i,limit=50,offset=0):
        self.get(p,c,i); self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_READ,i); ids=self.repo.list_members(i,limit,offset); return tuple(e for x in ids if (e:=self.endpoints.get_for_organization(x,c.organization_id)) is not None)
    def revoke(self,p,c,i):
        g=self.get(p,c,i).group; self._check(p,c,AuthorizationAction.ENDPOINT_GROUP_REVOKE,i); updated=g.revoke(self._now()); self.repo.update(updated); self._metric("endpoint_group.mutations"); self._audit("endpoint_group.revoke",p,updated); return self.get(p,c,i)
    def _metric(self,name):
        if self.metrics is not None: self.metrics.increment(name)
    def _audit(self,event,principal,group,metadata=None):
        if self.audit_sink is not None: self.audit_sink.append(SecurityAuditEvent(event_type=event,principal=principal,outcome=SecurityAuditOutcome.SUCCESS,organization_id=str(group.organization_id),resource=AuthorizationResource("endpoint_group",str(group.group_id)),metadata=metadata or {}))
    def _now(self): return (self.clock or (lambda:datetime.now(timezone.utc)))()

class TenantSavedFleetScopeService:
    def __init__(self,repo,fleet_service,authorizer,*,clock=None,metrics=None,audit_sink=None): self.repo=repo; self.fleet=fleet_service; self.auth=authorizer; self.clock=clock; self.metrics=metrics; self.audit_sink=audit_sink
    def _check(self,p,c,a,i=None):
        if p.principal_type.value!="human" or c is None: raise PermissionError("human context required")
        d=self.auth.authorize(AuthorizationRequest(p,a,AuthorizationResource("fleet_scope",str(i) if i else None,{"organization_id":str(c.organization_id)}),organization_context=c))
        if not d.allowed: raise PermissionError(d.reason_code)
    def create(self,p,c,name,query,description=""):
        self._check(p,c,AuthorizationAction.FLEET_SCOPE_CREATE); from ...domain.group_scope import fleet_query_from_dict
        q=query if isinstance(query,FleetQuery) else fleet_query_from_dict(query); now=self._now(); x=SavedFleetScope(SavedFleetScopeId.new(),c.organization_id,name,q,description,created_by=p.principal_id,created_at=now,updated_at=now); self.repo.add(x); self._metric("fleet_scope.mutations"); self._audit("fleet_scope.create",p,x); return x
    def list(self,p,c): self._check(p,c,AuthorizationAction.FLEET_SCOPE_READ); return self.repo.list_for_organization(c.organization_id)
    def get(self,p,c,i):
        self._check(p,c,AuthorizationAction.FLEET_SCOPE_READ,i); x=self.repo.get(i)
        if x is None or x.organization_id!=c.organization_id: raise KeyError("scope not found")
        return x
    def update(self,p,c,i,**changes):
        x=self.get(p,c,i)
        if x.status is ScopeStatus.REVOKED: raise ValueError("scope is revoked")
        self._check(p,c,AuthorizationAction.FLEET_SCOPE_UPDATE,i); q=changes.get("query",x.fleet_query); from ...domain.group_scope import fleet_query_from_dict; q=q if isinstance(q,FleetQuery) else fleet_query_from_dict(q); y=replace(x,name=changes.get("name",x.name),description=changes.get("description",x.description),fleet_query=q,updated_at=self._now()); self.repo.update(y); self._metric("fleet_scope.mutations"); self._audit("fleet_scope.update",p,y); return y
    def revoke(self,p,c,i):
        x=self.get(p,c,i); self._check(p,c,AuthorizationAction.FLEET_SCOPE_REVOKE,i); y=x.revoke(self._now()); self.repo.update(y); self._metric("fleet_scope.mutations"); self._audit("fleet_scope.revoke",p,y); return y
    def resolve(self,p,c,i,query):
        x=self.get(p,c,i)
        if x.status is ScopeStatus.REVOKED: raise ValueError("scope is revoked")
        self._check(p,c,AuthorizationAction.ENDPOINT_READ,i); self._metric("fleet_scope.resolutions")
        try:
            return self.fleet.query(p,c,replace(x.fleet_query,limit=query.limit,offset=query.offset,sort_by=query.sort_by,direction=query.direction))
        except Exception:
            self._metric("fleet_scope.resolution_failures")
            raise
    def _metric(self,name):
        if self.metrics is not None: self.metrics.increment(name)
    def _audit(self,event,principal,scope):
        if self.audit_sink is not None: self.audit_sink.append(SecurityAuditEvent(event_type=event,principal=principal,outcome=SecurityAuditOutcome.SUCCESS,organization_id=str(scope.organization_id),resource=AuthorizationResource("fleet_scope",str(scope.scope_id)),metadata={"query_version":scope.query_version}))
    def _now(self): return (self.clock or (lambda:datetime.now(timezone.utc)))()
