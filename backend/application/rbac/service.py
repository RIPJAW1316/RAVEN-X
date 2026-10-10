from datetime import datetime, timezone
from ...domain.organization import MembershipId, OrganizationId, OrganizationMembership
from ...domain.rbac import Permission, Role, RoleBinding, RoleBindingId, RoleBindingStatus, RoleId, RoleStatus
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal

def _now(clock): return (clock or (lambda:datetime.now(timezone.utc)))()
class _Service:
    def __init__(self,*,authorization_service=None,audit_sink=None,clock=None): self.authorization_service=authorization_service;self.audit_sink=audit_sink;self.clock=clock
    def _require(self,principal,action,resource_type,resource_id=None):
        if self.authorization_service:self.authorization_service.require(AuthorizationRequest(principal,action,AuthorizationResource(resource_type,resource_id)))
    def _audit(self,event_type,principal,resource,action=None,metadata=None):
        if self.audit_sink:self.audit_sink.append(SecurityAuditEvent(event_type=event_type.value,principal=principal,resource=resource,action=action,outcome=SecurityAuditOutcome.SUCCESS,metadata=metadata or {}))

class RoleService(_Service):
    def __init__(self,repository,**kwargs):super().__init__(**kwargs);self.repository=repository
    def create(self,organization_id,name,permissions,*,principal=None,description="",metadata=None):
        principal=principal or SecurityPrincipal.system();self._require(principal,AuthorizationAction.ROLE_CREATE,"organization",str(organization_id));now=_now(self.clock);role=Role(RoleId.new(),OrganizationId.parse(organization_id),name,description,frozenset(Permission(x) for x in permissions),RoleStatus.ACTIVE,now,now,metadata or {});self.repository.add(role);self._audit(SecurityAuditEventType.ROLE_CREATED,principal,AuthorizationResource("role",str(role.role_id)),AuthorizationAction.ROLE_CREATE, {"organization_id":str(role.organization_id)});return role
    def update(self,role_id,*,name=None,description=None,permissions=None,metadata=None,principal):
        old=self.repository.get(role_id)
        if old is None:raise KeyError("role does not exist")
        self._require(principal,AuthorizationAction.ROLE_UPDATE,"role",str(role_id));role=Role(old.role_id,old.organization_id,name if name is not None else old.name,description if description is not None else old.description,frozenset(Permission(x) for x in (permissions if permissions is not None else old.permissions)),old.status,old.created_at,_now(self.clock),metadata if metadata is not None else old.metadata);self.repository.update(role);self._audit(SecurityAuditEventType.ROLE_UPDATED,principal,AuthorizationResource("role",str(role.role_id)),AuthorizationAction.ROLE_UPDATE,{"old_permissions":sorted(str(x) for x in old.permissions),"new_permissions":sorted(str(x) for x in role.permissions)});return role
    def disable(self,role_id,*,principal):return self._transition(role_id,RoleStatus.DISABLED,principal)
    def revoke(self,role_id,*,principal):return self._transition(role_id,RoleStatus.REVOKED,principal)
    def _transition(self,role_id,status,principal):
        old=self.repository.get(role_id)
        if old is None:raise KeyError("role does not exist")
        action=AuthorizationAction.ROLE_DISABLE if status is RoleStatus.DISABLED else AuthorizationAction.ROLE_REVOKE;self._require(principal,action,"role",str(role_id));role=old.transition_to(status,_now(self.clock));self.repository.update(role);self._audit(SecurityAuditEventType.ROLE_DISABLED if status is RoleStatus.DISABLED else SecurityAuditEventType.ROLE_REVOKED,principal,AuthorizationResource("role",str(role.role_id)),action);return role

class RoleBindingService(_Service):
    def __init__(self,repository,role_repository,membership_repository,**kwargs):super().__init__(**kwargs);self.repository=repository;self.role_repository=role_repository;self.membership_repository=membership_repository
    def create(self,organization_id,membership_id,role_id,*,principal=None,metadata=None):
        principal=principal or SecurityPrincipal.system();self._require(principal,AuthorizationAction.ROLE_BINDING_CREATE,"membership",str(membership_id));oid=OrganizationId.parse(organization_id);membership=self.membership_repository.get(membership_id);role=self.role_repository.get(role_id)
        if membership is None:raise KeyError("membership does not exist")
        if role is None:raise KeyError("role does not exist")
        if membership.organization_id!=oid or role.organization_id!=oid or membership.organization_id!=role.organization_id:raise ValueError("role binding organization mismatch")
        now=_now(self.clock);binding=RoleBinding(RoleBindingId.new(),oid,MembershipId.parse(membership_id),RoleId.parse(role_id),RoleBindingStatus.ACTIVE,now,now,metadata or {});self.repository.add(binding);self._audit(SecurityAuditEventType.ROLE_BINDING_CREATED,principal,AuthorizationResource("role_binding",str(binding.role_binding_id)),AuthorizationAction.ROLE_BINDING_CREATE,{"organization_id":str(oid),"membership_id":str(membership_id),"role_id":str(role_id)});return binding
    def disable(self,binding_id,*,principal):return self._transition(binding_id,RoleBindingStatus.DISABLED,principal)
    def revoke(self,binding_id,*,principal):return self._transition(binding_id,RoleBindingStatus.REVOKED,principal)
    def _transition(self,binding_id,status,principal):
        binding=self.repository.get(binding_id)
        if binding is None:raise KeyError("role binding does not exist")
        action=AuthorizationAction.ROLE_BINDING_UPDATE if status is RoleBindingStatus.DISABLED else AuthorizationAction.ROLE_BINDING_REVOKE;self._require(principal,action,"role_binding",str(binding_id));updated=binding.transition_to(status,_now(self.clock));self.repository.update(updated);self._audit(SecurityAuditEventType.ROLE_BINDING_DISABLED if status is RoleBindingStatus.DISABLED else SecurityAuditEventType.ROLE_BINDING_REVOKED,principal,AuthorizationResource("role_binding",str(binding_id)),action);return updated
