"""Explicit organization lifecycle operations; membership is not authorization."""
from datetime import datetime, timezone
from ...domain.organization import (MembershipId, MembershipStatus, Organization,
    OrganizationId, OrganizationMembership, OrganizationStatus)
from ...domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource,
    SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal)
from ...domain.user import UserId

def _now(clock): return (clock or (lambda: datetime.now(timezone.utc)))()

class _Service:
    def __init__(self, *, authorization_service=None, audit_sink=None, clock=None): self.authorization_service=authorization_service; self.audit_sink=audit_sink; self.clock=clock
    def _require(self,principal,action,resource_type,resource_id=None):
        if self.authorization_service: self.authorization_service.require(AuthorizationRequest(principal,action,AuthorizationResource(resource_type,resource_id)))
    def _audit(self,event_type,principal,resource,action=None):
        if self.audit_sink: self.audit_sink.append(SecurityAuditEvent(event_type=event_type.value,principal=principal,resource=resource,action=action,outcome=SecurityAuditOutcome.SUCCESS))

class OrganizationService(_Service):
    def __init__(self,repository,**kwargs): super().__init__(**kwargs); self.repository=repository
    def create(self,name,*,principal=None,metadata=None):
        principal=principal or SecurityPrincipal.system(); self._require(principal,AuthorizationAction.ORGANIZATION_CREATE,"organization")
        now=_now(self.clock); org=Organization(OrganizationId.new(),name,OrganizationStatus.ACTIVE,now,now,metadata or {}); self.repository.add(org); self._audit(SecurityAuditEventType.ORGANIZATION_CREATED,principal,AuthorizationResource("organization",str(org.organization_id)),AuthorizationAction.ORGANIZATION_CREATE); return org
    def update(self,organization_id,*,name=None,metadata=None,principal):
        self._require(principal,AuthorizationAction.ORGANIZATION_UPDATE,"organization",str(organization_id)); old=self.repository.get(organization_id)
        if old is None: raise KeyError("organization does not exist")
        org=Organization(old.organization_id,name if name is not None else old.name,old.status,old.created_at,_now(self.clock),metadata if metadata is not None else old.metadata); self.repository.update(org); self._audit(SecurityAuditEventType.ORGANIZATION_UPDATED,principal,AuthorizationResource("organization",str(org.organization_id)),AuthorizationAction.ORGANIZATION_UPDATE); return org
    def suspend(self,organization_id,*,principal): return self._transition(organization_id,OrganizationStatus.SUSPENDED,principal)
    def revoke(self,organization_id,*,principal): return self._transition(organization_id,OrganizationStatus.REVOKED,principal)
    def _transition(self,organization_id,status,principal):
        action=AuthorizationAction.ORGANIZATION_SUSPEND if status is OrganizationStatus.SUSPENDED else AuthorizationAction.ORGANIZATION_REVOKE; self._require(principal,action,"organization",str(organization_id)); old=self.repository.get(organization_id)
        if old is None: raise KeyError("organization does not exist")
        org=old.transition_to(status,_now(self.clock)); self.repository.update(org); self._audit(SecurityAuditEventType.ORGANIZATION_SUSPENDED if status is OrganizationStatus.SUSPENDED else SecurityAuditEventType.ORGANIZATION_REVOKED,principal,AuthorizationResource("organization",str(org.organization_id)),action); return org

class OrganizationMembershipService(_Service):
    def __init__(self,repository,organization_repository=None,user_repository=None,**kwargs): super().__init__(**kwargs); self.repository=repository; self.organization_repository=organization_repository; self.user_repository=user_repository
    def create(self,user_id,organization_id,*,principal=None,metadata=None):
        principal=principal or SecurityPrincipal.system(); self._require(principal,AuthorizationAction.MEMBERSHIP_CREATE,"organization",str(organization_id))
        uid=UserId.parse(user_id); oid=OrganizationId.parse(organization_id)
        if self.organization_repository and self.organization_repository.get(oid) is None: raise KeyError("organization does not exist")
        if self.user_repository and self.user_repository.get_user(uid) is None: raise KeyError("user does not exist")
        now=_now(self.clock); m=OrganizationMembership(MembershipId.new(),uid,oid,MembershipStatus.ACTIVE,now,now,metadata or {}); self.repository.add(m); self._audit(SecurityAuditEventType.MEMBERSHIP_CREATED,principal,AuthorizationResource("membership",str(m.membership_id)),AuthorizationAction.MEMBERSHIP_CREATE); return m
    def suspend(self,membership_id,*,principal): return self._transition(membership_id,MembershipStatus.SUSPENDED,principal)
    def revoke(self,membership_id,*,principal): return self._transition(membership_id,MembershipStatus.REVOKED,principal)
    def _transition(self,membership_id,status,principal):
        action=AuthorizationAction.MEMBERSHIP_SUSPEND if status is MembershipStatus.SUSPENDED else AuthorizationAction.MEMBERSHIP_REVOKE; self._require(principal,action,"membership",str(membership_id)); old=self.repository.get(membership_id)
        if old is None: raise KeyError("membership does not exist")
        m=old.transition_to(status,_now(self.clock)); self.repository.update(m); self._audit(SecurityAuditEventType.MEMBERSHIP_SUSPENDED if status is MembershipStatus.SUSPENDED else SecurityAuditEventType.MEMBERSHIP_REVOKED,principal,AuthorizationResource("membership",str(m.membership_id)),action); return m
