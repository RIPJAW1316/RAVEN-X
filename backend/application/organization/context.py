"""Derived organization context for an authenticated human operation."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from ...domain.organization import MembershipStatus, OrganizationId, OrganizationStatus
from ...domain.security import (PrincipalType, SecurityAuditEvent, SecurityAuditEventType,
                                SecurityAuditOutcome, SecurityPrincipal)
from ...domain.user import UserId, UserStatus

class OrganizationContextReason(str, Enum):
    NOT_HUMAN_PRINCIPAL="NOT_HUMAN_PRINCIPAL"
    USER_NOT_FOUND="USER_NOT_FOUND"
    USER_INACTIVE="USER_INACTIVE"
    ORGANIZATION_NOT_FOUND="ORGANIZATION_NOT_FOUND"
    ORGANIZATION_SUSPENDED="ORGANIZATION_SUSPENDED"
    ORGANIZATION_REVOKED="ORGANIZATION_REVOKED"
    MEMBERSHIP_NOT_FOUND="MEMBERSHIP_NOT_FOUND"
    MEMBERSHIP_SUSPENDED="MEMBERSHIP_SUSPENDED"
    MEMBERSHIP_REVOKED="MEMBERSHIP_REVOKED"
    PRINCIPAL_MEMBERSHIP_MISMATCH="PRINCIPAL_MEMBERSHIP_MISMATCH"

class OrganizationContextError(PermissionError):
    def __init__(self, reason: OrganizationContextReason):
        self.reason_code=reason.value
        super().__init__(reason.value)

@dataclass(frozen=True)
class OrganizationContext:
    organization_id: OrganizationId
    membership_id: str
    user_id: UserId
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    def __post_init__(self):
        object.__setattr__(self,"organization_id",OrganizationId.parse(self.organization_id))
        object.__setattr__(self,"user_id",UserId.parse(self.user_id))
        if not isinstance(self.membership_id,str) or not self.membership_id.strip(): raise ValueError("membership_id is required")
        if self.resolved_at.tzinfo is None or self.resolved_at.utcoffset() is None: raise ValueError("resolved_at must be timezone-aware")
    def to_dict(self):
        return {"organization_id":str(self.organization_id),"membership_id":self.membership_id,"user_id":str(self.user_id),"resolved_at":self.resolved_at.astimezone(timezone.utc).isoformat()}

class OrganizationContextResolver:
    def __init__(self,user_repository,membership_repository,organization_repository,*,audit_sink=None,clock=None):
        self.user_repository=user_repository; self.membership_repository=membership_repository; self.organization_repository=organization_repository; self.audit_sink=audit_sink; self.clock=clock
    def resolve(self, principal: SecurityPrincipal, organization_id, *, membership_id: Optional[str]=None) -> OrganizationContext:
        requested=str(organization_id)
        try:
            if principal.principal_type is not PrincipalType.HUMAN: return self._deny(principal,OrganizationContextReason.NOT_HUMAN_PRINCIPAL,requested)
            try: user_id=UserId.parse(principal.principal_id)
            except (TypeError,ValueError): return self._deny(principal,OrganizationContextReason.USER_NOT_FOUND,requested)
            user=self.user_repository.get_user(user_id)
            if user is None: return self._deny(principal,OrganizationContextReason.USER_NOT_FOUND,requested)
            if user.status is not UserStatus.ACTIVE: return self._deny(principal,OrganizationContextReason.USER_INACTIVE,requested)
            try: org_id=OrganizationId.parse(organization_id)
            except (TypeError,ValueError): return self._deny(principal,OrganizationContextReason.ORGANIZATION_NOT_FOUND,requested)
            organization=self.organization_repository.get(org_id)
            if organization is None: return self._deny(principal,OrganizationContextReason.ORGANIZATION_NOT_FOUND,requested)
            if organization.status is OrganizationStatus.SUSPENDED: return self._deny(principal,OrganizationContextReason.ORGANIZATION_SUSPENDED,requested)
            if organization.status is OrganizationStatus.REVOKED: return self._deny(principal,OrganizationContextReason.ORGANIZATION_REVOKED,requested)
            membership=self.membership_repository.get_for_user_and_organization(user_id,org_id)
            if membership is None: return self._deny(principal,OrganizationContextReason.MEMBERSHIP_NOT_FOUND,requested)
            if membership_id is not None and str(membership.membership_id)!=str(membership_id): return self._deny(principal,OrganizationContextReason.PRINCIPAL_MEMBERSHIP_MISMATCH,requested,membership_id=str(membership_id),verified=True)
            if membership.status is MembershipStatus.SUSPENDED: return self._deny(principal,OrganizationContextReason.MEMBERSHIP_SUSPENDED,requested,membership_id=str(membership.membership_id),verified=True)
            if membership.status is MembershipStatus.REVOKED: return self._deny(principal,OrganizationContextReason.MEMBERSHIP_REVOKED,requested,membership_id=str(membership.membership_id),verified=True)
            return OrganizationContext(org_id,str(membership.membership_id),user_id,_now(self.clock))
        except OrganizationContextError: raise
    def _deny(self,principal,reason,organization_id,*,membership_id=None,verified=False):
        """Record a context denial.

        ``verified`` is True only once a membership linking this principal to
        the requested organization has been read back from the repository.
        Until then the organization is an unproven claim, and attributing the
        event to it would let any authenticated caller inject records into an
        arbitrary tenant's audit feed simply by naming it in a URL."""
        self._audit(principal,reason,organization_id if verified else None,membership_id if verified else None)
        raise OrganizationContextError(reason)
    def _audit(self,principal,reason,organization_id,membership_id):
        if self.audit_sink is not None:
            self.audit_sink.append(SecurityAuditEvent(event_type=SecurityAuditEventType.ORGANIZATION_CONTEXT_DENIED.value,principal=principal,outcome=SecurityAuditOutcome.DENIED,reason_code=reason.value,user_id=principal.principal_id if principal.principal_type is PrincipalType.HUMAN else None,organization_id=organization_id,membership_id=membership_id,metadata={"reason_code":reason.value}))

def _now(clock): return (clock or (lambda: datetime.now(timezone.utc)))()
