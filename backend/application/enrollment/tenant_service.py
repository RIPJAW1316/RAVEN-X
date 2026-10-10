"""Human, organization-scoped enrollment administration."""

from datetime import datetime, timedelta, timezone

from ...domain.enrollment import EnrollmentId
from ...domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType,
    SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome,
)
from ..organization.context import OrganizationContext
from .service import EnrollmentService


class TenantEnrollmentService:
    def __init__(self, repository, authorizer, *, audit_sink=None):
        self.repository = repository
        self.authorizer = authorizer
        self.audit_sink = audit_sink

    def create(self, principal, context, *, ttl_minutes=60, label=""):
        self._require(principal, context, AuthorizationAction.ENROLLMENT_CREATE)
        if isinstance(ttl_minutes, bool) or not isinstance(ttl_minutes, int) or not 1 <= ttl_minutes <= 1440:
            raise ValueError("ttl_minutes must be between 1 and 1440")
        if not isinstance(label, str) or len(label) > 80 or not label.isprintable():
            raise ValueError("label must be at most 80 printable characters")
        service = EnrollmentService(
            self.repository, audit_sink=self.audit_sink, principal=principal,
            membership_id=context.membership_id,
        )
        return service.create_enrollment_authorization(
            ttl=timedelta(minutes=ttl_minutes), organization_id=context.organization_id,
            metadata={"label": label.strip()},
        )

    def list(self, principal, context):
        self._require(principal, context, AuthorizationAction.ENROLLMENT_CREATE)
        return self.repository.list_authorizations_for_organization(context.organization_id)

    def revoke(self, principal, context, enrollment_id):
        self._require(principal, context, AuthorizationAction.ENROLLMENT_REVOKE)
        enrollment_id = EnrollmentId.parse(str(enrollment_id))
        authorization = self.repository.get_authorization_for_organization(enrollment_id, context.organization_id)
        if authorization is None:
            raise KeyError("enrollment authorization not found")
        changed = self.repository.revoke_authorization_for_organization(
            enrollment_id, context.organization_id, datetime.now(timezone.utc),
        )
        if changed and self.audit_sink is not None:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=SecurityAuditEventType.ENROLLMENT_REVOKED.value,
                principal=principal, outcome=SecurityAuditOutcome.SUCCESS,
                user_id=principal.principal_id, organization_id=str(context.organization_id),
                membership_id=context.membership_id,
                metadata={"enrollment_id": str(enrollment_id)},
            ))
        return self.repository.get_authorization_for_organization(enrollment_id, context.organization_id)

    def _require(self, principal, context, action):
        if principal.principal_type is not PrincipalType.HUMAN or not isinstance(context, OrganizationContext):
            raise PermissionError("verified human organization context required")
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, action,
            AuthorizationResource("enrollment", None, {"organization_id": str(context.organization_id)}),
            organization_context=context,
        ))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
