"""Organization-scoped security activity read boundary.

The service authorizes first and queries second. It never accepts an
organization identifier from the caller: the tenant always comes from the
resolved `OrganizationContext`, so a request cannot address another tenant's
history.
"""
from ...domain.audit import AuditPage, AuditQuery
from ...domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource,
                                PrincipalType)
from ..organization.context import OrganizationContext


class TenantAuditQueryService:
    def __init__(self, audit_repository, authorizer, *, metrics=None, logger=None):
        self.audit_repository = audit_repository
        self.authorizer = authorizer
        self.metrics = metrics
        self.logger = logger

    def query(self, principal, context, query: AuditQuery) -> AuditPage:
        self._require_human_context(principal, context)
        self._authorize(principal, context)
        if not isinstance(query, AuditQuery):
            raise ValueError("query must be an AuditQuery")
        # The organization comes from the verified context, never the request.
        page = self.audit_repository.query_for_organization(context.organization_id, query)
        if self.metrics is not None:
            self.metrics.increment("audit_feed.requests")
        return page

    @staticmethod
    def _require_human_context(principal, context):
        if getattr(principal, "principal_type", None) is not PrincipalType.HUMAN:
            raise PermissionError("human principal required")
        if not isinstance(context, OrganizationContext):
            raise PermissionError("organization context required")

    def _authorize(self, principal, context):
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal,
            AuthorizationAction.AUDIT_READ,
            AuthorizationResource("audit", None, {"organization_id": str(context.organization_id)}),
            organization_context=context,
        ))
        if not decision.allowed:
            if self.metrics is not None:
                self.metrics.increment("audit_feed.denied")
            raise PermissionError(getattr(decision, "reason_code", "permission_denied"))
