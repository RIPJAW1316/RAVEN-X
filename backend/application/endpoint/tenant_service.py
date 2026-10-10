"""Human organization-scoped endpoint operations.

This boundary deliberately never uses the global endpoint lookup for HUMAN
requests.  Global lookup remains an internal/agent-authentication primitive.
"""
from typing import Optional

from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus
from ...domain.organization import OrganizationId
from ...domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource,
                                 SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome,
                                 SecurityPrincipal)
from ..organization.context import OrganizationContext
from ..ports.endpoint_repository import DuplicateEndpointError


class TenantEndpointService:
    def __init__(self, repository, authorizer, *, audit_sink=None):
        self.repository = repository
        self.authorizer = authorizer
        self.audit_sink = audit_sink

    def register(self, principal: SecurityPrincipal, context: OrganizationContext, endpoint: Endpoint) -> Endpoint:
        self._context(principal, context)
        if endpoint.organization_id is None:
            raise ValueError("enterprise endpoint registration requires organization ownership")
        if endpoint.organization_id != context.organization_id:
            raise PermissionError("endpoint organization does not match context")
        # The endpoint does not exist yet; creation is authorized against the
        # active organization scope rather than a resource record.
        self._require(principal, context, AuthorizationAction.ENDPOINT_CREATE, None)
        if self.repository.exists(endpoint.endpoint_id):
            raise DuplicateEndpointError("endpoint already exists")
        self.repository.add(endpoint)
        self._audit(SecurityAuditEventType.ENDPOINT_REGISTERED, principal, endpoint, AuthorizationAction.ENDPOINT_CREATE, context)
        return endpoint

    def get(self, principal: SecurityPrincipal, context: OrganizationContext, endpoint_id: EndpointId) -> Endpoint:
        self._context(principal, context)
        endpoint = self.repository.get_for_organization(endpoint_id, context.organization_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        self._require(principal, context, AuthorizationAction.ENDPOINT_READ, endpoint_id)
        return endpoint

    def list(self, principal: SecurityPrincipal, context: OrganizationContext, status: Optional[EndpointStatus] = None):
        self._context(principal, context)
        self._require(principal, context, AuthorizationAction.ENDPOINT_READ, None)
        return self.repository.list_for_organization(context.organization_id, status)

    def revoke(self, principal: SecurityPrincipal, context: OrganizationContext, endpoint_id: EndpointId, revoked_at):
        self._context(principal, context)
        endpoint = self.repository.get_for_organization(endpoint_id, context.organization_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        self._require(principal, context, AuthorizationAction.ENDPOINT_REVOKE, endpoint_id)
        updated = self.repository.transition_status_for_organization(
            endpoint_id, context.organization_id,
            (EndpointStatus.NEW, EndpointStatus.ACTIVE, EndpointStatus.DEGRADED, EndpointStatus.OFFLINE),
            EndpointStatus.REVOKED, revoked_at,
        )
        self._audit(SecurityAuditEventType.ENDPOINT_REVOKED, principal, updated, AuthorizationAction.ENDPOINT_REVOKE, context)
        return updated

    def approve(self, principal: SecurityPrincipal, context: OrganizationContext, endpoint_id: EndpointId, approved_at):
        self._context(principal, context)
        endpoint = self.repository.get_for_organization(endpoint_id, context.organization_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        self._require(principal, context, AuthorizationAction.ENDPOINT_UPDATE, endpoint_id)
        if endpoint.status is not EndpointStatus.NEW:
            raise ValueError("only pending endpoints can be approved")
        updated = self.repository.transition_status_for_organization(
            endpoint_id, context.organization_id, (EndpointStatus.NEW,), EndpointStatus.ACTIVE, approved_at,
        )
        self._audit(SecurityAuditEventType.ENDPOINT_UPDATED, principal, updated, AuthorizationAction.ENDPOINT_UPDATE, context)
        return updated

    def update(self, principal: SecurityPrincipal, context: OrganizationContext, endpoint: Endpoint):
        self._context(principal, context)
        current = self.repository.get_for_organization(endpoint.endpoint_id, context.organization_id)
        if current is None:
            raise KeyError("endpoint not found")
        if endpoint.organization_id != current.organization_id:
            raise ValueError("endpoint organization ownership is immutable")
        if endpoint.status is not current.status or current.status is EndpointStatus.REVOKED:
            raise ValueError("endpoint lifecycle changes require an explicit action")
        self._require(principal, context, AuthorizationAction.ENDPOINT_UPDATE, endpoint.endpoint_id)
        self.repository.update(endpoint)
        self._audit(SecurityAuditEventType.ENDPOINT_UPDATED, principal, endpoint, AuthorizationAction.ENDPOINT_UPDATE, context)
        return endpoint

    def _context(self, principal, context):
        if principal.principal_type.value != "human":
            raise PermissionError("human principal required")
        if not isinstance(context, OrganizationContext):
            raise PermissionError("organization context required")

    def _require(self, principal, context, action, endpoint_id):
        resource = AuthorizationResource("endpoint", str(endpoint_id) if endpoint_id is not None else None,
                                         {"organization_id": str(context.organization_id)})
        decision = self.authorizer.authorize(AuthorizationRequest(principal, action, resource,
                                                                   organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)

    def _audit(self, event_type, principal, endpoint, action, context):
        if self.audit_sink is not None:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=principal, action=action,
                resource=AuthorizationResource("endpoint", str(endpoint.endpoint_id)),
                outcome=SecurityAuditOutcome.SUCCESS, endpoint_id=str(endpoint.endpoint_id),
                organization_id=str(context.organization_id), user_id=principal.principal_id,
                membership_id=context.membership_id, metadata={"status": endpoint.status.value},
            ))
