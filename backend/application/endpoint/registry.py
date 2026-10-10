"""Application service for durable endpoint records; not enrollment or transport."""

from datetime import datetime
from typing import Optional, Tuple

from ...domain.assessment import AssessmentTarget
from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus
from ...domain.scanner import TargetCapabilities
from ..ports.endpoint_repository import DuplicateEndpointError, EndpointRepository
from ..ports.control_plane_authorization import AuthorizationService
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal


class UnknownEndpointError(KeyError):
    """Raised when an explicit endpoint operation targets no registered identity."""


class EndpointRegistry:
    def __init__(self, repository: EndpointRepository, *, authorization_service: Optional[AuthorizationService] = None,
                 audit_sink=None, principal: Optional[SecurityPrincipal] = None):
        self._repository = repository
        self._authorization = authorization_service
        self._audit_sink = audit_sink
        self._principal = principal

    def register(self, endpoint: Endpoint) -> None:
        self._authorize(AuthorizationAction.ENDPOINT_UPDATE, endpoint.endpoint_id)
        if self._repository.exists(endpoint.endpoint_id):
            raise DuplicateEndpointError(f"endpoint {endpoint.endpoint_id} is already registered")
        self._repository.add(endpoint)
        self._audit(SecurityAuditEventType.ENDPOINT_REGISTERED, endpoint.endpoint_id)

    def get(self, endpoint_id: EndpointId) -> Optional[Endpoint]:
        return self._repository.get(endpoint_id)

    def list(self, status: Optional[EndpointStatus] = None) -> Tuple[Endpoint, ...]:
        return self._repository.list(status)

    def get_for_organization(self, endpoint_id, organization_id):
        return self._repository.get_for_organization(endpoint_id, organization_id)

    def list_for_organization(self, organization_id, status: Optional[EndpointStatus] = None):
        return self._repository.list_for_organization(organization_id, status)

    def update(self, endpoint: Endpoint) -> Endpoint:
        self._authorize(AuthorizationAction.ENDPOINT_UPDATE, endpoint.endpoint_id)
        self._require(endpoint.endpoint_id)
        self._repository.update(endpoint)
        self._audit(SecurityAuditEventType.ENDPOINT_UPDATED, endpoint.endpoint_id)
        return endpoint

    def update_capabilities(
        self,
        endpoint_id: EndpointId,
        capabilities: TargetCapabilities,
        updated_at: datetime,
    ) -> Endpoint:
        endpoint = self._require(endpoint_id)
        updated = endpoint.with_capabilities(capabilities, updated_at)
        self._repository.update(updated)
        return updated

    def update_status(self, endpoint_id: EndpointId, status: EndpointStatus, updated_at: datetime) -> Endpoint:
        self._authorize(AuthorizationAction.ENDPOINT_REVOKE if status is EndpointStatus.REVOKED else AuthorizationAction.ENDPOINT_UPDATE, endpoint_id)
        endpoint = self._require(endpoint_id)
        updated = endpoint.transition_to(status, updated_at)
        self._repository.update(updated)
        self._audit(SecurityAuditEventType.ENDPOINT_REVOKED if status is EndpointStatus.REVOKED else SecurityAuditEventType.ENDPOINT_UPDATED, endpoint_id)
        return updated

    def revoke(self, endpoint_id: EndpointId, revoked_at: datetime) -> Endpoint:
        return self.update_status(endpoint_id, EndpointStatus.REVOKED, revoked_at)

    def resolve_assessment_target(self, endpoint_id: EndpointId) -> AssessmentTarget:
        return self._require(endpoint_id).to_assessment_target()

    def _require(self, endpoint_id: EndpointId) -> Endpoint:
        endpoint = self._repository.get(endpoint_id)
        if endpoint is None:
            raise UnknownEndpointError(f"endpoint {endpoint_id} is not registered")
        return endpoint

    def _authorize(self, action, endpoint_id):
        if self._authorization is None:
            return
        if self._principal is None:
            raise PermissionError("an explicit security principal is required")
        self._authorization.require(AuthorizationRequest(
            self._principal, action, AuthorizationResource("endpoint", str(endpoint_id), {"endpoint_id": str(endpoint_id)})
        ))

    def _audit(self, event_type, endpoint_id):
        if self._audit_sink is not None:
            endpoint = self._repository.get(endpoint_id)
            self._audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=self._principal or SecurityPrincipal.system(),
                outcome=SecurityAuditOutcome.SUCCESS, endpoint_id=str(endpoint_id),
                organization_id=str(endpoint.organization_id) if endpoint is not None and endpoint.organization_id else None,
            ))
