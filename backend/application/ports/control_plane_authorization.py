"""Replaceable authorization boundary for control-plane application actions."""

from dataclasses import dataclass
from typing import Optional, Protocol

from ...domain.security import (
    AuthorizationAction, AuthorizationDecision, AuthorizationRequest, AuthorizationResource,
    PrincipalType, SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal,
)


class ControlPlaneAuthorizer(Protocol):
    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision: ...


class AuthorizationFailure(PermissionError):
    def __init__(self, decision: AuthorizationDecision):
        self.decision = decision
        super().__init__(decision.reason or decision.reason_code)


class ConservativeControlPlaneAuthorizer:
    """Deny-first policy with only current internal and endpoint protocol actions."""

    _system_actions = frozenset({
        AuthorizationAction.ENDPOINT_CREATE, AuthorizationAction.ENDPOINT_READ, AuthorizationAction.ENDPOINT_UPDATE, AuthorizationAction.ENDPOINT_REVOKE,
        AuthorizationAction.ENROLLMENT_CREATE, AuthorizationAction.ENROLLMENT_REVOKE,
        AuthorizationAction.CREDENTIAL_ROTATE, AuthorizationAction.CREDENTIAL_REVOKE,
        AuthorizationAction.ASSESSMENT_CREATE, AuthorizationAction.ASSESSMENT_READ,
        AuthorizationAction.ASSESSMENT_CANCEL,
        AuthorizationAction.ASSESSMENT_SCHEDULE_CREATE, AuthorizationAction.ASSESSMENT_SCHEDULE_READ,
        AuthorizationAction.ASSESSMENT_SCHEDULE_UPDATE, AuthorizationAction.ASSESSMENT_SCHEDULE_PAUSE,
        AuthorizationAction.ASSESSMENT_SCHEDULE_REVOKE,
        AuthorizationAction.ENDPOINT_GROUP_CREATE, AuthorizationAction.ENDPOINT_GROUP_READ, AuthorizationAction.ENDPOINT_GROUP_UPDATE,
        AuthorizationAction.ENDPOINT_GROUP_MEMBERSHIP_UPDATE, AuthorizationAction.ENDPOINT_GROUP_REVOKE,
        AuthorizationAction.FLEET_SCOPE_CREATE, AuthorizationAction.FLEET_SCOPE_READ, AuthorizationAction.FLEET_SCOPE_UPDATE,
        AuthorizationAction.FLEET_SCOPE_REVOKE,
        AuthorizationAction.USER_CREATE, AuthorizationAction.USER_READ, AuthorizationAction.USER_UPDATE,
        AuthorizationAction.USER_DISABLE, AuthorizationAction.USER_REVOKE,
        AuthorizationAction.SESSION_CREATE, AuthorizationAction.SESSION_REVOKE,
        AuthorizationAction.ORGANIZATION_CREATE, AuthorizationAction.ORGANIZATION_READ,
        AuthorizationAction.ORGANIZATION_UPDATE, AuthorizationAction.ORGANIZATION_SUSPEND,
        AuthorizationAction.ORGANIZATION_REVOKE, AuthorizationAction.MEMBERSHIP_CREATE,
        AuthorizationAction.MEMBERSHIP_READ, AuthorizationAction.MEMBERSHIP_UPDATE,
        AuthorizationAction.MEMBERSHIP_SUSPEND, AuthorizationAction.MEMBERSHIP_REVOKE,
        AuthorizationAction.ROLE_CREATE, AuthorizationAction.ROLE_READ, AuthorizationAction.ROLE_UPDATE,
        AuthorizationAction.ROLE_DISABLE, AuthorizationAction.ROLE_REVOKE,
        AuthorizationAction.ROLE_BINDING_CREATE, AuthorizationAction.ROLE_BINDING_READ,
        AuthorizationAction.ROLE_BINDING_UPDATE, AuthorizationAction.ROLE_BINDING_REVOKE,
    })
    _endpoint_actions = frozenset({
        AuthorizationAction.AGENT_HEARTBEAT_SUBMIT, AuthorizationAction.AGENT_CAPABILITIES_SUBMIT,
        AuthorizationAction.AGENT_STATUS_SUBMIT, AuthorizationAction.ASSESSMENT_ACK_SUBMIT,
        AuthorizationAction.ASSESSMENT_PROGRESS_SUBMIT, AuthorizationAction.ASSESSMENT_RESULT_SUBMIT,
    })

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        principal = request.principal
        if principal.principal_type is PrincipalType.SYSTEM:
            if request.action in self._system_actions:
                return AuthorizationDecision(True)
            return AuthorizationDecision(False, "system_action_not_configured", "system action is not explicitly allowed")
        if principal.principal_type is PrincipalType.INTERNAL:
            if request.action in self._system_actions:
                return AuthorizationDecision(True)
            return AuthorizationDecision(False, "internal_action_not_configured", "internal action is not explicitly allowed")
        if principal.principal_type is PrincipalType.ENDPOINT:
            if request.action not in self._endpoint_actions:
                return AuthorizationDecision(False, "endpoint_action_not_allowed", "endpoint principals cannot perform this action")
            expected = principal.principal_id
            resource_endpoint = request.resource.metadata.get("endpoint_id") or (
                request.resource.resource_id if request.resource.resource_type == "endpoint" else None
            )
            if resource_endpoint != expected:
                return AuthorizationDecision(False, "endpoint_scope_mismatch", "endpoint principal is outside the resource scope")
            return AuthorizationDecision(True)
        if principal.principal_type is PrincipalType.HUMAN:
            return AuthorizationDecision(False, "human_action_not_configured", "human authentication does not grant permissions")
        return AuthorizationDecision(False, "unknown_principal", "principal type is not recognized")


class SecurityAuditSink(Protocol):
    def append(self, event: SecurityAuditEvent) -> None: ...


class AuthorizationService:
    def __init__(self, authorizer: ControlPlaneAuthorizer, audit_sink: Optional[SecurityAuditSink] = None):
        self.authorizer = authorizer
        self.audit_sink = audit_sink

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        decision = self.authorizer.authorize(request)
        if self.audit_sink is not None and not decision.allowed:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=SecurityAuditEventType.AUTHORIZATION_DENIED.value,
                principal=request.principal, action=request.action, resource=request.resource,
                outcome=SecurityAuditOutcome.DENIED, reason_code=decision.reason_code,
                metadata={"reason": decision.reason},
            ))
        return decision

    def require(self, request: AuthorizationRequest) -> None:
        decision = self.authorize(request)
        if not decision.allowed:
            raise AuthorizationFailure(decision)
