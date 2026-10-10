from datetime import datetime, timezone

import pytest

from backend.application.ports.control_plane_authorization import (
    AuthorizationFailure, AuthorizationService, ConservativeControlPlaneAuthorizer,
)
from backend.domain.endpoint import EndpointId
from backend.domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType,
    SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal,
)
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.application.agent.processor import AgentMessageProcessor, CredentialEndpointAuthenticator, TypedMessageRouter, MessageAcceptanceError
from backend.application.enrollment.service import EnrollmentService
from backend.application.endpoint.registry import EndpointRegistry
from backend.domain.endpoint import EndpointStatus
from backend.domain.endpoint import AgentInfo, PlatformInfo
from backend.domain.enrollment import EnrollmentRequest
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository
from backend.protocol.agent import AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, InMemoryReplayGuard, ProtocolVersion


def _request(principal, action, endpoint_id):
    return AuthorizationRequest(principal, action, AuthorizationResource("endpoint", str(endpoint_id), {"endpoint_id": str(endpoint_id)}))


def test_endpoint_principal_is_self_scoped_and_system_policy_is_explicit():
    endpoint_a, endpoint_b = EndpointId.new(), EndpointId.new()
    authorizer = ConservativeControlPlaneAuthorizer()
    endpoint = SecurityPrincipal.endpoint(endpoint_a)
    assert authorizer.authorize(_request(endpoint, AuthorizationAction.AGENT_HEARTBEAT_SUBMIT, endpoint_a)).allowed
    denied = authorizer.authorize(_request(endpoint, AuthorizationAction.AGENT_HEARTBEAT_SUBMIT, endpoint_b))
    assert not denied.allowed and denied.reason_code == "endpoint_scope_mismatch"
    denied = authorizer.authorize(_request(endpoint, AuthorizationAction.ENDPOINT_REVOKE, endpoint_a))
    assert not denied.allowed and denied.reason_code == "endpoint_action_not_allowed"
    assert authorizer.authorize(_request(SecurityPrincipal.system(), AuthorizationAction.ENDPOINT_REVOKE, endpoint_a)).allowed
    unknown = authorizer.authorize(_request(SecurityPrincipal(PrincipalType.INTERNAL, "job"), "assessment.result.submit", endpoint_a))
    assert not unknown.allowed


def test_audit_event_redacts_sensitive_metadata_and_is_append_only():
    repository = InMemorySecurityAuditRepository()
    event = SecurityAuditEvent(
        event_type=SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_FAILED.value,
        principal=SecurityPrincipal.system(), outcome=SecurityAuditOutcome.DENIED,
        metadata={"token": "SUPER_SECRET_ENDPOINT_TOKEN", "nested": {"authorization": "Bearer secret"}, "safe": "value"},
    )
    repository.append(event)
    assert "SUPER_SECRET_ENDPOINT_TOKEN" not in str(event.to_dict())
    assert "Bearer secret" not in str(event.to_dict())
    assert repository.list(event_type=event.event_type)[0].event_id == event.event_id
    with pytest.raises(ValueError):
        repository.append(event)


def test_authorization_service_audits_denials():
    repository = InMemorySecurityAuditRepository()
    service = AuthorizationService(ConservativeControlPlaneAuthorizer(), repository)
    endpoint = EndpointId.new()
    with pytest.raises(AuthorizationFailure):
        service.require(_request(SecurityPrincipal.endpoint(endpoint), AuthorizationAction.ASSESSMENT_CREATE, endpoint))
    events = repository.list(event_type=SecurityAuditEventType.AUTHORIZATION_DENIED.value)
    assert len(events) == 1
    assert events[0].outcome is SecurityAuditOutcome.DENIED


def test_authenticated_message_audit_records_success_replay_and_invalid_credential_without_secret():
    now = datetime(2026, 8, 23, 16, 0, tzinfo=timezone.utc)
    enrollment = EnrollmentService(InMemoryEnrollmentRepository())
    authorization, token = enrollment.create_enrollment_authorization(now=now)
    endpoint, credential, raw = enrollment.accept_enrollment(
        authorization.enrollment_id, token.value,
        EnrollmentRequest("audit-agent", PlatformInfo("Windows"), agent=AgentInfo("1.0", "1.0")), now=now,
    )
    audit = InMemorySecurityAuditRepository()
    router = TypedMessageRouter()
    from backend.application.control_plane.handlers import ControlPlaneAgentHandlers
    from backend.application.control_plane import AgentSessionRegistry, RemoteAssessmentRegistry
    ControlPlaneAgentHandlers(AgentSessionRegistry(), RemoteAssessmentRegistry()).register_routes(router)
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(enrollment), InMemoryReplayGuard(), router=router,
                                      audit_repository=audit)
    payload = AgentHeartbeat(endpoint.endpoint_id, "1.0", ProtocolVersion.current(), now).to_dict()
    envelope = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, payload, endpoint_id=endpoint.endpoint_id, timestamp=now)
    processor.process(envelope, __import__("backend.application.ports.agent_transport", fromlist=["PresentedCredential"]).PresentedCredential(raw.value), now=now)
    with pytest.raises(MessageAcceptanceError):
        processor.process(envelope, __import__("backend.application.ports.agent_transport", fromlist=["PresentedCredential"]).PresentedCredential(raw.value), now=now)
    invalid = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, payload, endpoint_id=endpoint.endpoint_id, timestamp=now)
    with pytest.raises(MessageAcceptanceError):
        processor.process(invalid, __import__("backend.application.ports.agent_transport", fromlist=["PresentedCredential"]).PresentedCredential("SUPER_SECRET_ENDPOINT_TOKEN"), now=now)
    values = str([event.to_dict() for event in audit.list()])
    assert "SUPER_SECRET_ENDPOINT_TOKEN" not in values


def test_endpoint_and_credential_lifecycle_events_are_audited_without_secret_material():
    now = datetime(2026, 8, 23, 17, 0, tzinfo=timezone.utc)
    audit = InMemorySecurityAuditRepository()
    enrollment_repo = InMemoryEnrollmentRepository()
    enrollment = EnrollmentService(enrollment_repo, audit_sink=audit)
    authorization, token = enrollment.create_enrollment_authorization(now=now)
    endpoint, credential, raw = enrollment.accept_enrollment(
        authorization.enrollment_id, token.value,
        EnrollmentRequest("lifecycle-agent", PlatformInfo("Windows"), agent=AgentInfo("1.0", "1.0")), now=now,
    )
    replacement, replacement_raw = enrollment.rotate_credential(credential.credential_id, now=now)
    enrollment.revoke_credential(replacement.credential_id, now=now, reason="test")

    class Repository:
        def __init__(self): self.items = {}
        def exists(self, endpoint_id): return str(endpoint_id) in self.items
        def add(self, value): self.items[str(value.endpoint_id)] = value
        def get(self, endpoint_id): return self.items.get(str(endpoint_id))
        def update(self, value): self.items[str(value.endpoint_id)] = value
        def list(self, status=None): return tuple(self.items.values())

    registry = EndpointRegistry(Repository(), audit_sink=audit)
    registry.register(endpoint)
    registry.update_status(endpoint.endpoint_id, EndpointStatus.ACTIVE, now)
    registry.revoke(endpoint.endpoint_id, now)
    types = {event.event_type for event in audit.list()}
    assert SecurityAuditEventType.ENROLLMENT_CREATED.value in types
    assert SecurityAuditEventType.ENROLLMENT_CONSUMED.value in types
    assert SecurityAuditEventType.CREDENTIAL_ROTATED.value in types
    assert SecurityAuditEventType.CREDENTIAL_REVOKED.value in types
    assert SecurityAuditEventType.ENDPOINT_REVOKED.value in types
    values = str([event.to_dict() for event in audit.list()])
    assert raw.value not in values and replacement_raw.value not in values
