from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from backend.application.agent import (
    AgentMessageProcessor, CredentialEndpointAuthenticator, DefaultAgentMessageAuthorizer,
    EnrollmentMessageProcessor, MessageAcceptanceError, TypedMessageRouter,
)
from backend.application.enrollment import EnrollmentService
from backend.application.ports.agent_transport import PresentedCredential
from backend.application.ports.agent_transport import InMemoryAgentMessageSender
from backend.domain.endpoint import EndpointId, EndpointStatus, PlatformInfo
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository
from backend.protocol.agent import (
    AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, EnrollmentRequestPayload,
    InMemoryReplayGuard, ProtocolVersion,
)


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
ENDPOINT = EndpointId("123e4567-e89b-12d3-a456-426614174000")


def _enrolled():
    repository = InMemoryEnrollmentRepository()
    service = EnrollmentService(repository)
    authorization, token = service.create_enrollment_authorization(now=NOW)
    endpoint, credential, secret = service.accept_enrollment(
        authorization.enrollment_id, token.value,
        __import__("backend.domain.enrollment", fromlist=["EnrollmentRequest"]).EnrollmentRequest(
            "agent-host", PlatformInfo("Windows")
        ), now=NOW,
    )
    return repository, service, endpoint, credential, secret


def test_authenticated_heartbeat_routes_once_then_replay_is_rejected():
    repository, service, endpoint, credential, secret = _enrolled()
    received = []
    router = TypedMessageRouter()
    router.register(AgentMessageType.HEARTBEAT, AgentHeartbeat, lambda context, payload: received.append((context, payload)))
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(service), InMemoryReplayGuard(), router=router)
    heartbeat = AgentHeartbeat(endpoint.endpoint_id, "1.0.0", ProtocolVersion.current(), NOW)
    envelope = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, heartbeat.to_dict(), endpoint_id=endpoint.endpoint_id, timestamp=NOW)
    presented = PresentedCredential(secret.value, credential_id=credential.credential_id)
    processor.process(envelope, presented, now=NOW)
    assert received[0][0].endpoint_id == endpoint.endpoint_id
    assert received[0][1].health == "healthy"
    with pytest.raises(MessageAcceptanceError) as error:
        processor.process(envelope, presented, now=NOW)
    assert error.value.code == "replayed_message"

    repository.endpoints[str(endpoint.endpoint_id)] = replace(endpoint, status=EndpointStatus.REVOKED, updated_at=NOW)
    fresh = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, heartbeat.to_dict(), endpoint_id=endpoint.endpoint_id, timestamp=NOW)
    with pytest.raises(MessageAcceptanceError) as error:
        processor.process(fresh, presented, now=NOW)
    assert error.value.code == "invalid_credential"


def test_wrong_endpoint_and_direction_are_rejected():
    repository, service, endpoint, credential, secret = _enrolled()
    other = __import__("backend.domain.endpoint", fromlist=["EndpointId"]).EndpointId.new()
    router = TypedMessageRouter()
    router.register(AgentMessageType.HEARTBEAT, AgentHeartbeat, lambda context, payload: payload)
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(service), InMemoryReplayGuard(), router=router)
    heartbeat = AgentHeartbeat(endpoint.endpoint_id, "1.0.0", ProtocolVersion.current(), NOW)
    mismatch = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, heartbeat.to_dict(), endpoint_id=other, timestamp=NOW)
    with pytest.raises(MessageAcceptanceError):
        processor.process(mismatch, PresentedCredential(secret.value, credential_id=credential.credential_id), now=NOW)

    dispatch = AssessmentDispatch("assessment", endpoint.endpoint_id, ("windows.firewall",), NOW)
    outbound = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(), endpoint_id=endpoint.endpoint_id, timestamp=NOW)
    with pytest.raises(MessageAcceptanceError) as error:
        processor.process(outbound, PresentedCredential(secret.value, credential_id=credential.credential_id), now=NOW)
    assert error.value.code == "direction_not_allowed"


def test_stale_messages_never_reach_handlers_and_enrollment_is_separate():
    repository, service, endpoint, credential, secret = _enrolled()
    called = []
    router = TypedMessageRouter()
    router.register(AgentMessageType.HEARTBEAT, AgentHeartbeat, lambda context, payload: called.append(payload))
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(service), InMemoryReplayGuard(), router=router)
    heartbeat = AgentHeartbeat(endpoint.endpoint_id, "1.0.0", ProtocolVersion.current(), NOW)
    stale = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, heartbeat.to_dict(), endpoint_id=endpoint.endpoint_id, timestamp=NOW - timedelta(minutes=6))
    with pytest.raises(MessageAcceptanceError):
        processor.process(stale, PresentedCredential(secret.value, credential_id=credential.credential_id), now=NOW)
    assert not called

    auth, bootstrap = service.create_enrollment_authorization(now=NOW)
    payload = EnrollmentRequestPayload(bootstrap.value, "new-host", PlatformInfo("Windows"), "1.2.0", enrollment_id=auth.enrollment_id)
    response = EnrollmentMessageProcessor(service).process(payload, now=NOW)
    assert response.endpoint_id != endpoint.endpoint_id
    with pytest.raises(MessageAcceptanceError):
        processor.process(AgentMessageEnvelope(AgentMessageType.HEARTBEAT, heartbeat.to_dict(), endpoint_id=endpoint.endpoint_id, timestamp=NOW), PresentedCredential(bootstrap.value), now=NOW)


def test_presented_secret_is_redacted_and_outbound_sender_rejects_inbound_direction():
    presented = PresentedCredential("never-log-this")
    assert "never-log-this" not in repr(presented)
    sender = InMemoryAgentMessageSender()
    dispatch = AssessmentDispatch("assessment", ENDPOINT, ("windows.firewall",), NOW)
    outbound = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(), endpoint_id=ENDPOINT, timestamp=NOW)
    sender.send(outbound)
    assert sender.messages == [outbound]
    heartbeat = AgentHeartbeat(ENDPOINT, "1.0.0", ProtocolVersion.current(), NOW)
    sender.send(AgentMessageEnvelope(AgentMessageType.HEARTBEAT, heartbeat.to_dict(), endpoint_id=ENDPOINT, timestamp=NOW))
    assert sender.messages[-1].message_type is AgentMessageType.HEARTBEAT
