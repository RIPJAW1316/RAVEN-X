from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from backend.agent.runtime import (
    AgentConfig,
    AgentCredential,
    InMemoryAgentCredentialStore,
    InMemoryAgentIdentityStore,
    RavenXAgent,
)
from backend.application.agent.processor import (
    AgentMessageProcessor,
    CredentialEndpointAuthenticator,
    TypedMessageRouter,
    decode_payload,
)
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.control_plane import (
    AgentSessionRegistry,
    ControlPlaneAgentHandlers,
    EndpointRevokedError,
    EndpointUnavailableError,
    InProcessDuplexTransport,
    RemoteAssessmentDispatcher,
    RemoteAssessmentRegistry,
    RemoteAssessmentState,
)
from backend.application.control_plane.assessment_dispatch import DuplicateTerminalResultError
from backend.application.endpoint.registry import EndpointRegistry
from backend.application.enrollment.service import EnrollmentService
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import Finding, FindingSeverity
from backend.domain.endpoint import EndpointId, EndpointStatus, PlatformInfo
from backend.domain.scanner import (
    ScannerCapability,
    ScannerExecutionResult,
    ScannerExecutionStatus,
    ScannerManifest,
    TargetCapabilities,
)
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository


class EndpointRepository:
    def __init__(self):
        self.items = {}

    def exists(self, endpoint_id):
        return str(endpoint_id) in self.items

    def add(self, endpoint):
        self.items[str(endpoint.endpoint_id)] = endpoint

    def get(self, endpoint_id):
        return self.items.get(str(endpoint_id))

    def list(self, status=None):
        values = tuple(self.items.values())
        return tuple(item for item in values if status is None or item.status is status)

    def update(self, endpoint):
        self.items[str(endpoint.endpoint_id)] = endpoint


class FakeFirewall:
    manifest = ScannerManifest(
        scanner_id="windows.firewall", name="Firewall", description="fake", category="firewall", version="1.0",
        required_capabilities=frozenset({ScannerCapability("windows.firewall.read")} ),
    )

    def execute(self, target, target_capabilities):
        finding = Finding("fake-firewall", FindingSeverity.LOW, "firewall", "Firewall finding", "evidence", "firewall")
        return ScannerExecutionResult("windows.firewall", ScannerExecutionStatus.SUCCESS, datetime.now(timezone.utc), datetime.now(timezone.utc), (finding,))


@dataclass
class StaticCapabilities:
    capabilities: TargetCapabilities

    def capabilities_for(self, target):
        return self.capabilities


def _composition(*, approved=True):
    now = datetime.now(timezone.utc)
    enrollment_repo = InMemoryEnrollmentRepository()
    enrollment = EnrollmentService(enrollment_repo)
    authorization, token = enrollment.create_enrollment_authorization(now=now)
    from backend.domain.endpoint import AgentInfo
    from backend.domain.enrollment import EnrollmentRequest
    endpoint, credential, raw = enrollment.accept_enrollment(
        authorization.enrollment_id, token.value,
        EnrollmentRequest("agent-host", PlatformInfo("Windows"), agent=AgentInfo("1.0.0", "1.0")), now=now,
    )
    if approved:
        endpoint = endpoint.transition_to(EndpointStatus.ACTIVE, now)
        enrollment_repo.endpoints[str(endpoint.endpoint_id)] = endpoint
    endpoint_repo = EndpointRepository()
    endpoint_repo.add(endpoint)
    endpoint_registry = EndpointRegistry(endpoint_repo)
    sessions = AgentSessionRegistry()
    assessments = RemoteAssessmentRegistry()
    handlers = ControlPlaneAgentHandlers(sessions, assessments)
    router = TypedMessageRouter()
    handlers.register_routes(router)
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(enrollment), __import__("backend.protocol.agent", fromlist=["InMemoryReplayGuard"]).InMemoryReplayGuard(), router=router)
    transport = InProcessDuplexTransport(processor)
    capabilities = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")}))
    scanner_registry = ScannerRegistry((FakeFirewall(),))
    agent = RavenXAgent(
        config=AgentConfig(hostname="agent-host"),
        identity_store=InMemoryAgentIdentityStore(endpoint.endpoint_id),
        credential_store=InMemoryAgentCredentialStore(AgentCredential(credential.credential_id, raw.value)),
        capability_provider=StaticCapabilities(capabilities), scanner_registry=scanner_registry,
        assessment_orchestrator=LocalAssessmentOrchestrator(scanner_registry, lambda target: capabilities), sender=transport,
    )
    transport.attach_agent(agent)
    agent.start(now=now)
    agent.emit_startup_messages(now=now)
    dispatcher = RemoteAssessmentDispatcher(endpoint_registry, sessions, transport, assessments)
    return endpoint, endpoint_registry, dispatcher, assessments, sessions, transport


def test_control_plane_dispatches_through_duplex_transport_and_completes_real_local_orchestration():
    endpoint, _, dispatcher, assessments, sessions, transport = _composition()
    assert sessions.get(endpoint.endpoint_id).state.value == "ready"
    assessment = dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",))
    assert assessment.state is RemoteAssessmentState.COMPLETED
    assert assessment.result.endpoint_id == str(endpoint.endpoint_id)
    assert assessment.result.findings[0]["finding_id"] == "fake-firewall"
    assert len(transport.control_to_agent) == 1
    assert any(message.message_type.value == "assessment.result" for message in transport.agent_to_control)


def test_terminal_result_cannot_be_submitted_for_another_endpoint_or_twice():
    endpoint, _, dispatcher, assessments, sessions, transport = _composition()
    assessment = dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",))
    result_message = next(message for message in transport.agent_to_control if message.message_type.value == "assessment.result")
    handlers = transport._control_processor._router._handlers
    handler = handlers[result_message.message_type][1]
    from backend.application.ports.agent_authorization import AuthenticatedEndpointContext
    from backend.domain.enrollment import CredentialId
    context = AuthenticatedEndpointContext(endpoint.endpoint_id, CredentialId.new(), datetime.now(timezone.utc), "test")
    with pytest.raises(DuplicateTerminalResultError):
        handler(context, decode_payload(result_message.message_type, result_message.payload), result_message)
    wrong = AuthenticatedEndpointContext(EndpointId.new(), CredentialId.new(), datetime.now(timezone.utc), "test")
    with pytest.raises(ValueError):
        handler(wrong, decode_payload(result_message.message_type, result_message.payload), result_message)


def test_dispatch_requires_active_session_and_rejects_revoked_endpoint():
    endpoint, endpoint_registry, dispatcher, _, _, _ = _composition()
    # A second registered endpoint has no session: this is unavailable, not a local fallback.
    other = endpoint.__class__(EndpointId.new(), "offline", PlatformInfo("Windows"),
                               status=EndpointStatus.ACTIVE, created_at=datetime.now(timezone.utc))
    endpoint_registry.register(other)
    with pytest.raises(EndpointUnavailableError) as unavailable:
        dispatcher.dispatch(other.endpoint_id, ("windows.firewall",))
    assert unavailable.value.assessment.state is RemoteAssessmentState.ENDPOINT_UNAVAILABLE

    revoked = endpoint.transition_to(EndpointStatus.REVOKED, datetime.now(timezone.utc))
    endpoint_registry.update(revoked)
    with pytest.raises(EndpointRevokedError):
        dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",))


def test_pending_enrollment_cannot_receive_assessment_even_with_active_session():
    endpoint, _, dispatcher, assessments, sessions, _ = _composition(approved=False)
    assert sessions.get(endpoint.endpoint_id).state.value == "ready"
    with pytest.raises(EndpointUnavailableError):
        dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",))
    assert assessments.list() == ()
