from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.agent.runtime import AgentConfig, AgentCredential, InMemoryAgentCredentialStore, InMemoryAgentIdentityStore, RavenXAgent
from backend.application.agent.processor import AgentMessageProcessor, CredentialEndpointAuthenticator, TypedMessageRouter
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.control_plane import AgentSessionRegistry, ControlPlaneAgentHandlers, RemoteAssessmentDispatcher, RemoteAssessmentRegistry, RemoteAssessmentState
from backend.application.endpoint.registry import EndpointRegistry
from backend.application.enrollment.service import EnrollmentService
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import Finding, FindingSeverity
from backend.domain.endpoint import AgentInfo, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.enrollment import EnrollmentRequest
from backend.domain.scanner import ScannerCapability, ScannerExecutionResult, ScannerExecutionStatus, ScannerManifest, TargetCapabilities
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository
from backend.infrastructure.persistence.in_memory_agent_work_repository import InMemoryAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from backend.core.database.database import DatabaseManager
from backend.infrastructure.transport.http import HttpAgentTransport, HttpControlPlaneTransport, HttpTransportConfig, PendingWorkQueue, create_agent_http_app
from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, InMemoryReplayGuard, ProtocolValidationPolicy, ProtocolVersion


class EndpointRepository:
    def __init__(self): self.items = {}
    def exists(self, endpoint_id): return str(endpoint_id) in self.items
    def add(self, endpoint): self.items[str(endpoint.endpoint_id)] = endpoint
    def get(self, endpoint_id): return self.items.get(str(endpoint_id))
    def list(self, status=None): return tuple(item for item in self.items.values() if status is None or item.status is status)
    def update(self, endpoint): self.items[str(endpoint.endpoint_id)] = endpoint


class FakeFirewall:
    manifest = ScannerManifest("windows.firewall", "Firewall", "fake", "firewall", "1.0", frozenset({ScannerCapability("windows.firewall.read")}))
    def execute(self, target, capabilities):
        finding = Finding("http-firewall", FindingSeverity.LOW, "firewall", "HTTP firewall finding", "evidence", "firewall")
        now = datetime.now(timezone.utc)
        return ScannerExecutionResult("windows.firewall", ScannerExecutionStatus.SUCCESS, now, now, (finding,))


@dataclass
class StaticCapabilities:
    value: TargetCapabilities
    def capabilities_for(self, target): return self.value


class ClientAdapter:
    def __init__(self, client): self.client = client
    def request(self, method, path, **kwargs): return self.client.request(method, path, **kwargs)


def _setup():
    now = datetime.now(timezone.utc)
    enrollment_repo = InMemoryEnrollmentRepository()
    enrollment = EnrollmentService(enrollment_repo)
    authorization, token = enrollment.create_enrollment_authorization(now=now)
    endpoint, credential, raw = enrollment.accept_enrollment(
        authorization.enrollment_id, token.value,
        EnrollmentRequest("http-agent", PlatformInfo("Windows"), agent=AgentInfo("1.0.0", "1.0")), now=now,
    )
    endpoint = endpoint.transition_to(EndpointStatus.ACTIVE, now)
    enrollment_repo.endpoints[str(endpoint.endpoint_id)] = endpoint
    endpoint_repo = EndpointRepository(); endpoint_repo.add(endpoint)
    sessions, assessments = AgentSessionRegistry(), RemoteAssessmentRegistry()
    handlers = ControlPlaneAgentHandlers(sessions, assessments)
    router = TypedMessageRouter(); handlers.register_routes(router)
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(enrollment), InMemoryReplayGuard(), router=router)
    outbox = PendingWorkQueue()
    app = create_agent_http_app(processor, enrollment, outbox, policy=ProtocolValidationPolicy(max_payload_bytes=4096))
    client = TestClient(app)
    capabilities = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")}))
    scanner_registry = ScannerRegistry((FakeFirewall(),))
    http_transport = HttpAgentTransport(
        HttpTransportConfig("https://control.example"),
        InMemoryAgentCredentialStore(AgentCredential(credential.credential_id, raw.value)),
        endpoint_id=endpoint.endpoint_id, client=ClientAdapter(client),
    )
    agent = RavenXAgent(
        config=AgentConfig(hostname="http-agent"), identity_store=InMemoryAgentIdentityStore(endpoint.endpoint_id),
        credential_store=InMemoryAgentCredentialStore(AgentCredential(credential.credential_id, raw.value)),
        capability_provider=StaticCapabilities(capabilities), scanner_registry=scanner_registry,
        assessment_orchestrator=LocalAssessmentOrchestrator(scanner_registry, lambda target: capabilities), sender=http_transport,
    )
    agent.start(now=now); agent.emit_startup_messages(now=now)
    control_transport = HttpControlPlaneTransport(outbox)
    dispatcher = RemoteAssessmentDispatcher(EndpointRegistry(endpoint_repo), sessions, control_transport, assessments)
    return endpoint, credential, raw, client, http_transport, agent, dispatcher, assessments, outbox


def test_authenticated_http_distributed_assessment_completes_end_to_end():
    endpoint, credential, raw, client, transport, agent, dispatcher, assessments, outbox = _setup()
    assert dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",)).state is RemoteAssessmentState.DISPATCHED
    envelope = transport.poll_once()
    assert envelope.message_type is AgentMessageType.ASSESSMENT_DISPATCH
    agent.receive(envelope)
    assessment = assessments.get(envelope.payload["assessment_id"])
    assert assessment.state is RemoteAssessmentState.COMPLETED
    assert assessment.result.findings[0]["finding_id"] == "http-firewall"
    assert not outbox.pending(endpoint.endpoint_id)


def test_http_ingress_rejects_replay_wrong_endpoint_stale_and_oversized_messages():
    endpoint, credential, raw, client, transport, agent, dispatcher, assessments, outbox = _setup()
    message = agent.heartbeat(now=datetime.now(timezone.utc))
    body = message.to_dict()
    headers = {"Authorization": f"Bearer {raw.value}", "Content-Type": "application/json"}
    assert client.post("/api/v1/agent/messages", json=body, headers=headers).status_code == 200
    assert client.post("/api/v1/agent/messages", json=body, headers=headers).status_code == 409
    wrong = dict(body); wrong["endpoint_id"] = str(EndpointId.new()); wrong["payload"] = dict(body["payload"]); wrong["payload"]["endpoint_id"] = wrong["endpoint_id"]
    assert client.post("/api/v1/agent/messages", json=wrong, headers=headers).status_code == 401
    stale = dict(body); stale["message_id"] = str(__import__("uuid").uuid4()); stale["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    assert client.post("/api/v1/agent/messages", json=stale, headers=headers).status_code == 400
    assert client.post("/api/v1/agent/messages", content=b"x" * 5000, headers=headers).status_code == 413
    assert raw.value not in client.post("/api/v1/agent/messages", json=wrong, headers=headers).text


def test_http_ingress_requires_json_and_redacts_authentication_failures():
    endpoint, credential, raw, client, transport, agent, dispatcher, assessments, outbox = _setup()
    assert client.post("/api/v1/agent/messages", content="{}", headers={"Authorization": f"Bearer {raw.value}", "Content-Type": "text/plain"}).status_code == 415
    response = client.post("/api/v1/agent/messages", json=agent.heartbeat().to_dict(), headers={"Authorization": "Bearer wrong", "Content-Type": "application/json"})
    assert response.status_code == 401
    assert raw.value not in response.text


def test_http_ingress_rejects_malformed_json_and_control_to_agent_direction():
    endpoint, credential, raw, client, transport, agent, dispatcher, assessments, outbox = _setup()
    headers = {"Authorization": f"Bearer {raw.value}", "Content-Type": "application/json"}
    assert client.post("/api/v1/agent/messages", content=b"{not-json", headers=headers).status_code == 400
    now = datetime.now(timezone.utc)
    dispatch = AssessmentDispatch("direction-test", endpoint.endpoint_id, ("windows.firewall",), now)
    envelope = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(), protocol_version=ProtocolVersion.current(), endpoint_id=endpoint.endpoint_id, timestamp=now)
    response = client.post("/api/v1/agent/messages", json=envelope.to_dict(), headers=headers)
    assert response.status_code == 403


def test_durable_http_work_poll_ack_progress_and_result_complete_assessment(tmp_path):
    now = datetime.now(timezone.utc)
    enrollment_repo = InMemoryEnrollmentRepository()
    enrollment = EnrollmentService(enrollment_repo)
    authorization, token = enrollment.create_enrollment_authorization(now=now)
    endpoint, credential, raw = enrollment.accept_enrollment(
        authorization.enrollment_id, token.value, EnrollmentRequest(
            "durable-http-agent", PlatformInfo("Windows"), agent=AgentInfo("1.0.0", "1.0")
        ), now=now,
    )
    endpoint = endpoint.transition_to(EndpointStatus.ACTIVE, now)
    enrollment_repo.endpoints[str(endpoint.endpoint_id)] = endpoint
    endpoint_repo = EndpointRepository(); endpoint_repo.add(endpoint)
    sessions = AgentSessionRegistry()
    config = tmp_path / "http_durable.yaml"
    database = tmp_path / "http_durable.db"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '" + database.as_posix() + "'\n", encoding="utf-8")
    database_manager = DatabaseManager(str(config))
    database_manager.initialize_sync_engine()
    database_manager.create_tables()
    assessments = SQLAlchemyRemoteAssessmentRepository(database_manager)
    work_repository = SQLAlchemyAgentWorkRepository(database_manager)
    handlers = ControlPlaneAgentHandlers(sessions, assessments, work_repository)
    router = TypedMessageRouter(); handlers.register_routes(router)
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(enrollment), InMemoryReplayGuard(), router=router)
    app = create_agent_http_app(processor, enrollment, work_repository=work_repository,
                                policy=ProtocolValidationPolicy(max_payload_bytes=4096))
    client = TestClient(app)
    capabilities = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")}))
    scanner_registry = ScannerRegistry((FakeFirewall(),))
    transport = HttpAgentTransport(
        HttpTransportConfig("https://control.example"),
        InMemoryAgentCredentialStore(AgentCredential(credential.credential_id, raw.value)),
        endpoint_id=endpoint.endpoint_id, client=ClientAdapter(client),
    )
    agent = RavenXAgent(
        config=AgentConfig(hostname="durable-http-agent"), identity_store=InMemoryAgentIdentityStore(endpoint.endpoint_id),
        credential_store=InMemoryAgentCredentialStore(AgentCredential(credential.credential_id, raw.value)),
        capability_provider=StaticCapabilities(capabilities), scanner_registry=scanner_registry,
        assessment_orchestrator=LocalAssessmentOrchestrator(scanner_registry, lambda target: capabilities), sender=transport,
    )
    agent.start(now=now)
    agent.emit_startup_messages(now=now)
    dispatcher = RemoteAssessmentDispatcher(EndpointRegistry(endpoint_repo), sessions, HttpControlPlaneTransport(PendingWorkQueue()),
                                            assessments, work_repository=work_repository)

    assessment = dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",), requested_at=now)
    assert assessment.state.value == "queued"
    leased = transport.poll_work()
    assert leased is not None
    assert work_repository.get(leased.work_id).status.value == "leased"
    agent.receive_leased_work(leased)

    restored = assessments.get(assessment.assessment_id)
    assert restored.state is RemoteAssessmentState.COMPLETED
    assert work_repository.get(leased.work_id).status.value == "completed"
    assert transport.poll_work() is None
    database_manager.close()
    reloaded = DatabaseManager(str(config))
    reloaded.initialize_sync_engine()
    persisted = SQLAlchemyRemoteAssessmentRepository(reloaded).get(assessment.assessment_id)
    assert persisted.state is RemoteAssessmentState.COMPLETED
    assert persisted.result.findings[0]["finding_id"] == "http-firewall"
    reloaded.close()
