from datetime import datetime, timezone

from backend.agent import (
    AgentConfig, AgentCredential, AgentEnrollmentInstaller, InMemoryAgentCredentialStore,
    InMemoryAgentIdentityStore, AgentLifecycleState, build_local_agent,
)
from backend.application.ports.agent_transport import InMemoryAgentMessageSender
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, Finding, FindingSeverity
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.domain.scanner import ScannerExecutionResult, ScannerExecutionStatus, ScannerManifest, TargetCapabilities
from backend.protocol.agent import AgentMessageType, AssessmentDispatch, CorrelationId, AgentMessageEnvelope


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
ENDPOINT = EndpointId("123e4567-e89b-12d3-a456-426614174000")


class StaticProvider:
    def capabilities_for(self, target):
        return TargetCapabilities()


class FakeOrchestrator:
    def run(self, target, scanner_ids):
        finding = Finding("integration-finding", FindingSeverity.MEDIUM, "test", "Test finding", "evidence", "fake")
        return AssessmentResult(
            "integration-assessment", target, AssessmentStatus.COMPLETED, NOW, NOW, (finding,),
            scanner_results=(),
        )


def test_local_agent_end_to_end_in_process_without_network():
    identity_store = InMemoryAgentIdentityStore()
    credential_store = InMemoryAgentCredentialStore()
    AgentEnrollmentInstaller(identity_store, credential_store).install(
        type("EnrollmentResponse", (), {
            "endpoint_id": ENDPOINT,
            "credential_id": str(CredentialId.new()),
            "credential_secret": "integration-secret",
        })()
    )
    sender = InMemoryAgentMessageSender()
    agent = build_local_agent(
        config=AgentConfig(hostname="integration-agent"), identity_store=identity_store,
        credential_store=credential_store, capability_provider=StaticProvider(), scanner_registry=object(),
        assessment_orchestrator=FakeOrchestrator(), sender=sender,
    )
    assert agent.start(now=NOW) is AgentLifecycleState.READY
    startup = agent.emit_startup_messages(now=NOW)
    assert startup[0].message_type is AgentMessageType.HEARTBEAT
    correlation = CorrelationId()
    dispatch = AssessmentDispatch("integration-assessment", ENDPOINT, ("windows.firewall",), NOW)
    envelope = AgentMessageEnvelope(
        AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(), endpoint_id=ENDPOINT,
        timestamp=NOW, correlation_id=correlation,
    )
    result = agent.handle_dispatch(envelope, now=NOW)
    assert result.endpoint_id == str(ENDPOINT)
    assert result.findings[0]["finding_id"] == "integration-finding"
    assert sender.messages[-1].message_type is AgentMessageType.ASSESSMENT_RESULT
    assert sender.messages[-1].correlation_id == correlation
    assert "integration-secret" not in repr(sender.messages)


def test_agent_routes_dispatch_through_existing_local_orchestrator():
    class FakeScanner:
        manifest = ScannerManifest("test.scanner", "Test scanner", "safe fake", "test", "1.0", supported_platforms=frozenset({"Windows"}))

        def execute(self, target, capabilities):
            finding = Finding("scanner-finding", FindingSeverity.LOW, "test", "Scanner finding", "evidence", "fake")
            return ScannerExecutionResult("test.scanner", ScannerExecutionStatus.SUCCESS, NOW, NOW, (finding,))

    identity_store = InMemoryAgentIdentityStore(ENDPOINT)
    credential_store = InMemoryAgentCredentialStore(AgentCredential(CredentialId.new(), "scanner-secret"))
    sender = InMemoryAgentMessageSender()
    registry = ScannerRegistry((FakeScanner(),))
    orchestrator = LocalAssessmentOrchestrator(registry, lambda target: TargetCapabilities())
    agent = build_local_agent(
        config=AgentConfig(hostname="scanner-agent"), identity_store=identity_store,
        credential_store=credential_store, capability_provider=StaticProvider(), scanner_registry=registry,
        assessment_orchestrator=orchestrator, sender=sender,
    )
    agent.start(now=NOW)
    dispatch = AssessmentDispatch("scanner-assessment", ENDPOINT, ("test.scanner",), NOW)
    envelope = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(), endpoint_id=ENDPOINT, timestamp=NOW, correlation_id=CorrelationId())
    result = agent.handle_dispatch(envelope, now=NOW)
    assert result.scanner_results[0]["scanner_id"] == "test.scanner"
    assert result.findings[0]["finding_id"] == "scanner-finding"
