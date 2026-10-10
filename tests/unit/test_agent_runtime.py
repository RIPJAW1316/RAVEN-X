from datetime import datetime, timezone
from dataclasses import dataclass

import pytest

from backend.agent import (
    AgentConfig, AgentCredential, AgentEnrollmentInstaller, AgentLifecycleState,
    AgentStartupError, InMemoryAgentCredentialStore, InMemoryAgentIdentityStore, RavenXAgent,
)
from backend.application.ports.agent_transport import InMemoryAgentMessageSender
from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, Finding, FindingSeverity
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.domain.scanner import ScannerExecutionResult, ScannerExecutionStatus, TargetCapabilities
from backend.protocol.agent import (
    AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, CorrelationId, ProtocolVersion,
)


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
ENDPOINT = EndpointId("123e4567-e89b-12d3-a456-426614174000")


class StaticCapabilities:
    def capabilities_for(self, target):
        return TargetCapabilities()


class FailingCapabilities:
    def capabilities_for(self, target):
        raise RuntimeError("discovery unavailable")


class FakeOrchestrator:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, target, scanner_ids):
        self.calls.append((target, scanner_ids))
        return self.result


def _agent(orchestrator=None, identity=ENDPOINT, credential_id=None):
    identity_store = InMemoryAgentIdentityStore(identity)
    credential_store = InMemoryAgentCredentialStore(AgentCredential(credential_id or CredentialId.new(), "machine-secret"))
    sender = InMemoryAgentMessageSender()
    orchestrator = orchestrator or FakeOrchestrator(AssessmentResult(
        "assessment-result", AssessmentTarget(str(identity), "agent-host", "Windows"), AssessmentStatus.COMPLETED,
        NOW, NOW, (), scanner_results=(),
    ))
    return RavenXAgent(
        config=AgentConfig(hostname="agent-host"), identity_store=identity_store, credential_store=credential_store,
        capability_provider=StaticCapabilities(), scanner_registry=object(), assessment_orchestrator=orchestrator,
        sender=sender,
    ), sender, identity_store, credential_store


def _dispatch(endpoint_id, scanner_ids=("windows.firewall",), correlation=None):
    payload = AssessmentDispatch("assessment-1", endpoint_id, tuple(scanner_ids), NOW)
    return AgentMessageEnvelope(
        AgentMessageType.ASSESSMENT_DISPATCH, payload.to_dict(), endpoint_id=endpoint_id,
        timestamp=NOW, correlation_id=correlation or CorrelationId(),
    )


def test_startup_requires_enrollment_and_never_invents_identity():
    agent, _, identity_store, credential_store = _agent(identity=None)
    assert agent.start(now=NOW) is AgentLifecycleState.UNENROLLED
    assert identity_store.load() is None
    assert credential_store.load() is not None

    config = AgentConfig(protocol_version=ProtocolVersion(2, 0))
    with pytest.raises(AgentStartupError):
        RavenXAgent(config=config, identity_store=InMemoryAgentIdentityStore(ENDPOINT), credential_store=credential_store,
                    capability_provider=StaticCapabilities(), scanner_registry=object(), assessment_orchestrator=FakeOrchestrator(agent.assessment_orchestrator.result), sender=InMemoryAgentMessageSender()).start(now=NOW)


def test_enrollment_installer_persists_identity_and_credential_without_repr_leakage():
    identity_store, credential_store = InMemoryAgentIdentityStore(), InMemoryAgentCredentialStore()
    installer = AgentEnrollmentInstaller(identity_store, credential_store)
    response = type("Response", (), {"endpoint_id": ENDPOINT, "credential_id": str(CredentialId.new()), "credential_secret": "install-secret"})()
    installer.install(response)
    assert identity_store.load() == ENDPOINT
    assert credential_store.load().secret == "install-secret"
    assert "install-secret" not in repr(credential_store.load())


def test_agent_emits_heartbeat_capabilities_status_and_selected_assessment_results():
    finding = Finding("finding-1", FindingSeverity.HIGH, "test", "Issue", "details", "component")
    result = AssessmentResult(
        "assessment-result", AssessmentTarget(str(ENDPOINT), "agent-host", "Windows"), AssessmentStatus.COMPLETED,
        NOW, NOW, (finding,), scanner_results=(ScannerExecutionResult("windows.firewall", ScannerExecutionStatus.SUCCESS, NOW, NOW, (finding,)),),
    )
    orchestrator = FakeOrchestrator(result)
    agent, sender, _, _ = _agent(orchestrator)
    assert agent.start(now=NOW) is AgentLifecycleState.READY
    startup = agent.emit_startup_messages(now=NOW)
    assert [message.message_type for message in startup] == [AgentMessageType.HEARTBEAT, AgentMessageType.CAPABILITIES, AgentMessageType.STATUS]
    dispatch = _dispatch(ENDPOINT, correlation=CorrelationId())
    output = agent.handle_dispatch(dispatch, now=NOW)
    assert output.findings[0]["finding_id"] == "finding-1"
    assert orchestrator.calls[0][1] == ("windows.firewall",)
    assert [message.message_type for message in sender.messages[-3:]] == [AgentMessageType.ASSESSMENT_PROGRESS, AgentMessageType.ASSESSMENT_PROGRESS, AgentMessageType.ASSESSMENT_RESULT]
    assert sender.messages[-1].correlation_id == dispatch.correlation_id
    assert all("machine-secret" not in repr(message) for message in sender.messages)
    assert agent.state is AgentLifecycleState.READY


def test_dispatch_target_and_stale_messages_are_rejected():
    agent, _, _, _ = _agent()
    agent.start(now=NOW)
    with pytest.raises(AgentStartupError):
        agent.handle_dispatch(_dispatch(EndpointId.new()), now=NOW)
    stale = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, _dispatch(ENDPOINT).payload, endpoint_id=ENDPOINT, timestamp=NOW.replace(hour=11), correlation_id=CorrelationId())
    with pytest.raises(AgentStartupError):
        agent.handle_dispatch(stale, now=NOW)


def test_two_agents_are_identity_isolated():
    agent_a, _, _, _ = _agent(identity=ENDPOINT)
    agent_b, _, _, _ = _agent(identity=EndpointId.new())
    agent_a.start(now=NOW)
    agent_b.start(now=NOW)
    with pytest.raises(AgentStartupError):
        agent_b.handle_dispatch(_dispatch(ENDPOINT), now=NOW)


def test_capability_failure_degrades_startup_and_orchestrator_failure_emits_failed_result():
    agent, sender, identity_store, credential_store = _agent()
    degraded = RavenXAgent(
        config=AgentConfig(), identity_store=identity_store, credential_store=credential_store,
        capability_provider=FailingCapabilities(), scanner_registry=object(),
        assessment_orchestrator=agent.assessment_orchestrator, sender=sender,
    )
    with pytest.raises(AgentStartupError):
        degraded.start(now=NOW)
    assert degraded.state is AgentLifecycleState.DEGRADED

    class FailingOrchestrator:
        def run(self, target, scanner_ids):
            raise RuntimeError("should not escape")

    failing, sender, _, _ = _agent(FailingOrchestrator())
    failing.start(now=NOW)
    result = failing.handle_dispatch(_dispatch(ENDPOINT), now=NOW)
    assert result.status is AssessmentStatus.FAILED
    assert sender.messages[-1].message_type is AgentMessageType.ASSESSMENT_RESULT
