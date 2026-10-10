from datetime import datetime, timedelta, timezone

import pytest

from backend.agent.heartbeat import HeartbeatScheduler
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.presence import EndpointPresence, EndpointPresenceEvaluator, PresencePolicy, PresenceState
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_presence_repository import InMemoryEndpointPresenceRepository
from backend.application.endpoint.presence_service import EndpointPresenceService


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def endpoint(status=None):
    from backend.domain.endpoint import EndpointStatus
    return Endpoint(EndpointId.new(), "presence-host", PlatformInfo("Windows"),
                    status=status or EndpointStatus.ACTIVE, created_at=NOW)


def test_presence_thresholds_are_deterministic_and_serializable():
    policy = PresencePolicy(10, 30, 60)
    p = EndpointPresence("endpoint-1", last_seen_at=NOW, state=PresenceState.ONLINE)
    assert EndpointPresenceEvaluator.evaluate(p, NOW + timedelta(seconds=29), policy).state is PresenceState.ONLINE
    stale = EndpointPresenceEvaluator.evaluate(p, NOW + timedelta(seconds=30), policy)
    assert stale.state is PresenceState.STALE
    offline = EndpointPresenceEvaluator.evaluate(stale, NOW + timedelta(seconds=60), policy)
    assert offline.state is PresenceState.OFFLINE
    assert offline.to_dict()["state"] == "offline"


def test_invalid_presence_policy_is_rejected():
    with pytest.raises(ValueError):
        PresencePolicy(60, 60, 600)
    with pytest.raises(ValueError):
        PresencePolicy(60, 180, 180)


def test_heartbeat_updates_server_receipt_and_reconnects_without_reviving_revoked():
    ep = endpoint()
    endpoints = InMemoryEndpointRepository(); endpoints.add(ep)
    repository = InMemoryEndpointPresenceRepository()
    service = EndpointPresenceService(endpoints, repository, clock=lambda: NOW)
    online = service.record_heartbeat(ep.endpoint_id, receipt_at=NOW + timedelta(seconds=5), observed_at=NOW - timedelta(days=1))
    assert online.state is PresenceState.ONLINE
    assert online.last_seen_at == NOW + timedelta(seconds=5)
    offline = service.evaluate(ep.endpoint_id, now=NOW + timedelta(minutes=20))
    assert offline.state is PresenceState.OFFLINE
    recovered = service.record_heartbeat(ep.endpoint_id, receipt_at=NOW + timedelta(minutes=21))
    assert recovered.state is PresenceState.ONLINE and recovered.offline_since is None

    from backend.domain.endpoint import EndpointStatus
    endpoints.update(ep.transition_to(EndpointStatus.REVOKED, NOW + timedelta(minutes=22)))
    with pytest.raises(PermissionError):
        service.record_heartbeat(ep.endpoint_id, receipt_at=NOW + timedelta(minutes=23))
    assert repository.get(str(ep.endpoint_id)).state is PresenceState.ONLINE


def test_authenticated_handler_updates_presence_using_receipt_clock():
    from types import SimpleNamespace
    from backend.application.control_plane.handlers import ControlPlaneAgentHandlers
    from backend.protocol.agent import AgentHeartbeat, ProtocolVersion
    ep = endpoint()
    endpoints = InMemoryEndpointRepository(); endpoints.add(ep)
    repository = InMemoryEndpointPresenceRepository()
    service = EndpointPresenceService(endpoints, repository, clock=lambda: NOW)
    class _Sessions:
        def get(self, _): return None
        def register(self, _): pass
    handlers = ControlPlaneAgentHandlers(_Sessions(), None, presence_service=service)
    payload = AgentHeartbeat(ep.endpoint_id, "1.0.0", ProtocolVersion.current(), NOW - timedelta(days=1))
    handlers.heartbeat(SimpleNamespace(endpoint_id=ep.endpoint_id), payload)
    stored = repository.get(str(ep.endpoint_id))
    assert stored.state is PresenceState.ONLINE
    assert stored.last_seen_at > payload.observed_at


class _Sender:
    def __init__(self, fail=False): self.fail, self.messages = fail, []
    def send(self, envelope):
        if self.fail: raise OSError("network unavailable")
        self.messages.append(envelope)


def test_heartbeat_scheduler_run_once_failure_and_recovery_preserve_identity():
    from backend.agent.runtime import AgentConfig, InMemoryAgentCredentialStore, InMemoryAgentIdentityStore, RavenXAgent, AgentCredential
    from backend.domain.enrollment import CredentialId
    from backend.application.scanner.registry import ScannerRegistry
    from backend.application.scanner.local_capabilities import LocalTargetCapabilityProvider
    from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
    from backend.application.scanner.legacy_adapters import legacy_scanner_adapters
    identity = InMemoryAgentIdentityStore(EndpointId.new())
    credentials = InMemoryAgentCredentialStore(AgentCredential(CredentialId.new(), "secret"))
    sender = _Sender()
    agent = RavenXAgent(config=AgentConfig(), identity_store=identity, credential_store=credentials,
                        capability_provider=LocalTargetCapabilityProvider(), scanner_registry=ScannerRegistry(legacy_scanner_adapters()),
                        assessment_orchestrator=LocalAssessmentOrchestrator(ScannerRegistry(legacy_scanner_adapters()), LocalTargetCapabilityProvider()), sender=sender)
    agent.start(now=NOW)
    scheduler = HeartbeatScheduler(agent, interval_seconds=60)
    scheduler.start(); scheduler.run_once(now=NOW)
    assert len(sender.messages) == 1
    sender.fail = True
    with pytest.raises(OSError): scheduler.run_once(now=NOW + timedelta(minutes=1))
    assert agent.endpoint_id is not None and credentials.load().secret == "secret"
    sender.fail = False; scheduler.run_once(now=NOW + timedelta(minutes=2))
    assert agent.state.value == "ready"
    scheduler.stop(); assert not scheduler.running
