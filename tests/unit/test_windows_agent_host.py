from datetime import datetime, timedelta, timezone
import subprocess
import sys
from uuid import uuid4

import pytest

import backend.agent.host as host_module
from backend.agent.host import WindowsAgentHost, ca_certificate_digest
from backend.agent.runtime import AgentCredential, InMemoryAgentCredentialStore, InMemoryAgentIdentityStore
from backend.agent.windows_store import AgentRecord, AgentStateError
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.infrastructure.transport.http.client import HttpTransportError
from backend.infrastructure.transport.http.client import LeasedHttpWork
from backend.protocol.agent import (
    AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, CorrelationId,
)
from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners


class FakeStore:
    def __init__(self, directory, ca_cert):
        endpoint = EndpointId.new()
        credential_id = CredentialId.new()
        self.directory = directory
        self.record = AgentRecord(
            endpoint, credential_id, "x" * 48, str(uuid4()), "1.0",
            datetime.now(timezone.utc) + timedelta(days=30),
            "https://control.example", ca_certificate_digest(ca_cert),
        )
        self.identity_store = InMemoryAgentIdentityStore(endpoint)
        self.credential_store = InMemoryAgentCredentialStore(AgentCredential(credential_id, "x" * 48))

    def load_record(self):
        return self.record


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.polls = 0

    def send(self, envelope):
        self.sent.append(envelope)

    def poll_work(self):
        self.polls += 1
        if self.polls == 1:
            raise HttpTransportError("approval_required", "pending", status_code=403)
        return None


class FakeDurableSender:
    def __init__(self, transport, directory):
        self.transport = transport
        self.flushed = 0

    def send(self, envelope):
        self.transport.send(envelope)

    def flush(self):
        self.flushed += 1


def test_host_reports_presence_and_waits_for_approval(tmp_path, monkeypatch):
    ca_cert = tmp_path / "ca.pem"
    ca_cert.write_text("CA certificate")
    store = FakeStore(tmp_path, ca_cert)
    transport = FakeTransport()
    monkeypatch.setattr(host_module, "DurableResultSender", FakeDurableSender)
    host = WindowsAgentHost(store=store, server_url="https://control.example", ca_cert=ca_cert,
                            transport=transport)
    assert host.tick() == "pending_approval"
    assert [message.message_type for message in transport.sent] == [
        AgentMessageType.HEARTBEAT, AgentMessageType.CAPABILITIES, AgentMessageType.STATUS,
    ]
    assert host.tick() == "idle"
    assert transport.polls == 2
    assert host.sender.flushed == 2


def test_host_rejects_server_or_ca_swap_and_expired_credential(tmp_path, monkeypatch):
    ca_cert = tmp_path / "ca.pem"
    ca_cert.write_text("trusted CA")
    store = FakeStore(tmp_path, ca_cert)
    monkeypatch.setattr(host_module, "DurableResultSender", FakeDurableSender)
    with pytest.raises(AgentStateError, match="server URL differs"):
        WindowsAgentHost(store=store, server_url="https://attacker.example", ca_cert=ca_cert,
                         transport=FakeTransport())
    ca_cert.write_text("different CA")
    with pytest.raises(AgentStateError, match="CA certificate differs"):
        WindowsAgentHost(store=store, server_url="https://control.example", ca_cert=ca_cert,
                         transport=FakeTransport())


def test_host_executes_one_allowlisted_read_only_dispatch(tmp_path, monkeypatch):
    ca_cert = tmp_path / "ca.pem"
    ca_cert.write_text("trusted CA")
    store = FakeStore(tmp_path, ca_cert)
    manifest = next(scanner.manifest for scanner in windows_read_only_scanners()
                    if scanner.manifest.scanner_id == "windows.uac")
    scanner = WindowsReadOnlyScanner(
        manifest, registry_reader=lambda name: {
            "ConsentPromptBehaviorAdmin": 5, "PromptOnSecureDesktop": 1,
        }[name],
    )
    monkeypatch.setattr(host_module, "windows_read_only_scanners", lambda: (scanner,))
    monkeypatch.setattr(host_module, "DurableResultSender", FakeDurableSender)
    requested_at = datetime.now(timezone.utc)
    dispatch = AssessmentDispatch("assessment-1", store.record.endpoint_id,
                                  ("windows.uac",), requested_at)
    envelope = AgentMessageEnvelope(
        AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(),
        endpoint_id=store.record.endpoint_id, timestamp=requested_at,
        correlation_id=CorrelationId(),
    )
    work = LeasedHttpWork(envelope, str(uuid4()), "lease-token",
                          requested_at + timedelta(minutes=5))

    class WorkTransport(FakeTransport):
        def poll_work(self):
            return work

    transport = WorkTransport()
    host = WindowsAgentHost(store=store, server_url="https://control.example", ca_cert=ca_cert,
                            transport=transport)
    assert host.tick() == "assessed"
    kinds = [message.message_type for message in transport.sent]
    assert kinds[:3] == [AgentMessageType.HEARTBEAT, AgentMessageType.CAPABILITIES, AgentMessageType.STATUS]
    assert AgentMessageType.ASSESSMENT_ACK in kinds
    result = next(message for message in transport.sent if message.message_type is AgentMessageType.ASSESSMENT_RESULT)
    assert result.payload["findings"][0]["title"] == "UAC Not at Maximum Security"


def test_importing_agent_does_not_import_personal_scanner_or_server_stack():
    check = "import sys; import backend.agent.host; print('scanner' in sys.modules, 'fastapi' in sys.modules)"
    run = subprocess.run([sys.executable, "-c", check], capture_output=True, text=True, check=True)
    assert run.stdout.strip() == "False False"
