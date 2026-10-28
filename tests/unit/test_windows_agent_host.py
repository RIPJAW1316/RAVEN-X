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


def test_host_automatically_renews_near_expiry_credential_and_continues_operating(tmp_path, monkeypatch):
    from backend.agent.host import HostIntervals
    from backend.agent.windows_store import WindowsAgentStateStore
    from backend.infrastructure.transport.http.client import RenewalConfirmation, RenewalReceipt

    class FakeProtector:
        def protect(self, plaintext): return b"enc:" + plaintext
        def unprotect(self, ciphertext): return ciphertext[4:]

    class FakeFiles:
        def verify_directory(self, path): assert tmp_path.is_dir()
        def verify_protected_file(self, path): assert tmp_path.exists()
        def atomic_write_protected(self, path, data): tmp_path.joinpath(path.name).write_bytes(data)
        def atomic_create_protected(self, path, data):
            with tmp_path.joinpath(path.name).open("xb") as handle:
                handle.write(data)

    ca_cert = tmp_path / "ca.pem"
    ca_cert.write_text("trusted CA")
    now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeFiles())
    initial_grant = type("Grant", (), {
        "endpoint_id": EndpointId.new(),
        "credential_id": str(CredentialId.new()),
        "credential_secret": "a" * 48,
        "organization_id": str(uuid4()),
        "protocol_version": "1.0",
        "credential_expires_at": now + timedelta(days=2),
    })()
    enrolled = store.save_enrollment(initial_grant, server_url="https://control.example",
                                     ca_sha256=ca_certificate_digest(ca_cert))

    class RenewalTransport(FakeTransport):
        def __init__(self):
            super().__init__()
            self.renewals = []
            self.confirmations = []

        def renew_credential(self, *, credential, successor_credential_id, successor_credential_secret,
                             protocol_version="1.0", timestamp=None, **_kwargs):
            self.renewals.append((str(credential.credential_id), str(successor_credential_id), timestamp))
            return RenewalReceipt(
                endpoint_id=enrolled.endpoint_id,
                organization_id=enrolled.organization_id,
                credential_id=str(successor_credential_id),
                replaces_credential_id=str(credential.credential_id),
                credential_expires_at=now + timedelta(days=30),
                predecessor_valid_until=now + timedelta(minutes=15),
                protocol_version="1.0",
            )

        def confirm_renewal(self, *, credential, replaces_credential_id=None, protocol_version="1.0",
                            timestamp=None, **_kwargs):
            self.confirmations.append((str(credential.credential_id), replaces_credential_id, timestamp))
            return RenewalConfirmation(
                endpoint_id=enrolled.endpoint_id,
                organization_id=enrolled.organization_id,
                credential_id=str(credential.credential_id),
                credential_expires_at=now + timedelta(days=30),
                replaces_credential_id=replaces_credential_id,
            )

        def poll_work(self):
            self.polls += 1
            return None

    monkeypatch.setattr(host_module, "DurableResultSender", FakeDurableSender)
    transport = RenewalTransport()
    host = WindowsAgentHost(
        store=store,
        server_url="https://control.example",
        ca_cert=ca_cert,
        transport=transport,
        intervals=HostIntervals(renewal_threshold_seconds=7 * 86400.0),
        now_fn=lambda: now,
    )
    assert host.tick() == "idle"
    pending_id = transport.renewals[0][1]
    assert len(transport.renewals) == 1
    assert len(transport.confirmations) == 1
    assert str(store.load_record().credential_id) == pending_id
    assert store.load_pending_renewal() is None
    # Next tick does not renew again because credential now has 30 days remaining
    assert host.tick() == "idle"
    assert len(transport.renewals) == 1


def test_host_defers_renewal_when_endpoint_is_pending_approval(tmp_path, monkeypatch):
    from backend.agent.host import HostIntervals
    from backend.agent.windows_store import WindowsAgentStateStore

    class FakeProtector:
        def protect(self, plaintext): return b"enc:" + plaintext
        def unprotect(self, ciphertext): return ciphertext[4:]

    class FakeFiles:
        def verify_directory(self, path): pass
        def verify_protected_file(self, path): pass
        def atomic_write_protected(self, path, data): path.write_bytes(data)
        def atomic_create_protected(self, path, data):
            with path.open("xb") as handle:
                handle.write(data)

    ca_cert = tmp_path / "ca.pem"
    ca_cert.write_text("trusted CA")
    now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeFiles())
    store.save_enrollment(type("Grant", (), {
        "endpoint_id": EndpointId.new(),
        "credential_id": str(CredentialId.new()),
        "credential_secret": "a" * 48,
        "organization_id": str(uuid4()),
        "protocol_version": "1.0",
        "credential_expires_at": now + timedelta(days=2),
    })(), server_url="https://control.example", ca_sha256=ca_certificate_digest(ca_cert))

    class UnapprovedRenewalTransport(FakeTransport):
        def __init__(self):
            super().__init__()
            self.renewal_attempts = 0

        def renew_credential(self, **_kwargs):
            self.renewal_attempts += 1
            raise HttpTransportError("approval_required", "not active", status_code=403)

    monkeypatch.setattr(host_module, "DurableResultSender", FakeDurableSender)
    transport = UnapprovedRenewalTransport()
    clock_time = [100.0]
    host = WindowsAgentHost(
        store=store,
        server_url="https://control.example",
        ca_cert=ca_cert,
        transport=transport,
        intervals=HostIntervals(renewal_threshold_seconds=7 * 86400.0, renewal_retry_seconds=60.0),
        clock=lambda: clock_time[0],
        jitter=lambda low, high: high,
        now_fn=lambda: now,
    )
    assert host.tick() == "pending_approval"
    assert transport.renewal_attempts == 1
    # Within backoff window, renewal is not retried
    clock_time[0] = 120.0
    assert host.tick() == "idle"
    assert transport.renewal_attempts == 1
