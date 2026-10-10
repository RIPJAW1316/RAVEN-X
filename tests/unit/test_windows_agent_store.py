from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from backend.agent.windows_store import AgentRecord, DpapiMachineProtector, WindowsAgentStateStore
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId


class FakeProtector:
    def protect(self, plaintext):
        return b"encrypted:" + plaintext

    def unprotect(self, ciphertext):
        assert ciphertext.startswith(b"encrypted:")
        return ciphertext[len(b"encrypted:"):]


class FakeProtectedFiles:
    def verify_directory(self, path):
        assert Path(path).is_dir()

    def verify_protected_file(self, path):
        assert Path(path).is_file()

    def atomic_write_protected(self, path, data):
        Path(path).write_bytes(data)

    def atomic_create_protected(self, path, data):
        with Path(path).open("xb") as output:
            output.write(data)


def _grant():
    return type("Grant", (), {
        "endpoint_id": EndpointId.new(), "credential_id": str(CredentialId.new()),
        "credential_secret": "x" * 48, "organization_id": str(uuid4()),
        "protocol_version": "1.0",
        "credential_expires_at": datetime.now(timezone.utc) + timedelta(days=30),
    })()


def test_enrollment_record_is_one_time_atomic_and_redacted(tmp_path):
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeProtectedFiles())
    grant = _grant()
    record = store.save_enrollment(grant, server_url="https://control.example", ca_sha256="a" * 64)
    assert isinstance(record, AgentRecord)
    assert store.identity_store.load() == grant.endpoint_id
    assert store.credential_store.load().secret == grant.credential_secret
    assert "x" * 48 not in repr(record)
    assert not (tmp_path / "credential.bin").read_bytes().startswith(b"{")
    with pytest.raises(Exception, match="already enrolled"):
        store.save_enrollment(_grant(), server_url="https://control.example")


def test_expired_credential_is_not_served(tmp_path):
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeProtectedFiles())
    grant = _grant()
    grant.credential_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    store.save_enrollment(grant, server_url="https://control.example")
    assert store.credential_store.load() is None


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI requires Windows")
def test_real_machine_dpapi_round_trip():
    protector = DpapiMachineProtector()
    plaintext = b"ravenx-dpapi-round-trip"
    ciphertext = protector.protect(plaintext)
    assert ciphertext != plaintext
    assert protector.unprotect(ciphertext) == plaintext


def test_concurrent_local_enrollment_consumes_only_one_token(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, Event
    from backend.agent.windows_store import AgentStateError

    start = Barrier(2)
    release = Event()
    rejected = Event()
    redeemed = []
    def enroll_one():
        store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeProtectedFiles())
        start.wait(timeout=5)
        try:
            with store.enrollment_lock():
                grant = _grant()
                redeemed.append(grant.endpoint_id)
                release.wait(timeout=5)
                return store.save_enrollment(grant, server_url="https://control.example")
        except AgentStateError:
            rejected.set()
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(enroll_one), pool.submit(enroll_one)
        assert rejected.wait(timeout=5)
        release.set()
        results = (first.result(timeout=5), second.result(timeout=5))
    assert len(redeemed) == 1
    assert sum(value is not None for value in results) == 1
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeProtectedFiles())
    assert store.load_record().endpoint_id == redeemed[0]
    before = store.path.read_bytes()
    with pytest.raises(AgentStateError, match="already enrolled"):
        with store.enrollment_lock():
            pytest.fail("an existing identity must be rejected before redeeming a token")
    assert store.path.read_bytes() == before
