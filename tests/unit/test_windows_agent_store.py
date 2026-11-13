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


@pytest.mark.parametrize("year", [2001, 2099])
@pytest.mark.parametrize("offset_us, accepted", [(-1, True), (0, False), (1, False)])
def test_credential_expiry_boundary_uses_controlled_clock(tmp_path, monkeypatch, year, offset_us, accepted):
    expiry = datetime(year, 1, 1, 12, 0, tzinfo=timezone.utc)
    observed = expiry + timedelta(microseconds=offset_us)

    class ControlledDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return observed.astimezone(tz) if tz is not None else observed.replace(tzinfo=None)

    monkeypatch.setattr("backend.agent.windows_store.datetime", ControlledDatetime)
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeProtectedFiles())
    grant = _grant()
    grant.credential_expires_at = expiry
    store.save_enrollment(grant, server_url="https://control.example")
    credential = store.credential_store.load()
    if accepted:
        assert credential.credential_id == CredentialId(grant.credential_id)
        assert credential.secret == grant.credential_secret
    else:
        assert credential is None
    assert store.load_record().credential_expires_at == expiry


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


# --- WS-01 agent-prepared renewal state -------------------------------------------------------

import json

from backend.agent.windows_store import AgentStateError, PendingRenewal
from backend.infrastructure.security.windows_files import WindowsFileSecurityError

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
BASELINE_V1_KEYS = {"version", "endpoint_id", "credential_id", "credential_secret", "organization_id",
                    "protocol_version", "credential_expires_at", "server_url", "ca_sha256"}


def _baseline_v1_reader(plaintext: bytes):
    """The parsing rules of the previously shipped agent (fc9d3c38), used to prove rollback compatibility."""
    data = json.loads(plaintext.decode("utf-8"))
    if data["version"] != 1:
        raise ValueError("state version mismatch")
    return AgentRecord(EndpointId(data["endpoint_id"]), CredentialId(data["credential_id"]),
                       data["credential_secret"], data["organization_id"], data["protocol_version"],
                       datetime.fromisoformat(data["credential_expires_at"]), data["server_url"],
                       data.get("ca_sha256"))


def _enrolled(tmp_path, *, protector=None, files=None):
    store = WindowsAgentStateStore(tmp_path, protector=protector or FakeProtector(),
                                   files=files or FakeProtectedFiles())
    record = store.save_enrollment(_grant(), server_url="https://control.example", ca_sha256="a" * 64)
    return store, record


def test_prepare_persists_a_protected_successor_before_any_request_and_never_overwrites_it(tmp_path):
    store, record = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)

    assert pending.predecessor_credential_id == record.credential_id
    assert pending.successor_credential_id != record.credential_id
    assert len(pending.successor_credential_secret) >= 43
    assert pending.successor_credential_secret not in repr(pending)
    assert store.load_pending_renewal() == pending
    assert (tmp_path / "renewal.bin").read_bytes().startswith(b"encrypted:")
    assert store.load_record() == record
    with pytest.raises(AgentStateError, match="already prepared"):
        store.prepare_renewal(now=NOW)
    assert store.load_pending_renewal() == pending


def test_promotion_is_atomic_preserves_bindings_and_accepts_duplicate_acknowledgements(tmp_path):
    store, record = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)
    expires = NOW + timedelta(days=30)

    promoted = store.promote_renewal(pending, credential_expires_at=expires)
    assert promoted.credential_id == pending.successor_credential_id
    assert promoted.credential_secret == pending.successor_credential_secret
    assert (promoted.endpoint_id, promoted.organization_id, promoted.server_url, promoted.ca_sha256) == (
        record.endpoint_id, record.organization_id, record.server_url, record.ca_sha256)
    assert promoted.credential_expires_at == expires
    assert store.load_pending_renewal() is None
    assert store.credential_store.load().secret == pending.successor_credential_secret
    # A delayed duplicate acknowledgement of the same successor is a no-op.
    assert store.promote_renewal(pending, credential_expires_at=expires + timedelta(hours=1)) == promoted
    assert store.load_record() == promoted


def test_an_acknowledgement_for_any_other_successor_never_changes_state(tmp_path):
    store, record = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)
    impostor = PendingRenewal(pending.endpoint_id, pending.organization_id, pending.predecessor_credential_id,
                              CredentialId.new(), "B" * 43, NOW)
    with pytest.raises(AgentStateError, match="does not match"):
        store.promote_renewal(impostor, credential_expires_at=NOW + timedelta(days=30))
    assert store.load_record() == record
    assert store.load_pending_renewal() == pending


def test_reconcile_discards_an_already_promoted_renewal_and_fails_closed_on_foreign_lineage(tmp_path):
    store, record = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)
    renewal_bytes = (tmp_path / "renewal.bin").read_bytes()
    promoted = store.promote_renewal(pending, credential_expires_at=NOW + timedelta(days=30))
    # Simulate power loss after credential.bin was replaced but before renewal.bin was removed.
    (tmp_path / "renewal.bin").write_bytes(renewal_bytes)
    assert store.reconcile_renewal_state() == (promoted, None)
    assert not (tmp_path / "renewal.bin").exists()

    foreign = PendingRenewal(EndpointId.new(), record.organization_id, promoted.credential_id,
                             CredentialId.new(), "C" * 43, NOW)
    (tmp_path / "renewal.bin").write_bytes(FakeProtector().protect(foreign.to_json_bytes()))
    with pytest.raises(AgentStateError, match="different endpoint"):
        store.reconcile_renewal_state()
    unrelated = PendingRenewal(promoted.endpoint_id, record.organization_id, CredentialId.new(),
                               CredentialId.new(), "D" * 43, NOW)
    (tmp_path / "renewal.bin").write_bytes(FakeProtector().protect(unrelated.to_json_bytes()))
    with pytest.raises(AgentStateError, match="does not extend"):
        store.reconcile_renewal_state()
    assert store.load_record() == promoted


def test_credential_state_keeps_the_version_1_format_readable_by_the_previous_agent(tmp_path):
    store, record = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)
    store.promote_renewal(pending, credential_expires_at=NOW + timedelta(days=30))

    plaintext = FakeProtector().unprotect((tmp_path / "credential.bin").read_bytes())
    assert set(json.loads(plaintext)) == BASELINE_V1_KEYS
    assert json.loads(plaintext)["version"] == 1
    rolled_back = _baseline_v1_reader(plaintext)
    assert rolled_back.credential_id == pending.successor_credential_id
    assert rolled_back.credential_secret == pending.successor_credential_secret
    # A pending renewal lives in its own file, so the previous agent never sees it.
    second = store.prepare_renewal(now=NOW + timedelta(days=24))
    plaintext = FakeProtector().unprotect((tmp_path / "credential.bin").read_bytes())
    assert _baseline_v1_reader(plaintext).credential_id == second.predecessor_credential_id


def test_version_1_state_written_by_the_installed_agent_loads_and_renews(tmp_path):
    endpoint_id, credential_id, organization_id = EndpointId.new(), CredentialId.new(), str(uuid4())
    installed = {"version": 1, "endpoint_id": str(endpoint_id), "credential_id": str(credential_id),
                 "credential_secret": "v" * 48, "organization_id": organization_id, "protocol_version": "1.0",
                 "credential_expires_at": (NOW + timedelta(days=3)).isoformat(),
                 "server_url": "https://control.example", "ca_sha256": "b" * 64}
    (tmp_path / "credential.bin").write_bytes(FakeProtector().protect(
        json.dumps(installed, separators=(",", ":"), sort_keys=True).encode("utf-8")))
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=FakeProtectedFiles())

    assert store.load_record().credential_id == credential_id
    assert store.load_pending_renewal() is None
    pending = store.prepare_renewal(now=NOW)
    promoted = store.promote_renewal(pending, credential_expires_at=NOW + timedelta(days=30))
    assert (promoted.endpoint_id, promoted.organization_id, promoted.ca_sha256) == (endpoint_id, organization_id, "b" * 64)


def test_dpapi_failure_while_preparing_leaves_no_renewal_state(tmp_path):
    store, record = _enrolled(tmp_path)

    class FailingProtector(FakeProtector):
        def protect(self, plaintext):
            raise AgentStateError("DPAPI CryptProtectData failed")

    failing = WindowsAgentStateStore(tmp_path, protector=FailingProtector(), files=FakeProtectedFiles())
    with pytest.raises(AgentStateError, match="DPAPI"):
        failing.prepare_renewal(now=NOW)
    assert not (tmp_path / "renewal.bin").exists()
    assert store.load_record() == record


def test_dpapi_or_file_failure_while_promoting_keeps_the_credential_and_the_prepared_successor(tmp_path):
    store, record = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)
    credential_bytes = (tmp_path / "credential.bin").read_bytes()

    class FailingProtector(FakeProtector):
        def protect(self, plaintext):
            raise AgentStateError("DPAPI CryptProtectData failed")

    with pytest.raises(AgentStateError, match="DPAPI"):
        WindowsAgentStateStore(tmp_path, protector=FailingProtector(), files=FakeProtectedFiles()).promote_renewal(
            pending, credential_expires_at=NOW + timedelta(days=30))
    assert (tmp_path / "credential.bin").read_bytes() == credential_bytes

    class InterruptedFiles(FakeProtectedFiles):
        def atomic_write_protected(self, path, data):
            Path(path).with_name("credential.bin.deadbeef.tmp").write_bytes(b"partial")
            raise WindowsFileSecurityError("ACL verification failed on the temporary credential file")

    with pytest.raises(WindowsFileSecurityError):
        WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=InterruptedFiles()).promote_renewal(
            pending, credential_expires_at=NOW + timedelta(days=30))
    assert (tmp_path / "credential.bin").read_bytes() == credential_bytes
    assert store.load_pending_renewal() == pending
    # Recovery later completes the same renewal and removes the orphaned temporary file.
    promoted = store.promote_renewal(pending, credential_expires_at=NOW + timedelta(days=30))
    assert promoted.credential_id == pending.successor_credential_id
    assert not list(tmp_path.glob("credential.bin.*.tmp"))


def test_corrupted_renewal_state_fails_closed_without_touching_the_credential(tmp_path):
    store, record = _enrolled(tmp_path)
    store.prepare_renewal(now=NOW)
    (tmp_path / "renewal.bin").write_bytes(b"encrypted:{not json")
    with pytest.raises(AgentStateError):
        store.reconcile_renewal_state()
    assert store.load_record() == record


def test_clearing_agent_state_removes_renewal_state_and_re_enrollment_discards_orphans(tmp_path):
    store, record = _enrolled(tmp_path)
    store.prepare_renewal(now=NOW)
    store.clear()
    assert not (tmp_path / "credential.bin").exists() and not (tmp_path / "renewal.bin").exists()

    orphan = PendingRenewal(EndpointId.new(), str(uuid4()), CredentialId.new(), CredentialId.new(), "E" * 43, NOW)
    (tmp_path / "renewal.bin").write_bytes(FakeProtector().protect(orphan.to_json_bytes()))
    store.save_enrollment(_grant(), server_url="https://control.example", ca_sha256="a" * 64)
    assert store.load_pending_renewal() is None


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI requires Windows")
def test_real_machine_dpapi_protects_the_prepared_successor_and_the_promoted_credential(tmp_path):
    store = WindowsAgentStateStore(tmp_path, protector=DpapiMachineProtector(), files=FakeProtectedFiles())
    grant = _grant()
    store.save_enrollment(grant, server_url="https://control.example", ca_sha256="e" * 64)
    pending = store.prepare_renewal(now=NOW)

    renewal_ciphertext = (tmp_path / "renewal.bin").read_bytes()
    assert pending.successor_credential_secret.encode("ascii") not in renewal_ciphertext
    assert store.load_pending_renewal() == pending
    promoted = store.promote_renewal(pending, credential_expires_at=NOW + timedelta(days=30))
    credential_ciphertext = (tmp_path / "credential.bin").read_bytes()
    assert pending.successor_credential_secret.encode("ascii") not in credential_ciphertext
    assert grant.credential_secret.encode("ascii") not in credential_ciphertext
    assert store.load_record() == promoted
    (tmp_path / "credential.bin").write_bytes(b"corrupted-dpapi-blob")
    with pytest.raises(AgentStateError, match="could not be decrypted"):
        store.load_record()
