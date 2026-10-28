"""Prepared-successor publication fault injection.

These tests prove crash-consistent recovery at each file-publication boundary.
They do not prove sudden power-loss durability of NTFS metadata. That remains
a physical validation gate and must not be treated as a PASS.
"""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest

from backend.agent.renewal import CredentialRenewalCoordinator
from backend.agent.windows_store import AgentStateError, PendingRenewal, WindowsAgentStateStore
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.infrastructure.security.windows_files import DurabilityError, flush_published


NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


class FakeProtector:
    def protect(self, plaintext):
        return b"encrypted:" + plaintext

    def unprotect(self, ciphertext):
        assert ciphertext.startswith(b"encrypted:")
        return ciphertext[len(b"encrypted:"):]


class RecordingFiles:
    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.events = []

    def verify_directory(self, path):
        assert Path(path).is_dir()

    def verify_protected_file(self, path):
        assert Path(path).is_file()

    def atomic_write_protected(self, path, data):
        Path(path).write_bytes(data)

    def atomic_create_protected(self, path, data):
        path = Path(path)
        temporary = path.with_name(path.name + ".deadbeef.tmp")
        temporary.write_bytes(data)
        self.events.append(("tmp_written", path.name))
        if self.fail_at and path.name == "renewal.bin" and self.fail_at == "before_publish":
            raise OSError("publication interrupted before the durable name existed")
        path.write_bytes(data)
        self.events.append(("published", path.name))
        if self.fail_at and path.name == "renewal.bin" and self.fail_at == "before_unlink":
            raise OSError("cleanup interrupted after publication")
        temporary.unlink()
        self.events.append(("tmp_unlinked", path.name))


def _grant():
    return type("Grant", (), {
        "endpoint_id": EndpointId.new(), "credential_id": str(CredentialId.new()),
        "credential_secret": "x" * 48, "organization_id": str(uuid4()),
        "protocol_version": "1.0",
        "credential_expires_at": NOW + timedelta(days=30),
    })()


def _enrolled(tmp_path, *, files=None):
    store = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=files or RecordingFiles())
    store.save_enrollment(_grant(), server_url="https://control.example", ca_sha256="a" * 64)
    return store


def test_prepare_does_not_return_until_publication_succeeds(tmp_path):
    store = _enrolled(tmp_path, files=RecordingFiles(fail_at="before_publish"))
    with pytest.raises(OSError, match="publication interrupted"):
        store.prepare_renewal(now=NOW)
    assert not (tmp_path / "renewal.bin").exists()
    assert list(tmp_path.glob("renewal.bin.*.tmp"))


def test_orphaned_prepared_temp_is_republished_instead_of_deleted(tmp_path):
    store = _enrolled(tmp_path, files=RecordingFiles(fail_at="before_publish"))
    with pytest.raises(OSError):
        store.prepare_renewal(now=NOW)
    recovered = WindowsAgentStateStore(
        tmp_path, protector=FakeProtector(), files=RecordingFiles()
    ).recover_prepared_publication()
    assert recovered is not None
    assert (tmp_path / "renewal.bin").exists()
    assert store.load_pending_renewal() == recovered
    assert not list(tmp_path.glob("renewal.bin.*.tmp"))
    with pytest.raises(AgentStateError, match="already prepared"):
        store.prepare_renewal(now=NOW)


def test_published_renewal_survives_cleanup_interruption(tmp_path):
    store = _enrolled(tmp_path, files=RecordingFiles(fail_at="before_unlink"))
    with pytest.raises(OSError, match="cleanup interrupted"):
        store.prepare_renewal(now=NOW)
    assert (tmp_path / "renewal.bin").exists()
    recovered = store.recover_prepared_publication()
    assert recovered is not None
    assert not list(tmp_path.glob("renewal.bin.*.tmp"))


def test_cleanup_does_not_delete_prepared_successor_temps(tmp_path):
    store = _enrolled(tmp_path)
    pending = store.prepare_renewal(now=NOW)
    orphan = tmp_path / "renewal.bin.orphan.tmp"
    orphan.write_bytes((tmp_path / "renewal.bin").read_bytes())
    assert store.cleanup_interrupted_writes() == 0
    assert orphan.exists()
    assert store.load_pending_renewal() == pending


def test_foreign_and_corrupt_temps_are_left_in_place(tmp_path):
    store = _enrolled(tmp_path)
    record = store.load_record()
    foreign = PendingRenewal(EndpointId.new(), record.organization_id, record.credential_id,
                             CredentialId.new(), "F" * 43, NOW)
    foreign_path = tmp_path / "renewal.bin.foreign.tmp"
    foreign_path.write_bytes(FakeProtector().protect(foreign.to_json_bytes()))
    corrupt = tmp_path / "renewal.bin.corrupt.tmp"
    corrupt.write_bytes(b"not-a-protected-record")
    assert store.recover_prepared_publication() is None
    assert foreign_path.exists() and corrupt.exists()
    assert store.load_record() == record


def test_flush_published_is_documented_as_best_effort_not_power_loss_proof():
    assert "FlushFileBuffers" in flush_published.__doc__
    assert "not a proof" in flush_published.__doc__
    assert "physical gate" in flush_published.__doc__
    assert "DurabilityError" in flush_published.__doc__


def test_required_file_flush_failure_propagates(tmp_path, monkeypatch):
    path = tmp_path / "renewal.bin"
    path.write_bytes(b"prepared")
    real_fsync = os.fsync

    def fail_fsync(descriptor):
        raise OSError("flush failed")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    try:
        with pytest.raises(DurabilityError, match="required file durability flush failed"):
            flush_published(path)
    finally:
        monkeypatch.setattr(os, "fsync", real_fsync)


def test_required_file_open_failure_propagates(tmp_path, monkeypatch):
    path = tmp_path / "renewal.bin"
    path.write_bytes(b"prepared")
    real_open = os.open

    def fail_open(file, flags, *args, **kwargs):
        if str(file).endswith("renewal.bin"):
            raise OSError("open failed")
        return real_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail_open)
    with pytest.raises(DurabilityError, match="required file durability flush failed"):
        flush_published(path)


def test_directory_metadata_flush_is_a_reported_limitation_not_success(tmp_path):
    path = tmp_path / "renewal.bin"
    path.write_bytes(b"prepared")
    result = flush_published(path)
    assert result.file_durable is True
    if os.name == "nt":
        assert result.directory_metadata_confirmed is False
        assert result.limitation == "ntfs_directory_metadata_not_flushable"


def test_required_flush_failure_sends_no_renewal_request_and_keeps_a_recoverable_orphan(tmp_path):
    class _StoppingFiles(RecordingFiles):
        def atomic_create_protected(self, path, data):
            path = Path(path)
            path.write_bytes(data)
            if path.name == "renewal.bin":
                raise DurabilityError("required file durability flush failed")

    store = _enrolled(tmp_path, files=_StoppingFiles())

    class _Transport:
        def __init__(self):
            self.calls = 0

        def renew_credential(self, **kwargs):
            self.calls += 1
            raise AssertionError("renewal HTTP was sent")

        def confirm_renewal(self, **kwargs):
            self.calls += 1
            raise AssertionError("confirm HTTP was sent")

    transport = _Transport()
    coordinator = CredentialRenewalCoordinator(
        store, transport, now_fn=lambda: NOW, threshold=timedelta(days=31), retry_interval=timedelta(0))
    with pytest.raises(DurabilityError):
        coordinator.advance()
    assert transport.calls == 0
    assert (tmp_path / "renewal.bin").is_file()

    recovered = WindowsAgentStateStore(tmp_path, protector=FakeProtector(), files=RecordingFiles())
    record, pending = recovered.reconcile_renewal_state()
    assert record is not None and pending is not None
    assert pending.predecessor_credential_id == record.credential_id


class _RetryFiles(RecordingFiles):
    def __init__(self):
        super().__init__()
        self.durable = False
        self.flushes = 0

    def atomic_create_protected(self, path, data):
        Path(path).write_bytes(data)
        if Path(path).name == "renewal.bin":
            self.require_durable_file(path)

    def require_durable_file(self, path):
        if Path(path).name != "renewal.bin":
            return
        self.flushes += 1
        if not self.durable:
            raise DurabilityError("required file durability flush failed")


def test_failed_flush_is_retried_and_keeps_the_same_successor(tmp_path):
    files = _RetryFiles()
    store = _enrolled(tmp_path, files=files)

    class _Transport:
        def __init__(self):
            self.calls = []

        def renew_credential(self, **kwargs):
            self.calls.append(kwargs["successor_credential_id"])
            return type("Receipt", (), {"credential_expires_at": NOW + timedelta(days=30)})()

        def confirm_renewal(self, **kwargs):
            return type("Receipt", (), {"credential_expires_at": NOW + timedelta(days=30)})()

    transport = _Transport()
    coordinator = CredentialRenewalCoordinator(
        store, transport, now_fn=lambda: NOW, threshold=timedelta(days=31), retry_interval=timedelta(0))
    with pytest.raises(DurabilityError):
        coordinator.advance()
    with pytest.raises(DurabilityError):
        coordinator.advance()
    assert transport.calls == []
    assert files.flushes >= 2
    prepared = store.load_pending_renewal()
    files.durable = True
    assert coordinator.advance() == __import__(
        "backend.agent.renewal", fromlist=["RenewalOutcome"]).RenewalOutcome.RENEWED
    assert transport.calls == [str(prepared.successor_credential_id)]


def test_recovered_orphan_is_not_proposed_until_its_flush_succeeds(tmp_path):
    files = _RetryFiles()
    store = _enrolled(tmp_path, files=files)
    record = store.load_record()
    pending = PendingRenewal(
        record.endpoint_id, record.organization_id, record.credential_id,
        CredentialId.new(), "z" * 43, NOW)
    orphan = tmp_path / "renewal.bin.orphan.tmp"
    orphan.write_bytes(FakeProtector().protect(pending.to_json_bytes()))

    class _Transport:
        def __init__(self):
            self.calls = []

        def renew_credential(self, **kwargs):
            self.calls.append(kwargs["successor_credential_id"])
            return type("Receipt", (), {"credential_expires_at": NOW + timedelta(days=30)})()

        def confirm_renewal(self, **kwargs):
            return type("Receipt", (), {"credential_expires_at": NOW + timedelta(days=30)})()

    transport = _Transport()
    coordinator = CredentialRenewalCoordinator(
        store, transport, now_fn=lambda: NOW, threshold=timedelta(days=31), retry_interval=timedelta(0))
    with pytest.raises(DurabilityError):
        coordinator.advance()
    assert transport.calls == []
    assert (tmp_path / "renewal.bin").is_file()
    files.durable = True
    coordinator.advance()
    assert transport.calls == [str(pending.successor_credential_id)]


def test_distinct_orphan_successors_are_not_chosen(tmp_path):
    store = _enrolled(tmp_path)
    record = store.load_record()
    first = PendingRenewal(record.endpoint_id, record.organization_id, record.credential_id,
                           CredentialId.new(), "a" * 43, NOW)
    second = PendingRenewal(record.endpoint_id, record.organization_id, record.credential_id,
                            CredentialId.new(), "b" * 43, NOW + timedelta(seconds=1))
    protector = FakeProtector()
    (tmp_path / "renewal.bin.one.tmp").write_bytes(protector.protect(first.to_json_bytes()))
    (tmp_path / "renewal.bin.two.tmp").write_bytes(protector.protect(second.to_json_bytes()))
    with pytest.raises(AgentStateError, match="ambiguous"):
        store.recover_prepared_publication()
    assert (tmp_path / "renewal.bin.one.tmp").is_file()
    assert (tmp_path / "renewal.bin.two.tmp").is_file()
    assert not (tmp_path / "renewal.bin").exists()
    duplicate = tmp_path / "other"
    duplicate.mkdir()
    same = _enrolled(duplicate)
    same_record = same.load_record()
    one = PendingRenewal(same_record.endpoint_id, same_record.organization_id, same_record.credential_id,
                         CredentialId.new(), "c" * 43, NOW)
    (duplicate / "renewal.bin.left.tmp").write_bytes(protector.protect(one.to_json_bytes()))
    (duplicate / "renewal.bin.right.tmp").write_bytes(protector.protect(one.to_json_bytes()))
    recovered = same.recover_prepared_publication()
    assert recovered is not None
    assert recovered.successor_credential_secret == "c" * 43
