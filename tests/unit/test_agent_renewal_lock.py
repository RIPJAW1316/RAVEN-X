"""The renewal lock is owned by an OS handle: never by age, never released by a non-owner."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import inspect
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from backend.agent.file_lock import ExclusiveFileLock, FileLockBusyError
from backend.agent.renewal import CredentialRenewalCoordinator, RenewalOutcome
from backend.agent.windows_store import RenewalLockBusyError, WindowsAgentStateStore
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId


REPO_ROOT = Path(__file__).resolve().parents[2]
_HOLDER = textwrap.dedent("""
    import sys
    from backend.agent.file_lock import ExclusiveFileLock
    lock = ExclusiveFileLock(sys.argv[1])
    for line in sys.stdin:
        command = line.strip()
        if command == "acquire":
            try:
                lock.acquire()
                print("acquired", flush=True)
            except Exception:
                print("busy", flush=True)
        elif command == "release":
            lock.release()
            print("released", flush=True)
        elif command == "exit":
            break
""")


class Holder:
    """A separate Python process that owns (or tries to own) the lock on command."""

    def __init__(self, path):
        self.process = subprocess.Popen(
            [sys.executable, "-c", _HOLDER, str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, cwd=REPO_ROOT, env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})

    def send(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.process.stdout.readline().strip()

    def kill(self):
        self.process.kill()
        self.process.wait(timeout=20)

    def close(self):
        if self.process.poll() is None:
            self.send("exit")
            self.process.wait(timeout=20)


class _Files:
    def verify_directory(self, path):
        assert Path(path).is_dir()

    def verify_protected_file(self, path):
        assert Path(path).is_file()

    def atomic_write_protected(self, path, data):
        Path(path).write_bytes(data)

    def atomic_create_protected(self, path, data):
        with Path(path).open("xb") as handle:
            handle.write(data)


class _Protector:
    def protect(self, plaintext):
        return b"p:" + plaintext

    def unprotect(self, ciphertext):
        return ciphertext[2:]


def _lock_file(tmp_path):
    path = tmp_path / ".renewal.lock"
    path.write_bytes(b"\x00")
    return path


def _enrolled_store(tmp_path):
    store = WindowsAgentStateStore(tmp_path, protector=_Protector(), files=_Files())
    store.save_enrollment(SimpleNamespace(
        endpoint_id=EndpointId.new(), credential_id=str(CredentialId.new()), credential_secret="s" * 43,
        organization_id=str(uuid4()), protocol_version="1.0",
        credential_expires_at=datetime.now(timezone.utc) + timedelta(days=2)),
        server_url="https://control.example", ca_sha256="c" * 64)
    return store


def test_lock_is_exclusive_within_a_process_and_release_never_deletes_the_file(tmp_path):
    path = _lock_file(tmp_path)
    first, second = ExclusiveFileLock(path), ExclusiveFileLock(path)
    first.acquire()
    with pytest.raises(FileLockBusyError):
        second.acquire()
    first.release()
    first.release()  # a repeated release is a no-op
    assert path.exists()
    second.acquire()
    with pytest.raises(FileLockBusyError):
        first.acquire()
    second.release()
    assert path.exists()


def test_lock_api_has_no_time_based_reclamation():
    for target in (ExclusiveFileLock.acquire, ExclusiveFileLock.release, WindowsAgentStateStore.renewal_lock):
        parameters = set(inspect.signature(target).parameters)
        assert not parameters & {"now", "stale_after_seconds", "timeout", "max_age"}


def test_a_live_owner_keeps_the_lock_however_much_time_appears_to_pass(tmp_path, monkeypatch):
    path = _lock_file(tmp_path)
    owner = Holder(path)
    try:
        assert owner.send("acquire") == "acquired"
        future = time.time() + 30 * 24 * 3600
        monkeypatch.setattr(time, "time", lambda: future)
        monkeypatch.setattr(time, "monotonic", lambda: future)
        for _ in range(3):
            with pytest.raises(FileLockBusyError):
                ExclusiveFileLock(path).acquire()
        assert owner.process.poll() is None
        assert path.exists()
    finally:
        owner.close()


def _acquire_eventually(path, timeout=20.0):
    """Windows unlocks a terminated process's byte ranges asynchronously; the agent simply retries."""
    deadline = time.monotonic() + timeout
    while True:
        lock = ExclusiveFileLock(path)
        try:
            lock.acquire()
            return lock
        except FileLockBusyError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def test_the_lock_is_released_when_its_owner_process_is_terminated(tmp_path):
    path = _lock_file(tmp_path)
    owner = Holder(path)
    assert owner.send("acquire") == "acquired"
    with pytest.raises(FileLockBusyError):
        ExclusiveFileLock(path).acquire()
    owner.kill()

    successor = _acquire_eventually(path)
    assert path.exists()
    successor.release()


def test_a_previous_owner_releasing_again_cannot_free_the_successor_lock(tmp_path):
    path = _lock_file(tmp_path)
    process_a, process_c = Holder(path), Holder(path)
    try:
        assert process_a.send("acquire") == "acquired"
        assert process_a.send("release") == "released"
        process_b = ExclusiveFileLock(path)
        process_b.acquire()
        # A's late, duplicate release must not touch B's lock or its file.
        assert process_a.send("release") == "released"
        assert path.exists()
        assert process_a.send("acquire") == "busy"
        assert process_c.send("acquire") == "busy"
        process_b.release()
        assert process_c.send("acquire") == "acquired"
    finally:
        process_a.close()
        process_c.close()


def test_store_renewal_lock_serializes_threads_and_survives_a_preexisting_lock_file(tmp_path):
    store = _enrolled_store(tmp_path)
    # A leftover lock file (for example from an older implementation) carries no ownership.
    store.renewal_lock_path.write_bytes(b'{"pid": 1, "created_at": "2020-01-01T00:00:00+00:00"}')
    with store.renewal_lock():
        with ThreadPoolExecutor(max_workers=1) as pool:
            def contend():
                with store.renewal_lock():
                    return "acquired"
            with pytest.raises(RenewalLockBusyError):
                pool.submit(contend).result(timeout=10)
    with store.renewal_lock():
        pass
    assert store.renewal_lock_path.exists()


def test_coordinator_reports_busy_while_another_process_holds_the_renewal_lock(tmp_path):
    store = _enrolled_store(tmp_path)

    class Transport:
        def renew_credential(self, **_):
            pytest.fail("renewal must not run while another process holds the lock")

    with store.renewal_lock():
        pass
    owner = Holder(store.renewal_lock_path)
    try:
        assert owner.send("acquire") == "acquired"
        coordinator = CredentialRenewalCoordinator(store, Transport(), clock=lambda: 0.0)
        assert coordinator.advance() is RenewalOutcome.BUSY
        assert store.load_pending_renewal() is None
    finally:
        owner.close()
