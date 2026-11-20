"""HMAC verifier-key custody. These tests use disposable SQLite files only."""

from pathlib import Path
import os
import sqlite3
import subprocess
import sys

import pytest

from backend.application.enrollment.service import EnrollmentService
from backend.infrastructure.security.verifier_key import (
    VerifierKeyError,
    bind_control_plane_verifier_key,
    prepare_persistent_verifier_key,
    verifier_key_id,
)


ROOT = Path(__file__).resolve().parents[2]


def _safe_dir() -> Path:
    """A disposable directory whose ancestors do not grant untrusted delete rights."""
    from uuid import uuid4
    from backend.infrastructure.security.windows_files import protect_private_directory
    root = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "ws01-key-tests" / uuid4().hex
    root.mkdir(parents=True)
    if os.name == "nt":
        protect_private_directory(root)
    return root
_STARTUP = r"""
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
os.environ["RAVENX_DATABASE_PATH"] = str(root / "raven_x.db")
os.environ["RAVENX_ENVIRONMENT"] = "production"
os.environ["RAVENX_VERIFIER_KEY_MODE"] = "persistent"
os.environ["RAVENX_ENABLE_LEGACY_ROUTES"] = "false"
os.environ.pop("RAVENX_CREDENTIAL_VERIFIER_KEY", None)

from sqlalchemy import text
from backend.core.database.database import DatabaseManager

db = DatabaseManager()
db.create_tables()
with db.engine.begin() as connection:
    connection.execute(text(
        "INSERT INTO endpoint_credentials (credential_id, endpoint_id, credential_kind, verifier, status, "
        "issued_at, credential_metadata) VALUES ('cred-hmac', 'endpoint-1', 'opaque', "
        "'token-hmac-v2$salt$mac', 'active', '2026-10-01 00:00:00', '{}')"
    ))
db.close()

from fastapi.testclient import TestClient
from backend.api.main import app

failed = False
try:
    with TestClient(app) as client:
        client.get("/ready")
    print("API READY")
    raise SystemExit(2)
except Exception as error:
    failed = True
    print(type(error).__name__)
    print(error)
if (root / "credential-hmac.key").exists():
    print("KEY CREATED")
    raise SystemExit(4)
if not failed:
    raise SystemExit(5)
print("STARTUP_REFUSED")
"""


class _Manager:
    def __init__(self, database: Path):
        self.config = {"type": "sqlite", "sqlite_path": str(database)}
        self.config_path = database.parent / "unused-config.yaml"


def _empty_database(path: Path) -> None:
    sqlite3.connect(path).close()


def _insert_hmac(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS endpoint_credentials ("
        "credential_id TEXT PRIMARY KEY, endpoint_id TEXT, credential_kind TEXT, verifier TEXT, "
        "status TEXT, issued_at TEXT, credential_metadata TEXT)"
    )
    connection.execute(
        "INSERT INTO endpoint_credentials (credential_id, endpoint_id, credential_kind, verifier, status, "
        "issued_at, credential_metadata) VALUES ('cred-hmac', 'endpoint-1', 'opaque', "
        "'token-hmac-v2$salt$mac', 'active', '2026-10-01 00:00:00', '{}')"
    )
    connection.commit()
    connection.close()


def _identity(path: Path):
    connection = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "ravenx_verifier_keys" not in tables:
            return None
        row = connection.execute("SELECT key_id FROM ravenx_verifier_keys WHERE id = 1").fetchone()
        return None if row is None else row[0]
    finally:
        connection.close()


@pytest.fixture
def allow_unprotected_key(monkeypatch):
    monkeypatch.setattr(
        "backend.infrastructure.security.verifier_key.enforce_verifier_key_file_acl",
        lambda path, production=False: None,
    )
    monkeypatch.setattr(
        "backend.infrastructure.security.verifier_key.verify_existing_verifier_key",
        lambda path, production=False: None,
    )


def test_empty_database_bootstraps_once_and_restart_reloads_the_same_key(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    first = prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert (tmp_path / "credential-hmac.key").read_bytes() == first
    assert _identity(database) == verifier_key_id(first)
    second = prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert second == first
    assert _identity(database) == verifier_key_id(first)


@pytest.mark.skipif(os.name != "nt", reason="requires a Windows process token")
def test_verifier_bootstrap_uses_token_sid_when_account_name_resolves_to_another_sid(
    monkeypatch, allow_unprotected_key
):
    import win32security

    other_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinUsersSid)
    monkeypatch.setattr(win32security, "LookupAccountName", lambda *_: (other_sid, "", 4))
    database = _safe_dir() / "raven_x.db"
    _empty_database(database)

    first = prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert _identity(database) == verifier_key_id(first)
    assert prepare_persistent_verifier_key(database, environ={}, environment="production") == first


def test_missing_key_is_not_regenerated_over_active_hmac_credentials(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    key = prepare_persistent_verifier_key(database, environ={}, environment="production")
    _insert_hmac(database)
    (tmp_path / "credential-hmac.key").unlink()
    with pytest.raises(VerifierKeyError, match="will not be regenerated") as error:
        prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert key.hex() not in str(error.value)
    assert not (tmp_path / "credential-hmac.key").exists()
    assert _identity(database) == verifier_key_id(key)


def test_replaced_key_and_environment_key_fail_without_rewriting_identity(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    original = prepare_persistent_verifier_key(database, environ={}, environment="production")
    identity = _identity(database)
    replacement = bytes(byte ^ 0xFF for byte in original)
    (tmp_path / "credential-hmac.key").write_bytes(replacement)
    with pytest.raises(VerifierKeyError, match="does not match the database identity") as error:
        prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert original.hex() not in str(error.value)
    assert replacement.hex() not in str(error.value)
    assert (tmp_path / "credential-hmac.key").read_bytes() == replacement
    assert _identity(database) == identity

    with pytest.raises(VerifierKeyError, match="does not match"):
        prepare_persistent_verifier_key(
            database,
            environ={"RAVENX_CREDENTIAL_VERIFIER_KEY": os.urandom(32).hex()},
            environment="production",
        )
    assert _identity(database) == identity
    assert (tmp_path / "credential-hmac.key").read_bytes() == replacement


def test_restored_database_with_a_different_key_is_refused(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    live_dir = tmp_path / "live"
    restored_dir = tmp_path / "restored"
    live_dir.mkdir()
    restored_dir.mkdir()
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_directory
        protect_private_directory(live_dir)
        protect_private_directory(restored_dir)
    live = live_dir / "raven_x.db"
    restored = restored_dir / "raven_x.db"
    _empty_database(live)
    _empty_database(restored)
    live_key = prepare_persistent_verifier_key(live, environ={}, environment="production")
    other = prepare_persistent_verifier_key(restored, environ={}, environment="production")
    assert live_key != other
    target_dir = tmp_path / "server"
    target_dir.mkdir()
    if os.name == "nt":
        protect_private_directory(target_dir)
    target = target_dir / "raven_x.db"
    target.write_bytes(restored.read_bytes())
    (target_dir / "credential-hmac.key").write_bytes(live_key)
    before = _identity(target)
    with pytest.raises(VerifierKeyError, match="does not match the database identity"):
        prepare_persistent_verifier_key(target, environ={}, environment="production")
    assert _identity(target) == before
    assert (target_dir / "credential-hmac.key").read_bytes() == live_key


def test_file_backed_development_database_keeps_one_verifier_key(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    service = EnrollmentService(object(), defer_verifier_key=True)
    bind_control_plane_verifier_key(_Manager(database), service, environment="development", environ={})
    first = (tmp_path / "credential-hmac.key").read_bytes()
    assert service._verifier_key == first
    restarted = EnrollmentService(object(), defer_verifier_key=True)
    bind_control_plane_verifier_key(
        _Manager(database), restarted, environment="development",
        environ={"RAVENX_VERIFIER_KEY_MODE": "ephemeral"})
    assert restarted._verifier_key == first
    assert (tmp_path / "credential-hmac.key").read_bytes() == first


def test_explicit_ephemeral_mode_is_in_memory_only(tmp_path):
    tmp_path = _safe_dir()
    service = EnrollmentService(object(), defer_verifier_key=True)
    memory = type("Manager", (), {"config": {"type": "sqlite", "sqlite_path": ":memory:"},
                                   "config_path": tmp_path / "unused.yaml"})()
    bind_control_plane_verifier_key(memory, service, environment="test",
                                    environ={"RAVENX_VERIFIER_KEY_MODE": "ephemeral"})
    assert service._verifier_bound
    assert not list(tmp_path.glob("credential-hmac.key"))
    with pytest.raises(VerifierKeyError, match="in-memory"):
        bind_control_plane_verifier_key(memory, EnrollmentService(object(), defer_verifier_key=True),
                                        environment="test", environ={})


def test_production_refuses_ephemeral_mode():
    with pytest.raises(VerifierKeyError, match="ephemeral"):
        prepare_persistent_verifier_key(
            Path("unused.db"),
            environ={"RAVENX_VERIFIER_KEY_MODE": "ephemeral"},
            environment="production",
        )


def test_unprotected_windows_key_is_not_left_behind(tmp_path):
    tmp_path = _safe_dir()
    if os.name != "nt":
        pytest.skip("Windows ACL failure is the case under test")
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    key_path = tmp_path / "credential-hmac.key"
    try:
        key = prepare_persistent_verifier_key(database, environ={}, environment="production")
    except VerifierKeyError as error:
        assert "could not be protected" in str(error)
        assert not key_path.exists()
        assert len(str(error)) < 200
    else:
        from backend.infrastructure.security.windows_files import _verify_acl
        _verify_acl(key_path, directory=False)
        assert key_path.read_bytes() == key


def test_short_or_interrupted_key_write_does_not_commit_an_identity(tmp_path, allow_unprotected_key, monkeypatch):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    real_write = os.write

    def interrupted(descriptor, data):
        payload = bytes(data)
        if len(payload) >= 32:
            real_write(descriptor, payload[:8])
            raise OSError("interrupted write")
        return real_write(descriptor, payload)

    monkeypatch.setattr(os, "write", interrupted)
    with pytest.raises(VerifierKeyError):
        prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert not (tmp_path / "credential-hmac.key").exists()
    assert _identity(database) is None


def test_failure_after_publish_does_not_delete_a_bound_key(tmp_path, allow_unprotected_key, monkeypatch):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    import backend.infrastructure.security.verifier_key as keys
    real_bind = keys._require_matching_identity
    armed = {"value": True}

    def bind_then_fail(database_path, key):
        real_bind(database_path, key)
        if armed["value"]:
            armed["value"] = False
            raise VerifierKeyError("injected after bind")

    monkeypatch.setattr(keys, "_require_matching_identity", bind_then_fail)
    with pytest.raises(VerifierKeyError, match="injected after bind"):
        prepare_persistent_verifier_key(database, environ={}, environment="production")
    key_path = tmp_path / "credential-hmac.key"
    assert key_path.is_file()
    stored = key_path.read_bytes()
    assert _identity(database) == verifier_key_id(stored)
    reloaded = prepare_persistent_verifier_key(database, environ={}, environment="production")
    assert reloaded == stored
    from backend.infrastructure.security import hash_bearer_secret, verify_secret
    verifier = hash_bearer_secret("C" * 43, key=reloaded, binding="cred-restart")
    assert verify_secret("C" * 43, verifier, key=reloaded, binding="cred-restart")


def test_file_backed_development_renewal_survives_restart(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    from datetime import datetime, timedelta, timezone
    from backend.core.database.database import DatabaseManager
    from backend.domain.endpoint import EndpointStatus, PlatformInfo
    from backend.domain.enrollment import CredentialId, EnrollmentRequest
    from backend.domain.organization import Organization, OrganizationId
    from backend.infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository
    from backend.infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository

    database = tmp_path / "raven_x.db"
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % database.as_posix(), encoding="utf-8")
    os.environ.pop("RAVENX_DATABASE_PATH", None)
    now = datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)
    manager = DatabaseManager(str(config))
    manager.create_tables()
    service = EnrollmentService(SQLAlchemyEnrollmentRepository(manager), defer_verifier_key=True,
                                organization_repository=SQLAlchemyOrganizationRepository(manager))
    bind_control_plane_verifier_key(manager, service, environment="development", environ={})
    organization = Organization(OrganizationId.new(), "Dev tenant", created_at=now, updated_at=now)
    SQLAlchemyOrganizationRepository(manager).add(organization)
    authorization, token = service.create_enrollment_authorization(now=now, organization_id=organization.organization_id)
    endpoint, credential, secret = service.accept_enrollment(
        authorization.enrollment_id, token.value, EnrollmentRequest("dev-host", PlatformInfo("Windows")), now=now)
    with manager.get_db() as session:
        from backend.core.database.models import EndpointRecord
        session.get(EndpointRecord, str(endpoint.endpoint_id)).status = EndpointStatus.ACTIVE.value
    successor_id, successor_secret = CredentialId.new(), "D" * 43
    service.renew_credential(
        endpoint.endpoint_id, secret.value, claimed_credential_id=credential.credential_id,
        successor_credential_id=successor_id, successor_secret=successor_secret, now=now + timedelta(days=20))
    key_path = tmp_path / "credential-hmac.key"
    original = key_path.read_bytes()
    manager.close()

    restarted_manager = DatabaseManager(str(config))
    restarted_manager.create_tables()
    restarted = EnrollmentService(SQLAlchemyEnrollmentRepository(restarted_manager), defer_verifier_key=True,
                                  organization_repository=SQLAlchemyOrganizationRepository(restarted_manager))
    bind_control_plane_verifier_key(restarted_manager, restarted, environment="development", environ={})
    assert key_path.read_bytes() == original
    assert restarted.verify_credential(
        endpoint.endpoint_id, secret.value, now=now + timedelta(days=20, minutes=1)
    ).credential_id == credential.credential_id
    assert restarted.verify_credential(
        endpoint.endpoint_id, successor_secret, now=now + timedelta(days=20, minutes=2)
    ).credential_id == successor_id
    restarted_manager.close()


def test_permissive_acl_and_reparse_parent_are_refused(tmp_path):
    tmp_path = _safe_dir()
    if os.name != "nt":
        pytest.skip("Windows custody checks are the case under test")
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    key_path = tmp_path / "credential-hmac.key"
    key_path.write_bytes(os.urandom(32))
    import win32security
    import ntsecuritycon
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    descriptor = win32security.GetFileSecurity(str(key_path), win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl() or win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everyone)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(str(key_path), win32security.DACL_SECURITY_INFORMATION, descriptor)
    from backend.infrastructure.security.verifier_key import verify_existing_verifier_key
    with pytest.raises(VerifierKeyError):
        verify_existing_verifier_key(key_path, production=False)
    link_parent = tmp_path / "linked"
    target = tmp_path / "real-parent"
    target.mkdir()
    created = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link_parent), str(target)],
                             capture_output=True, text=True)
    if created.returncode != 0:
        pytest.skip("this account cannot create a directory junction")
    linked_key = link_parent / "credential-hmac.key"
    linked_key.write_bytes(os.urandom(32))
    with pytest.raises(VerifierKeyError):
        verify_existing_verifier_key(linked_key, production=False)


def test_lock_file_with_a_permissive_acl_or_reparse_parent_is_refused(tmp_path):
    tmp_path = _safe_dir()
    if os.name != "nt":
        pytest.skip("Windows lock custody is the case under test")
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    lock = tmp_path / "credential-hmac.key.lock"
    lock.write_bytes(b"\x00")
    import ntsecuritycon
    import win32security
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    descriptor = win32security.GetFileSecurity(str(lock), win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl() or win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everyone)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(str(lock), win32security.DACL_SECURITY_INFORMATION, descriptor)
    before = lock.read_bytes()
    with pytest.raises(VerifierKeyError, match="lock"):
        prepare_persistent_verifier_key(database, environ={}, environment="development")
    assert lock.read_bytes() == before
    assert not (tmp_path / "credential-hmac.key").exists()

    parent = tmp_path / "everyone-parent"
    parent.mkdir()
    parent_db = parent / "raven_x.db"
    _empty_database(parent_db)
    parent_descriptor = win32security.GetFileSecurity(str(parent), win32security.DACL_SECURITY_INFORMATION)
    parent_dacl = parent_descriptor.GetSecurityDescriptorDacl() or win32security.ACL()
    parent_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, everyone)
    parent_descriptor.SetSecurityDescriptorDacl(True, parent_dacl, False)
    win32security.SetFileSecurity(str(parent), win32security.DACL_SECURITY_INFORMATION, parent_descriptor)
    with pytest.raises(VerifierKeyError, match="lock parent"):
        prepare_persistent_verifier_key(parent_db, environ={}, environment="development")
    assert not (parent / "credential-hmac.key.lock").exists()

    target = tmp_path / "real-lock-parent"
    target.mkdir()
    linked = tmp_path / "linked-lock-parent"
    created = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(linked), str(target)],
                             capture_output=True, text=True)
    if created.returncode != 0:
        return
    linked_db = linked / "raven_x.db"
    _empty_database(linked_db)
    with pytest.raises(VerifierKeyError, match="lock parent"):
        prepare_persistent_verifier_key(linked_db, environ={}, environment="development")


def test_two_threads_bootstrap_the_same_persistent_key(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    import threading
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    barrier = threading.Barrier(2)
    found = []
    errors = []

    def worker():
        try:
            barrier.wait()
            found.append(prepare_persistent_verifier_key(database, environ={}, environment="development"))
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(found) == 2 and found[0] == found[1]
    assert (tmp_path / "credential-hmac.key").read_bytes() == found[0]
    assert _identity(database) == verifier_key_id(found[0])


def test_two_processes_bootstrap_one_key_and_restart(tmp_path):
    tmp_path = _safe_dir()
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    gate = tmp_path / "start"
    script = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from backend.infrastructure.security.verifier_key import prepare_persistent_verifier_key, verifier_key_id\n"
        "database, gate = Path(sys.argv[1]), Path(sys.argv[2])\n"
        "for _ in range(600):\n"
        "    if gate.exists(): break\n"
        "    time.sleep(0.05)\n"
        "else: raise SystemExit('gate timed out')\n"
        "print(verifier_key_id(prepare_persistent_verifier_key(database, environ={}, environment='development')))\n"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    processes = [subprocess.Popen([sys.executable, "-B", "-c", script, str(database), str(gate)],
                                  cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
    try:
        gate.write_text("start", encoding="ascii")
        results = [process.communicate(timeout=45) for process in processes]
        for process, (output, errors) in zip(processes, results):
            assert process.returncode == 0, errors
            assert output.strip() == _identity(database)
        restart = subprocess.run([sys.executable, "-B", "-c", script, str(database), str(gate)],
                                 cwd=ROOT, env=env, capture_output=True, text=True, timeout=45)
        assert restart.returncode == 0, restart.stderr
        assert restart.stdout.strip() == _identity(database)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


def test_unsafe_lock_parent_owner_is_rejected_when_change_is_permitted(tmp_path):
    tmp_path = _safe_dir()
    if os.name != "nt":
        pytest.skip("Windows owner validation is the case under test")
    import win32security
    from backend.infrastructure.security.windows_files import protect_private_directory
    parent = tmp_path / "unsafe-owner"
    parent.mkdir()
    protect_private_directory(parent)
    database = parent / "raven_x.db"
    _empty_database(database)
    original = win32security.GetFileSecurity(str(parent), win32security.OWNER_SECURITY_INFORMATION)
    altered = win32security.GetFileSecurity(str(parent), win32security.OWNER_SECURITY_INFORMATION)
    altered.SetSecurityDescriptorOwner(win32security.ConvertStringSidToSid("S-1-5-32-545"), False)
    try:
        try:
            win32security.SetFileSecurity(str(parent), win32security.OWNER_SECURITY_INFORMATION, altered)
        except Exception:
            pytest.skip("this account cannot set a disposable directory to an untrusted owner")
        with pytest.raises(VerifierKeyError, match="lock parent"):
            prepare_persistent_verifier_key(database, environ={}, environment="development")
        assert not (parent / "credential-hmac.key.lock").exists()
    finally:
        win32security.SetFileSecurity(str(parent), win32security.OWNER_SECURITY_INFORMATION, original)


def test_untrusted_lock_parent_owner_is_rejected_before_creation(tmp_path, monkeypatch):
    tmp_path = _safe_dir()
    if os.name != "nt":
        pytest.skip("Windows owner validation is the case under test")
    import win32security
    import backend.infrastructure.security.windows_files as files
    parent = tmp_path / "untrusted-owner"
    parent.mkdir()
    files.protect_private_directory(parent)
    database = parent / "raven_x.db"
    _empty_database(database)
    real_descriptor = files._security_descriptor
    untrusted = win32security.ConvertStringSidToSid("S-1-5-32-545")

    class BadOwner:
        def __init__(self, descriptor):
            self.descriptor = descriptor

        def GetSecurityDescriptorOwner(self):
            return untrusted

        def GetSecurityDescriptorControl(self):
            return self.descriptor.GetSecurityDescriptorControl()

        def GetSecurityDescriptorDacl(self):
            return self.descriptor.GetSecurityDescriptorDacl()

    monkeypatch.setattr(files, "_security_descriptor",
                        lambda path: BadOwner(real_descriptor(path)) if Path(path) == parent else real_descriptor(path))
    with pytest.raises(VerifierKeyError, match="lock parent"):
        prepare_persistent_verifier_key(database, environ={}, environment="development")
    assert not (parent / "credential-hmac.key.lock").exists()


def test_lock_file_reparse_point_is_rejected_when_creation_is_permitted(tmp_path):
    tmp_path = _safe_dir()
    if os.name != "nt":
        pytest.skip("Windows reparse validation is the case under test")
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    target = tmp_path / "innocent-file"
    target.write_bytes(b"unchanged")
    lock = tmp_path / "credential-hmac.key.lock"
    try:
        lock.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create a file symlink")
    with pytest.raises(VerifierKeyError, match="lock"):
        prepare_persistent_verifier_key(database, environ={}, environment="development")
    assert target.read_bytes() == b"unchanged"
    assert lock.is_symlink()


def test_resolve_refuses_ephemeral_keys_for_file_backed_databases(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    from backend.infrastructure.security.verifier_key import resolve_verifier_key
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    for environment in ("development", "production"):
        with pytest.raises(VerifierKeyError, match="in-memory"):
            resolve_verifier_key(environ={
                "RAVENX_ENVIRONMENT": environment,
                "RAVENX_VERIFIER_KEY_MODE": "ephemeral",
                "RAVENX_DATABASE_PATH": str(database),
            })
    key = prepare_persistent_verifier_key(database, environ={}, environment="development")
    resolved = resolve_verifier_key(environ={"RAVENX_DATABASE_PATH": str(database), "RAVENX_ENVIRONMENT": "development"})
    again = resolve_verifier_key(environ={"RAVENX_DATABASE_PATH": str(database), "RAVENX_ENVIRONMENT": "development"})
    assert resolved == again == key
    assert resolve_verifier_key(environ={
        "RAVENX_DATABASE_PATH": str(database), "RAVENX_ENVIRONMENT": "production",
    }) == key
    with pytest.raises(VerifierKeyError, match="does not match"):
        resolve_verifier_key(environ={
            "RAVENX_DATABASE_PATH": str(database),
            "RAVENX_CREDENTIAL_VERIFIER_KEY": os.urandom(32).hex(),
        })
    assert resolve_verifier_key(environ={
        "RAVENX_DATABASE_PATH": str(database),
        "RAVENX_CREDENTIAL_VERIFIER_KEY": key.hex(),
    }) == key
    memory = resolve_verifier_key(environ={
        "RAVENX_ENVIRONMENT": "test", "RAVENX_VERIFIER_KEY_MODE": "ephemeral",
        "RAVENX_DATABASE_PATH": ":memory:",
    })
    assert memory != key
    with pytest.raises(VerifierKeyError, match="in-memory"):
        resolve_verifier_key(environ={
            "RAVENX_ENVIRONMENT": "production", "RAVENX_VERIFIER_KEY_MODE": "ephemeral",
            "RAVENX_DATABASE_PATH": ":memory:",
        })
    with pytest.raises(VerifierKeyError, match="ambiguous"):
        resolve_verifier_key(environ={"RAVENX_DATABASE_PATH": str(database)}, default_path=tmp_path / "other.key")
    with pytest.raises(VerifierKeyError, match="database identity"):
        resolve_verifier_key(environ={}, default_path=tmp_path / "credential-hmac.key")


def test_resolver_rejects_a_database_with_a_mismatched_key_identity(tmp_path, allow_unprotected_key):
    tmp_path = _safe_dir()
    from backend.infrastructure.security.verifier_key import resolve_verifier_key
    database = tmp_path / "raven_x.db"
    _empty_database(database)
    key = prepare_persistent_verifier_key(database, environ={}, environment="development")
    connection = sqlite3.connect(database)
    try:
        connection.execute("UPDATE ravenx_verifier_keys SET key_id = ? WHERE id = 1", ("0" * 64,))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(VerifierKeyError, match="does not match the database identity"):
        resolve_verifier_key(environ={"RAVENX_DATABASE_PATH": str(database)})
    assert (tmp_path / "credential-hmac.key").read_bytes() == key


def test_startup_fails_before_http_readiness_when_the_key_is_missing(tmp_path):
    tmp_path = _safe_dir()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env.pop("RAVENX_CREDENTIAL_VERIFIER_KEY", None)
    completed = subprocess.run(
        [sys.executable, "-c", _STARTUP, str(tmp_path)],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "STARTUP_REFUSED" in output
    assert "API READY" not in output
    assert "KEY CREATED" not in output
    assert "will not be regenerated" in output
    assert not (tmp_path / "credential-hmac.key").exists()


def test_lock_parent_substituted_after_open_does_not_publish_a_key(tmp_path):
    """Artificial same-user rename after the parent handle is open.

    The disposable directory's ancestors do not grant Users delete-child, so
    another account could not perform this rename. The planted key must stay
    unchanged and the renamed directory must not receive a key.
    """
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import shutil
    import backend.infrastructure.security.verifier_key as keys
    from backend.infrastructure.security.windows_files import protect_private_directory
    directory = _safe_dir()
    database = directory / "raven_x.db"
    _empty_database(database)
    moved = directory.with_name(directory.name + "-moved")
    trap = b"T" * 32
    swapped = {"done": False}

    def swap(stage, info):
        if stage != "after-parent-open" or swapped["done"]:
            return
        swapped["done"] = True
        directory.rename(moved)
        directory.mkdir()
        protect_private_directory(directory)
        (directory / "credential-hmac.key").write_bytes(trap)

    keys.lock_fault_hooks.append(swap)
    try:
        with pytest.raises(VerifierKeyError, match="substituted"):
            prepare_persistent_verifier_key(database, environ={}, environment="development")
        assert swapped["done"]
        assert (directory / "credential-hmac.key").read_bytes() == trap
        assert not (moved / "credential-hmac.key").exists()
    finally:
        keys.lock_fault_hooks.remove(swap)
        if moved.exists():
            shutil.rmtree(moved)


def test_lock_file_replaced_before_open_is_refused(tmp_path):
    """A permissive lock file planted after parent validation.

    The permissive DACL is a realistic unsafe configuration. Planting it from
    this process is an artificial hook, not a second user.
    """
    if os.name != "nt":
        pytest.skip("Windows lock ACLs are the case under test")
    import ntsecuritycon
    import win32security
    import backend.infrastructure.security.verifier_key as keys
    directory = _safe_dir()
    database = directory / "raven_x.db"
    _empty_database(database)
    canary = directory / "canary.bin"
    canary.write_bytes(b"unchanged")

    def plant(stage, info):
        if stage != "before-lock-open":
            return
        info.write_bytes(b"\x00")
        descriptor = win32security.GetFileSecurity(str(info), win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl() or win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS,
                                 win32security.ConvertStringSidToSid("S-1-1-0"))
        descriptor.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(str(info), win32security.DACL_SECURITY_INFORMATION, descriptor)

    keys.lock_fault_hooks.append(plant)
    try:
        with pytest.raises(VerifierKeyError, match="lock"):
            prepare_persistent_verifier_key(database, environ={}, environment="development")
    finally:
        keys.lock_fault_hooks.remove(plant)
    assert canary.read_bytes() == b"unchanged"
    assert not (directory / "credential-hmac.key").exists()


def _missing_file_error():
    import pywintypes
    return pywintypes.error(2, "CreateFile", "The system cannot find the file specified.")


def test_missing_parent_during_identity_check_raises_verifier_key_error(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows file-not-found normalization is the case under test")
    import pywintypes
    import backend.infrastructure.security.windows_files as files
    directory = _safe_dir()
    database = directory / "raven_x.db"
    _empty_database(database)
    unrelated = directory / "unrelated.txt"
    unrelated.write_bytes(b"keep")

    def missing(_path):
        raise _missing_file_error()

    monkeypatch.setattr(files, "path_file_identity", missing)
    with pytest.raises(VerifierKeyError, match="substituted") as caught:
        prepare_persistent_verifier_key(database, environ={}, environment="development")
    assert isinstance(caught.value.__cause__, pywintypes.error)
    assert caught.value.__cause__.winerror == 2
    assert not (directory / "credential-hmac.key").exists()
    assert _identity(database) is None
    assert unrelated.read_bytes() == b"keep"


def test_missing_parent_during_initial_open_raises_verifier_key_error(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows file-not-found normalization is the case under test")
    import pywintypes
    import backend.infrastructure.security.windows_files as files
    directory = _safe_dir()
    database = directory / "raven_x.db"
    _empty_database(database)

    def missing(_path, share_delete=True):
        raise _missing_file_error()

    monkeypatch.setattr(files, "open_bound_directory", missing)
    with pytest.raises(VerifierKeyError, match="not usable") as caught:
        prepare_persistent_verifier_key(database, environ={}, environment="development")
    assert isinstance(caught.value.__cause__, pywintypes.error)
    assert caught.value.__cause__.winerror == 2
    assert not (directory / "credential-hmac.key").exists()
    assert _identity(database) is None


def test_two_initializers_do_not_publish_different_keys_if_the_parent_is_renamed(tmp_path):
    """Artificial same-user rename while two initializers run."""
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import shutil
    import threading
    import backend.infrastructure.security.verifier_key as keys
    from backend.infrastructure.security.windows_files import protect_private_directory
    directory = _safe_dir()
    database = directory / "raven_x.db"
    _empty_database(database)
    moved = directory.with_name(directory.name + "-moved")
    state = {"swapped": False}

    def swap(stage, info):
        if stage != "after-parent-open" or state["swapped"]:
            return
        state["swapped"] = True
        try:
            directory.rename(moved)
            directory.mkdir()
            protect_private_directory(directory)
        except Exception:
            return

    keys.lock_fault_hooks.append(swap)
    errors = []
    try:
        def worker():
            try:
                prepare_persistent_verifier_key(database, environ={}, environment="development")
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        found = []
        for place in (directory, moved):
            key_path = place / "credential-hmac.key"
            if key_path.is_file():
                found.append(key_path.read_bytes())
        assert state["swapped"]
        assert len(set(found)) <= 1
        assert all(isinstance(error, VerifierKeyError) for error in errors), [type(error).__name__ for error in errors]
    finally:
        keys.lock_fault_hooks.remove(swap)
        if moved.exists():
            shutil.rmtree(moved)


def test_killed_lock_owner_is_followed_by_a_protected_bootstrap(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows lock release on process exit is the case under test")
    directory = _safe_dir()
    database = directory / "raven_x.db"
    _empty_database(database)
    lock = directory / "credential-hmac.key.lock"
    script = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from backend.infrastructure.security.verifier_key import _acquire_key_lock\n"
        "_acquire_key_lock(Path(sys.argv[1]))\n"
        "print('HELD', flush=True)\n"
        "time.sleep(60)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1"}
    process = subprocess.Popen([sys.executable, "-B", "-c", script, str(lock)],
                               cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = process.stdout.readline()
        assert "HELD" in line, process.stderr.read()
        process.kill()
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    first = prepare_persistent_verifier_key(database, environ={}, environment="development")
    second = prepare_persistent_verifier_key(database, environ={}, environment="development")
    assert first == second
    assert _identity(database) == verifier_key_id(first)
    from backend.infrastructure.security.secret_verifiers import hash_token, verify_secret
    legacy = hash_token("legacy-token-value")
    assert legacy.startswith("token-sha256-v1$")
    assert verify_secret("legacy-token-value", legacy) is True
