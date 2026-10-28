"""Rollback metadata, read-only checks, and restore eligibility."""

import asyncio
import hashlib
import os
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import text

from backend.application.ops.rollback import (
    RestoreCredential,
    RestoreLineage,
    evaluate_database_restore,
    evaluate_server_rollback,
    inspect_existing_sqlite_readonly,
)
from backend.application.ops.schema import SchemaVersionError, schema_version
from backend.cli import main
from backend.core.database.database import DatabaseManager


KEY = "ab" * 32
_HMAC_SQL = (
    "INSERT INTO endpoint_credentials (credential_id, endpoint_id, credential_kind, verifier, status, "
    "issued_at, credential_metadata) VALUES ('cred-hmac', 'endpoint-1', 'opaque', "
    "'token-hmac-v2$salt$mac', 'active', '2026-10-01 00:00:00', '{}')"
)


@pytest.fixture(autouse=True)
def isolated_rollback_snapshot_root(tmp_path):
    # Keep disposable snapshots under the user profile, whose ancestors do not
    # grant untrusted delete rights. A directory under the process temp folder
    # is intentionally not used: that folder allows other principals to rename it.
    from uuid import uuid4
    previous = os.environ.get("LOCALAPPDATA")
    base = Path(previous) / "RAVEN-X" / "ws01-rollback-tests" / uuid4().hex
    base.mkdir(parents=True)
    os.environ["LOCALAPPDATA"] = str(base)
    try:
        yield base
    finally:
        if previous is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = previous


def _manager(tmp_path, monkeypatch, name="raven.db"):
    monkeypatch.delenv("RAVENX_DATABASE_PATH", raising=False)
    database = tmp_path / name
    config = tmp_path / (name + ".yaml")
    config.write_text(
        "database:\n  type: sqlite\n  sqlite_path: '%s'\n" % database.as_posix(),
        encoding="utf-8",
    )
    return DatabaseManager(config), database


def _strip_version_and_add_hmac(engine):
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM ravenx_schema_versions"))
        connection.execute(text(_HMAC_SQL))


def _snapshot(directory: Path):
    files = {}
    if not directory.exists():
        return files
    for path in directory.rglob("*"):
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def _credential(credential_id, status="active", **overrides):
    values = {
        "endpoint_id": "endpoint-1",
        "organization_id": "org-1",
        "verifier_key_id": KEY,
        "issued_at": "2026-10-01T00:00:00",
        "revoked_at": "2026-10-02T00:00:00" if status == "revoked" else None,
    }
    values.update(overrides)
    return RestoreCredential(credential_id, status, **values)


def test_sync_startup_empty_version_with_hmac_is_not_schema_1(tmp_path, monkeypatch):
    manager, _database = _manager(tmp_path, monkeypatch)
    manager.create_tables()
    _strip_version_and_add_hmac(manager.engine)
    with pytest.raises(SchemaVersionError):
        schema_version(manager.engine)
    decision = evaluate_server_rollback(engine=manager.engine, target_schema=1)
    assert not decision.allowed
    assert decision.code == "ambiguous_schema"
    manager.close()


def test_async_startup_empty_version_with_hmac_is_not_schema_1(tmp_path, monkeypatch):
    manager, _database = _manager(tmp_path, monkeypatch, "async.db")

    async def startup():
        await manager.create_tables_async()

    asyncio.run(startup())
    _strip_version_and_add_hmac(manager.engine)
    with pytest.raises(SchemaVersionError):
        schema_version(manager.engine)
    decision = evaluate_server_rollback(engine=manager.engine, target_schema=1)
    assert not decision.allowed
    assert decision.code == "ambiguous_schema"
    manager.close()
    asyncio.run(manager.close_async())


def test_rollback_check_is_read_only_and_sees_committed_wal(tmp_path, monkeypatch):
    import subprocess
    import sys
    manager, database = _manager(tmp_path, monkeypatch, "wal.db")
    manager.create_tables()
    manager.close()
    script = (
        "import os, sqlite3, sys\n"
        "connection = sqlite3.connect(sys.argv[1])\n"
        "connection.execute('PRAGMA journal_mode=WAL')\n"
        "connection.execute('PRAGMA synchronous=FULL')\n"
        "connection.execute(\"\"\"%s\"\"\")\n"
        "connection.commit()\n"
        "os._exit(0)\n"
    ) % _HMAC_SQL
    subprocess.run([sys.executable, "-c", script, str(database)], check=True)
    wal = Path(str(database) + "-wal")
    shm = Path(str(database) + "-shm")
    assert wal.is_file() and wal.stat().st_size > 0
    if shm.is_file():
        with_shm = _snapshot(database.parent)
        with inspect_existing_sqlite_readonly(database) as engine:
            seen = evaluate_server_rollback(engine=engine, target_schema=1)
        assert seen.code == "incompatible_hmac_successors"
        assert _snapshot(database.parent) == with_shm
        shm.unlink()
    before = _snapshot(database.parent)
    with inspect_existing_sqlite_readonly(database) as engine:
        decision = evaluate_server_rollback(engine=engine, target_schema=1)
    assert not decision.allowed
    assert decision.code == "incompatible_hmac_successors"
    assert not shm.exists()
    assert _snapshot(database.parent) == before


def test_rollback_check_does_not_create_or_mutate_a_database(tmp_path, monkeypatch):
    previous_database = os.environ.get("RAVENX_DATABASE_PATH")
    previous_legacy = os.environ.get("RAVENX_ENABLE_LEGACY_ROUTES")
    os.environ.pop("RAVENX_DATABASE_PATH", None)
    try:
        missing = tmp_path / "missing-data"
        assert main(["rollback-check", "--data-dir", str(missing)]) == 3
        assert not missing.exists()

        manager, database = _manager(tmp_path, monkeypatch, "existing.db")
        manager.create_tables()
        _strip_version_and_add_hmac(manager.engine)
        with manager.engine.begin() as connection:
            connection.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        manager.close()
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "raven_x.db").write_bytes(database.read_bytes())
        before = _snapshot(data_dir)
        assert main(["rollback-check", "--data-dir", str(data_dir)]) == 3
        assert _snapshot(data_dir) == before
    finally:
        if previous_database is None:
            os.environ.pop("RAVENX_DATABASE_PATH", None)
        else:
            os.environ["RAVENX_DATABASE_PATH"] = previous_database
        if previous_legacy is None:
            os.environ.pop("RAVENX_ENABLE_LEGACY_ROUTES", None)
        else:
            os.environ["RAVENX_ENABLE_LEGACY_ROUTES"] = previous_legacy


def _owned_snapshots(rollback):
    root = rollback.rollback_snapshot_root()
    return list(root.glob("ravenx-rollback-%s-*" % os.getpid()))


def test_snapshot_copy_verification_engine_and_cleanup_failures_do_not_leave_a_copy(tmp_path, monkeypatch):
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    wal = Path(str(database) + "-wal")
    wal.write_bytes(b"source-wal")
    import backend.application.ops.rollback as rollback
    rollback.rollback_snapshot_root()
    before = (database.read_bytes(), wal.read_bytes(), list(tmp_path.iterdir()))

    def fail_database_copy(source, destination):
        if not str(source).endswith("-wal"):
            destination.write_bytes(b"partial database copy")
            raise OSError("db copy failed")
        raise AssertionError("wal copy should not run")

    monkeypatch.setattr(rollback, "_copy_verified", fail_database_copy)
    with pytest.raises(rollback.RollbackInspectionError):
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    assert _owned_snapshots(rollback) == []

    def fail_wal_copy(source, destination):
        if str(source).endswith("-wal"):
            destination.write_bytes(b"partial WAL copy")
            raise OSError("wal copy failed")
        rollback.shutil.copyfile(source, destination)
        if not rollback._snapshot_bytes_match(source, destination):
            raise rollback.RollbackInspectionError("mismatch")

    monkeypatch.setattr(rollback, "_copy_verified", fail_wal_copy)
    with pytest.raises(rollback.RollbackInspectionError):
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    assert _owned_snapshots(rollback) == []

    monkeypatch.setattr(rollback, "_snapshot_bytes_match", lambda source, destination: False)
    with pytest.raises(rollback.RollbackInspectionError):
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    assert _owned_snapshots(rollback) == []
    monkeypatch.undo()

    def fail_engine(_snapshot, _name):
        raise OSError("engine")

    monkeypatch.setattr(rollback, "_open_snapshot_engine", fail_engine)
    with pytest.raises(rollback.RollbackInspectionError):
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    assert _owned_snapshots(rollback) == []
    monkeypatch.undo()

    with pytest.raises(RuntimeError, match="inspection failed"):
        with rollback.inspect_existing_sqlite_readonly(database):
            raise RuntimeError("inspection failed")
    assert _owned_snapshots(rollback) == []
    assert (database.read_bytes(), wal.read_bytes(), list(tmp_path.iterdir())) == before


def test_snapshot_cleanup_failure_is_an_inspection_error_and_names_the_residue(tmp_path, monkeypatch):
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    before = database.read_bytes()
    import backend.application.ops.rollback as rollback
    real_destroy = rollback._destroy_owned_snapshot
    residue = {}

    def fail_cleanup(snapshot):
        residue["name"] = snapshot.name
        raise rollback.RollbackInspectionError("cleanup failed", residue=snapshot.name)

    monkeypatch.setattr(rollback, "_destroy_owned_snapshot", fail_cleanup)
    with pytest.raises(rollback.RollbackInspectionError, match="cleanup failed") as caught:
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    assert caught.value.residue == residue["name"]
    leftover = rollback.rollback_snapshot_root() / residue["name"]
    assert leftover.is_dir()
    monkeypatch.undo()
    real_destroy(leftover)
    assert not leftover.exists()
    assert database.read_bytes() == before


def test_data_file_removal_failure_keeps_the_ownership_marker(tmp_path, monkeypatch):
    import backend.application.ops.rollback as rollback
    import backend.infrastructure.security.windows_files as files
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    real_delete = files.BoundDirectory.delete_named

    def fail_data_delete(self, name, expected_identity=None):
        if name == database.name:
            raise files.WindowsFileSecurityError("injected removal failure")
        return real_delete(self, name, expected_identity=expected_identity)

    with monkeypatch.context() as failure:
        failure.setattr(files.BoundDirectory, "delete_named", fail_data_delete)
        with pytest.raises(rollback.RollbackInspectionError, match="could not be removed") as caught:
            with rollback.inspect_existing_sqlite_readonly(database):
                pass
        residue = caught.value.residue
        assert residue
        snapshot = rollback.rollback_snapshot_root() / residue
        assert (snapshot / rollback._MARKER_NAME).is_file()
        assert (snapshot / database.name).is_file()
    rollback._destroy_owned_snapshot(rollback.rollback_snapshot_root() / residue)
    assert _owned_snapshots(rollback) == []
    assert database.read_bytes() == b"source-database"


def test_rollback_cleanup_failure_exits_4(tmp_path, monkeypatch):
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    import backend.application.ops.rollback as rollback

    def fail_cleanup(snapshot):
        raise rollback.RollbackInspectionError("cleanup failed", residue=snapshot.name)

    monkeypatch.setattr(rollback, "_destroy_owned_snapshot", fail_cleanup)
    code = main(["rollback-check", "--data-dir", str(tmp_path)])
    assert code == 4
    monkeypatch.undo()
    for child in rollback.rollback_snapshot_root().glob("ravenx-rollback-%s-*" % os.getpid()):
        rollback._destroy_owned_snapshot(child)


def test_terminated_process_snapshot_is_recovered_without_deleting_live_owners(tmp_path):
    import subprocess
    import sys
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    import backend.application.ops.rollback as rollback
    script = (
        "import os, sys\n"
        "from pathlib import Path\n"
        "from backend.application.ops.rollback import _snapshot_for_inspection\n"
        "_snapshot_for_inspection(Path(sys.argv[1]))\n"
        "os._exit(0)\n"
    )
    completed = subprocess.run([sys.executable, "-c", script, str(database)], cwd=str(Path(__file__).resolve().parents[2]),
                               env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])},
                               capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    names = [path.name for path in rollback.rollback_snapshot_root().glob("ravenx-rollback-*")]
    recovered = rollback.recover_stale_rollback_snapshots()
    assert recovered == ()
    assert database.read_bytes() == b"source-database"
    live = None
    with rollback.inspect_existing_sqlite_readonly(database):
        live = _owned_snapshots(rollback)
        assert live
        assert rollback.recover_stale_rollback_snapshots() == ()
        assert live[0].exists()
    assert not live[0].exists()


def test_snapshot_directory_is_not_world_writable(tmp_path):
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import parent_has_everyone_write
    with rollback.inspect_existing_sqlite_readonly(database):
        root = rollback.rollback_snapshot_root()
        assert parent_has_everyone_write(root) is False
        owned = _owned_snapshots(rollback)
        assert owned and parent_has_everyone_write(owned[0]) is False


def test_dispose_error_still_removes_snapshot(tmp_path, monkeypatch):
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    import backend.application.ops.rollback as rollback

    class FailingEngine:
        def dispose(self):
            raise OSError("injected disposal failure")

    monkeypatch.setattr(rollback, "_open_snapshot_engine", lambda *_args: FailingEngine())
    with pytest.raises(rollback.RollbackInspectionError, match="could not be disposed"):
        with rollback.inspect_existing_sqlite_readonly(database):
            assert _owned_snapshots(rollback)
    assert _owned_snapshots(rollback) == []
    assert database.read_bytes() == b"source-database"


def test_invalid_snapshot_marker_is_reported_and_never_removed(tmp_path):
    import backend.application.ops.rollback as rollback
    root = rollback.rollback_snapshot_root()
    snapshot = root / ("ravenx-rollback-999999-" + "a" * 32)
    snapshot.mkdir()
    rollback._restrict_snapshot_directory(snapshot)
    (snapshot / rollback._MARKER_NAME).write_text("[]", encoding="utf-8")
    assert rollback.recover_stale_rollback_snapshots() == (snapshot.name,)
    assert snapshot.exists()


def test_snapshot_files_have_verified_private_custody(tmp_path):
    import backend.application.ops.rollback as rollback
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"source-database")
    Path(str(database) + "-wal").write_bytes(b"committed-wal")
    with rollback.inspect_existing_sqlite_readonly(database):
        snapshot = _owned_snapshots(rollback)[0]
        if os.name == "nt":
            from backend.infrastructure.security.windows_files import verify_private_directory, verify_verifier_key_custody
            verify_private_directory(snapshot)
            for child in snapshot.iterdir():
                verify_verifier_key_custody(child, production=False)
        else:
            assert snapshot.stat().st_mode & 0o077 == 0
            assert all(child.stat().st_mode & 0o077 == 0 for child in snapshot.iterdir())
    assert _owned_snapshots(rollback) == []


def test_unsafe_snapshot_root_is_refused_before_recovery(tmp_path):
    import backend.application.ops.rollback as rollback
    root = rollback._snapshot_root_path()
    root.mkdir(parents=True)
    if os.name == "nt":
        import ntsecuritycon
        import win32security
        descriptor = win32security.GetFileSecurity(str(root), win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl() or win32security.ACL()
        everyone = win32security.ConvertStringSidToSid("S-1-1-0")
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, everyone)
        descriptor.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(str(root), win32security.DACL_SECURITY_INFORMATION, descriptor)
    else:
        root.chmod(0o777)
    child = root / ("ravenx-rollback-999999-" + "b" * 32)
    child.mkdir()
    with pytest.raises(rollback.RollbackInspectionError, match="not private"):
        rollback.recover_stale_rollback_snapshots()
    assert child.exists()


def test_rollback_inspection_error_uses_a_distinct_exit_code(tmp_path, monkeypatch):
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"not-a-database-but-present")
    import backend.application.ops.rollback as rollback
    def explode(_path):
        raise rollback.RollbackInspectionError("snapshot failed")
    monkeypatch.setattr(rollback, "inspect_existing_sqlite_readonly", explode)
    assert main(["rollback-check", "--data-dir", str(tmp_path)]) == 4


def test_restore_refuses_pre_revocation_and_status_differences_without_writing(tmp_path):
    database = tmp_path / "untouched.db"
    database.write_bytes(b"sqlite-sentinel")
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    live = _credential("cred-1", "revoked")
    backup = _credential("cred-1", "active", revoked_at=None)
    refused = evaluate_database_restore(
        live_credentials=(live,), backup_credentials=(backup,),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY,
        revocation_event_ids=("cred-1",), history_complete=True,
    )
    assert not refused.allowed
    assert refused.code == "credential_status_mismatch"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == digest

    after = evaluate_database_restore(
        live_credentials=(_credential("cred-1", "revoked"),),
        backup_credentials=(_credential("cred-1", "revoked"),),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY,
        revocation_event_ids=("cred-1",), history_complete=True,
    )
    assert after.allowed
    assert after.code == "restore_eligible"
    assert "does not restore" in after.message


def test_restore_refuses_newer_credentials_key_mismatch_lineage_and_missing_history():
    live = _credential("cred-new", "active", revoked_at=None)
    older = _credential("cred-old", "active", revoked_at=None)
    newer = evaluate_database_restore(
        live_credentials=(live, older), backup_credentials=(older,),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY, history_complete=True,
    )
    assert not newer.allowed and newer.code == "backup_missing_live_credentials"

    mismatch = evaluate_database_restore(
        live_credentials=(older,), backup_credentials=(older,),
        live_verifier_key_id=KEY, backup_verifier_key_id="cd" * 32, history_complete=True,
    )
    assert not mismatch.allowed and mismatch.code == "verifier_key_mismatch"

    pending = RestoreLineage("cred-old", "cred-next", confirmed=False, endpoint_id="endpoint-1", organization_id="org-1")
    lineage = evaluate_database_restore(
        live_credentials=(older,), backup_credentials=(older,),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY,
        live_lineages=(pending,), history_complete=True,
    )
    assert not lineage.allowed and lineage.code == "pending_lineage_mismatch"

    missing = evaluate_database_restore(
        live_credentials=(_credential("cred-1", "revoked"),),
        backup_credentials=(_credential("cred-1", "revoked"),),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY, history_complete=True,
    )
    assert not missing.allowed and missing.code == "missing_revocation_history"

    tenant = evaluate_database_restore(
        live_credentials=(older,),
        backup_credentials=(_credential("cred-old", "active", organization_id="other-org", revoked_at=None),),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY, history_complete=True,
    )
    assert not tenant.allowed and tenant.code == "tenant_or_endpoint_mismatch"


def test_restore_refuses_a_backup_that_drops_a_confirmed_lineage():
    credential = _credential("cred-old", "active", revoked_at=None)
    successor = _credential("cred-next", "active", revoked_at=None)
    confirmed = RestoreLineage("cred-old", "cred-next", confirmed=True, endpoint_id="endpoint-1",
                               organization_id="org-1")
    altered = RestoreLineage("cred-old", "cred-other", confirmed=True, endpoint_id="endpoint-1",
                             organization_id="org-1")
    missing = evaluate_database_restore(
        live_credentials=(credential, successor), backup_credentials=(credential, successor),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY,
        live_lineages=(confirmed,), backup_lineages=(), history_complete=True,
    )
    assert not missing.allowed and missing.code == "confirmed_lineage_mismatch"
    changed = evaluate_database_restore(
        live_credentials=(credential, successor), backup_credentials=(credential, successor),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY,
        live_lineages=(confirmed,), backup_lineages=(altered,), history_complete=True,
    )
    assert not changed.allowed and changed.code == "confirmed_lineage_mismatch"
    present = evaluate_database_restore(
        live_credentials=(credential, successor), backup_credentials=(credential, successor),
        live_verifier_key_id=KEY, backup_verifier_key_id=KEY,
        live_lineages=(confirmed,), backup_lineages=(confirmed,), history_complete=True,
    )
    assert present.allowed


def _grant_delete_child(directory: Path, sid: str) -> None:
    import ntsecuritycon
    import win32security
    descriptor = win32security.GetFileSecurity(str(directory), win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_DELETE_CHILD, win32security.ConvertStringSidToSid(sid))
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(str(directory), win32security.DACL_SECURITY_INFORMATION, descriptor)


def _file_sids(path: Path) -> set[str]:
    import win32security
    descriptor = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl()
    return {win32security.ConvertSidToStringSid(dacl.GetAce(index)[2]) for index in range(dacl.GetAceCount())}


def test_snapshot_root_substituted_after_open_does_not_receive_database_bytes(tmp_path):
    """Artificial same-user rename after the root handle is open.

    The profile ancestors do not grant an untrusted principal delete-child, so
    this is not a demonstrated cross-user attack. The root is opened with
    delete sharing so concurrent inspections can open it, and the copy must
    follow the handle rather than the replaced path.
    """
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import shutil
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import protect_private_directory
    database = tmp_path / "raven_x.db"
    marker = b"UNIQUE-SNAPSHOT-BYTES-round7-root"
    database.write_bytes(marker)
    root = rollback.rollback_snapshot_root()
    moved = root.with_name(root.name + "-moved")
    seen = set()

    def swap(stage, info):
        if stage in seen:
            return
        if stage == "after-root-open":
            seen.add(stage)
            root.rename(moved)
            root.mkdir()
            protect_private_directory(root)
            (root / "canary.bin").write_bytes(b"do-not-delete")
        elif stage == "after-child-create":
            seen.add(stage)
            info.mkdir()
            (info / "planted.bin").write_bytes(b"foreign-directory")

    rollback.snapshot_fault_hooks.append(swap)
    try:
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
        assert (root / "canary.bin").read_bytes() == b"do-not-delete"
        planted = next(root.rglob("planted.bin"))
        assert planted.read_bytes() == b"foreign-directory"
        assert not any(path.is_file() and path.read_bytes() == marker for path in root.rglob("*"))
        assert not any(path.is_file() and path.read_bytes() == marker for path in moved.rglob("*"))
        assert database.read_bytes() == marker
    finally:
        rollback.snapshot_fault_hooks.remove(swap)
        if moved.exists():
            shutil.rmtree(moved)


def test_snapshot_child_cannot_be_replaced_before_the_database_copy(tmp_path):
    """Artificial same-user rename. The child handle does not share delete."""
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import backend.application.ops.rollback as rollback
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"child-substitution-source")
    outcome = {}

    def attempt(stage, info):
        if stage != "before-db-copy":
            return
        try:
            info.parent.rename(info.parent.with_name(info.parent.name + "-swapped"))
        except OSError as error:
            outcome["winerror"] = getattr(error, "winerror", None)
        else:
            outcome["renamed"] = True

    rollback.snapshot_fault_hooks.append(attempt)
    try:
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    finally:
        rollback.snapshot_fault_hooks.remove(attempt)
    assert outcome.get("renamed") is not True
    assert outcome.get("winerror") == 32
    assert database.read_bytes() == b"child-substitution-source"
    assert _owned_snapshots(rollback) == []


def test_snapshot_child_cannot_be_replaced_before_the_wal_copy(tmp_path):
    """Artificial same-user rename while the snapshot directory handle is open."""
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import backend.application.ops.rollback as rollback
    database = tmp_path / "raven_x.db"
    wal = Path(str(database) + "-wal")
    database.write_bytes(b"wal-substitution-source")
    wal.write_bytes(b"wal-substitution-frames")
    outcome = {}

    def attempt(stage, info):
        if stage != "before-wal-copy":
            return
        try:
            info.parent.rename(info.parent.with_name(info.parent.name + "-swapped"))
        except OSError as error:
            outcome["winerror"] = getattr(error, "winerror", None)
        else:
            outcome["renamed"] = True

    rollback.snapshot_fault_hooks.append(attempt)
    try:
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
    finally:
        rollback.snapshot_fault_hooks.remove(attempt)
    assert outcome.get("renamed") is not True
    assert outcome.get("winerror") == 32
    assert database.read_bytes() == b"wal-substitution-source"
    assert wal.read_bytes() == b"wal-substitution-frames"
    assert _owned_snapshots(rollback) == []


def test_untrusted_delete_child_on_an_ancestor_refuses_before_copy(tmp_path):
    """Realistic DACL: Users has FILE_DELETE_CHILD on an ancestor.

    The test account adds that ACE. A second logged-on user is not launched.
    """
    if os.name != "nt":
        pytest.skip("Windows ACL ancestry is the case under test")
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import protect_private_directory
    ancestor = Path(os.environ["LOCALAPPDATA"]) / "unsafe-ancestor"
    ancestor.mkdir()
    protect_private_directory(ancestor)
    _grant_delete_child(ancestor, "S-1-5-32-545")
    database = tmp_path / "raven_x.db"
    marker = b"must-not-be-copied-to-an-unsafe-ancestor"
    database.write_bytes(marker)
    previous = os.environ["LOCALAPPDATA"]
    os.environ["LOCALAPPDATA"] = str(ancestor)
    try:
        with pytest.raises(rollback.RollbackInspectionError, match="not trusted"):
            with rollback.inspect_existing_sqlite_readonly(database):
                pass
        assert not any(path.is_file() and path.read_bytes() == marker for path in ancestor.rglob("*"))
        assert database.read_bytes() == marker
    finally:
        os.environ["LOCALAPPDATA"] = previous


def test_snapshot_destination_does_not_inherit_a_permissive_acl(tmp_path):
    """The parent is given an inheritable Everyone ACE before the copy.

    That ACE is a realistic permissive configuration. The file must be born
    with the private access list rather than copied and hardened afterward.
    """
    if os.name != "nt":
        pytest.skip("Windows ACL inheritance is the case under test")
    import ntsecuritycon
    import win32security
    import backend.application.ops.rollback as rollback
    database = tmp_path / "raven_x.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample (id INTEGER)")
    connection.commit()
    connection.close()
    before = database.read_bytes()

    def widen(stage, info):
        if stage != "after-child-create":
            return
        descriptor = win32security.GetFileSecurity(str(info), win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION,
            win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE,
            ntsecuritycon.FILE_ALL_ACCESS, win32security.ConvertStringSidToSid("S-1-1-0"))
        descriptor.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(str(info), win32security.DACL_SECURITY_INFORMATION, descriptor)

    rollback.snapshot_fault_hooks.append(widen)
    copied = None
    try:
        with pytest.raises(rollback.RollbackInspectionError, match="not private"):
            with rollback.inspect_existing_sqlite_readonly(database):
                snapshot = _owned_snapshots(rollback)[0]
                copied = snapshot / database.name
                assert _file_sids(copied).isdisjoint({"S-1-1-0", "S-1-5-32-545", "S-1-5-11"})
        assert copied is not None and copied.is_file()
        assert _file_sids(copied).isdisjoint({"S-1-1-0", "S-1-5-32-545", "S-1-5-11"})
    finally:
        rollback.snapshot_fault_hooks.remove(widen)
        if copied is not None and copied.parent.exists():
            from backend.infrastructure.security.windows_files import protect_private_directory
            protect_private_directory(copied.parent)
            import backend.application.ops.rollback as rollback_module
            rollback_module._destroy_owned_snapshot(copied.parent)
    assert database.read_bytes() == before
    assert _owned_snapshots(rollback) == []


def test_reparse_snapshot_root_is_refused_before_copy(tmp_path):
    """A junction created by this account. Not a cross-user attack."""
    if os.name != "nt":
        pytest.skip("Windows reparse points are the case under test")
    import subprocess
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import protect_private_directory
    base = Path(os.environ["LOCALAPPDATA"])
    target = base / "reparse-target"
    target.mkdir()
    protect_private_directory(target)
    app = base / "reparse-app"
    link_parent = app / "RAVEN-X"
    link_parent.mkdir(parents=True)
    junction = link_parent / "rollback-snapshots"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                             capture_output=True, text=True)
    if created.returncode != 0:
        pytest.skip("this account cannot create a directory junction")
    database = tmp_path / "raven_x.db"
    marker = b"must-not-follow-a-reparse-point"
    database.write_bytes(marker)
    previous = os.environ["LOCALAPPDATA"]
    os.environ["LOCALAPPDATA"] = str(app)
    try:
        with pytest.raises(rollback.RollbackInspectionError, match="reparse|ancestry|not private"):
            with rollback.inspect_existing_sqlite_readonly(database):
                pass
        assert not any(path.is_file() and path.read_bytes() == marker for path in target.rglob("*"))
        assert database.read_bytes() == marker
    finally:
        os.environ["LOCALAPPDATA"] = previous


def test_foreign_snapshot_marker_and_unrelated_directory_are_not_removed(tmp_path):
    import backend.application.ops.rollback as rollback
    root = rollback.rollback_snapshot_root()
    unrelated = root / "not-a-snapshot"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_bytes(b"keep-unrelated")
    foreign = root / ("ravenx-rollback-424242-" + "ab" * 16)
    foreign.mkdir()
    rollback._restrict_snapshot_directory(foreign)
    (foreign / rollback._MARKER_NAME).write_text('{"purpose":"someone-else"}', encoding="utf-8")
    (foreign / "keep.txt").write_bytes(b"keep-foreign")
    residues = rollback.recover_stale_rollback_snapshots()
    assert foreign.name in residues
    assert (unrelated / "keep.txt").read_bytes() == b"keep-unrelated"
    assert (foreign / "keep.txt").read_bytes() == b"keep-foreign"
    assert foreign.is_dir()


def test_concurrent_snapshot_inspections_share_a_protected_root(tmp_path):
    import threading
    import backend.application.ops.rollback as rollback
    database = tmp_path / "raven_x.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample (id INTEGER)")
    connection.execute("INSERT INTO sample (id) VALUES (1)")
    connection.commit()
    connection.close()
    before = database.read_bytes()
    barrier = threading.Barrier(2)
    errors = []

    def inspect():
        try:
            barrier.wait(timeout=10)
            with rollback.inspect_existing_sqlite_readonly(database) as engine:
                with engine.connect() as opened:
                    assert opened.execute(text("SELECT id FROM sample")).scalar() == 1
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=inspect) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert database.read_bytes() == before
    assert _owned_snapshots(rollback) == []


def test_cleanup_cannot_delete_a_directory_substituted_after_the_identity_check(tmp_path):
    """The held directory handle is the cleanup object.

    Replacing the pathname while that handle is open is a same-user attempt.
    It must not let cleanup delete a foreign directory and report success.
    """
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import protect_private_directory
    database = tmp_path / "raven_x.db"
    source = b"cleanup-race-source"
    database.write_bytes(source)
    sibling = tmp_path / "foreign-sibling"
    sibling.mkdir()
    (sibling / "keep.txt").write_bytes(b"keep-sibling")
    outcome = {}

    def attempt(stage, info):
        if stage != "before-bound-delete":
            return
        snapshot = rollback.rollback_snapshot_root() / info.name
        try:
            moved = snapshot.with_name(snapshot.name + "-owned")
            snapshot.rename(moved)
            snapshot.mkdir()
            protect_private_directory(snapshot)
            (snapshot / rollback._MARKER_NAME).write_bytes(b"foreign-marker")
            outcome["renamed"] = True
            outcome["moved"] = moved
        except OSError as error:
            outcome["winerror"] = getattr(error, "winerror", None)

    import backend.application.ops.rollback as rollback_module
    rollback_module.snapshot_fault_hooks.append(attempt)
    try:
        with rollback.inspect_existing_sqlite_readonly(database):
            pass
        assert outcome.get("renamed") is not True
        assert outcome.get("winerror") == 32
        assert _owned_snapshots(rollback) == []
    finally:
        rollback_module.snapshot_fault_hooks.remove(attempt)
    assert (sibling / "keep.txt").read_bytes() == b"keep-sibling"
    assert database.read_bytes() == source
    assert not (rollback.rollback_snapshot_root() / "foreign-marker").exists()


def test_substituted_child_file_is_not_deleted_during_cleanup(tmp_path):
    """Same-user replacement of a snapshot file after its identity was recorded."""
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    import backend.application.ops.rollback as rollback
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"child-file-source")
    planted = {}

    def attempt(stage, info):
        if stage != "before-child-delete" or info != database.name or planted:
            return
        snapshot = next(path for path in rollback.rollback_snapshot_root().iterdir()
                        if path.name.startswith("ravenx-rollback-"))
        target = snapshot / database.name
        try:
            renamed = snapshot / (database.name + ".owned")
            target.rename(renamed)
            target.write_bytes(b"foreign-child")
            planted["foreign"] = target
            planted["owned"] = renamed
        except OSError as error:
            planted["winerror"] = getattr(error, "winerror", None)

    rollback.snapshot_fault_hooks.append(attempt)
    try:
        try:
            with rollback.inspect_existing_sqlite_readonly(database):
                pass
        except rollback.RollbackInspectionError as error:
            assert error.residue
            assert planted.get("foreign") is None or planted["foreign"].read_bytes() == b"foreign-child"
        else:
            assert planted.get("winerror") == 32
            assert "foreign" not in planted
        assert _owned_snapshots(rollback) == [] or planted.get("foreign")
    finally:
        rollback.snapshot_fault_hooks.remove(attempt)
    assert database.read_bytes() == b"child-file-source"


def test_capability_full_control_on_an_ancestor_is_refused(tmp_path):
    """A capability SID with full control is a substitution right.

    Traverse-only capability ACEs on a normal profile are not this case.
    """
    if os.name != "nt":
        pytest.skip("Windows ACL ancestry is the case under test")
    import ntsecuritycon
    import win32security
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import protect_private_directory
    ancestor = Path(os.environ["LOCALAPPDATA"]) / "capability-ancestor"
    ancestor.mkdir()
    protect_private_directory(ancestor)
    descriptor = win32security.GetFileSecurity(str(ancestor), win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS,
                             win32security.ConvertStringSidToSid("S-1-15-3-1"))
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(str(ancestor), win32security.DACL_SECURITY_INFORMATION, descriptor)
    previous = os.environ.get("RAVENX_ROLLBACK_SNAPSHOT_ROOT")
    os.environ["RAVENX_ROLLBACK_SNAPSHOT_ROOT"] = str(ancestor / "snapshots")
    database = tmp_path / "raven_x.db"
    marker = b"must-not-be-copied-under-a-capability-full-control-ancestor"
    database.write_bytes(marker)
    try:
        with pytest.raises(rollback.RollbackInspectionError, match="not trusted"):
            with rollback.inspect_existing_sqlite_readonly(database):
                pass
        assert not any(path.is_file() and path.read_bytes() == marker for path in ancestor.rglob("*"))
    finally:
        if previous is None:
            os.environ.pop("RAVENX_ROLLBACK_SNAPSHOT_ROOT", None)
        else:
            os.environ["RAVENX_ROLLBACK_SNAPSHOT_ROOT"] = previous
    assert database.read_bytes() == marker


def test_untrusted_ancestor_owner_is_refused_from_the_descriptor():
    if os.name != "nt":
        pytest.skip("Windows owner validation is the case under test")
    import win32security
    import backend.infrastructure.security.windows_files as files
    real = files._security_descriptor
    untrusted = win32security.ConvertStringSidToSid("S-1-15-3-1")

    class BadOwner:
        def __init__(self, descriptor):
            self.descriptor = descriptor

        def GetSecurityDescriptorOwner(self):
            return untrusted

        def GetSecurityDescriptorDacl(self):
            return self.descriptor.GetSecurityDescriptorDacl()

        def GetSecurityDescriptorControl(self):
            return self.descriptor.GetSecurityDescriptorControl()

    def wrapped(path):
        current = real(path)
        if Path(path).name == "owner-probe":
            return BadOwner(current)
        return current

    probe = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "owner-probe"
    probe.mkdir(parents=True, exist_ok=True)
    files.protect_private_directory(probe)
    files._security_descriptor = wrapped
    try:
        with pytest.raises(files.WindowsFileSecurityError, match="owner"):
            files.assert_ancestry_not_substitutable(probe)
    finally:
        files._security_descriptor = real


def test_directory_handle_access_omits_unneeded_file_rights(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows directory handles are the case under test")
    from backend.infrastructure.security.windows_files import (
        DIRECTORY_HANDLE_ACCESS, open_bound_directory, protect_private_directory,
    )
    omitted = 0x8 | 0x10 | 0x100 | 0x40000 | 0x80000
    included = 0x1 | 0x2 | 0x4 | 0x20 | 0x40 | 0x80 | 0x10000 | 0x20000 | 0x100000
    assert DIRECTORY_HANDLE_ACCESS & omitted == 0
    assert DIRECTORY_HANDLE_ACCESS & included == included
    root = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "access-mask-probe"
    root.mkdir(parents=True, exist_ok=True)
    protect_private_directory(root)
    binding = open_bound_directory(root, share_delete=False)
    try:
        child = binding.make_directory("child")
        child.write_file("note.bin", b"note")
        child.delete_named("note.bin", expected_identity=child.created["note.bin"])
        child.delete_self()
    finally:
        if binding.handle is not None:
            binding.close()
    assert not (root / "child").exists()


def test_explicit_snapshot_root_is_used_and_temp_is_not(tmp_path, monkeypatch):
    import backend.application.ops.rollback as rollback
    from backend.infrastructure.security.windows_files import protect_private_directory
    explicit = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "explicit-root"
    explicit.mkdir(parents=True, exist_ok=True)
    protect_private_directory(explicit)
    monkeypatch.setenv("RAVENX_ROLLBACK_SNAPSHOT_ROOT", str(explicit))
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"explicit-root-source")
    with rollback.inspect_existing_sqlite_readonly(database):
        assert rollback.rollback_snapshot_root() == explicit
        assert _owned_snapshots(rollback)
    assert list(explicit.glob("ravenx-rollback-*")) == []
    assert database.read_bytes() == b"explicit-root-source"
    assert list(tmp_path.glob("ravenx-rollback-*")) == []
