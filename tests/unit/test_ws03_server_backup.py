import json
import os
from pathlib import Path
import shutil
import subprocess
import sqlite3
import uuid

import pytest

from backend.application.ops.server_backup import BackupError, create_backup, restore_isolated, verify_backup
from backend.cli import generate_local_tls


@pytest.fixture
def roots(tmp_path):
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_directory
        base = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / ("ws03-" + uuid.uuid4().hex)
        base.mkdir(parents=True)
        protect_private_directory(base)
        def make(name):
            path = base / name
            path.mkdir()
            protect_private_directory(path)
            return path
    else:
        base = tmp_path
        base.chmod(0o700)
        def make(name):
            path = base / name
            path.mkdir(mode=0o700)
            return path
    data, install, backup_parent = (make(name) for name in ("data", "install", "backups"))
    tls = data / "tls"
    tls.mkdir(mode=0o700)
    if os.name == "nt":
        protect_private_directory(tls)
    generate_local_tls(tls, ["192.168.1.121"], protect=lambda _path: None)
    for name in ("ca.pem", "ca-key.pem", "server.pem", "server-key.pem"):
        file = tls / name
        if os.name == "nt":
            from backend.infrastructure.security.windows_files import protect_private_secret_file
            protect_private_secret_file(file)
        else:
            file.chmod(0o600)
    db = data / "raven_x.db"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO records VALUES (1, 'kept')")
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_secret_file
        protect_private_secret_file(db)
    else:
        db.chmod(0o600)
    yield base, data, install, backup_parent


def test_backup_and_isolated_restore_preserve_records(roots):
    base, data, install, backup_parent = roots
    backup = backup_parent / "snapshot"
    result = create_backup(data_root=data, install_root=install, destination=backup, production=False)
    assert result["verified"] is True
    assert result["tables"] == 1
    assert verify_backup(backup, production=False)
    from backend.application.ops.server_backup import _custody_metadata
    manifest = json.loads((backup / "manifest.json").read_text())
    db_entry = next(item for item in manifest["files"] if item["name"] == "raven_x.db")
    assert db_entry["source_custody"] == _custody_metadata(data / "raven_x.db")
    assert not (backup / "sqlite-online-snapshot.db").exists()
    with pytest.raises(BackupError, match="network isolation"):
        restore_isolated(backup_root=backup, destination=base / "refused", production=False)
    restored = restore_isolated(backup_root=backup, destination=base / "restored",
                                production=False, network_isolated=True)
    assert restored["counts"]["records"] == 1
    with sqlite3.connect(base / "restored" / "raven_x.db") as connection:
        assert connection.execute("SELECT value FROM records WHERE id=1").fetchone() == ("kept",)


def test_installed_config_is_encrypted_and_restored_without_version_marker(roots):
    base, data, install, backup_parent = roots
    config_dir = install / "config"
    config_dir.mkdir()
    config = config_dir / "config.yaml"
    config.write_bytes(b"server:\n  bind: synthetic\n")
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import (
            protect_private_directory, protect_private_secret_file,
        )
        protect_private_directory(config_dir)
        protect_private_secret_file(config)
    else:
        config_dir.chmod(0o700)
        config.chmod(0o600)
    backup = backup_parent / "config-snapshot"
    create_backup(data_root=data, install_root=install, destination=backup, production=False)
    manifest = json.loads((backup / "manifest.json").read_text())
    assert "install/config/config.yaml" in {item["name"] for item in manifest["files"]}
    restored = base / "config-restored"
    restore_isolated(backup_root=backup, destination=restored,
                     production=False, network_isolated=True)
    assert (restored / "install" / "config" / "config.yaml").read_bytes() == config.read_bytes()


def test_tampered_or_partial_backup_is_refused(roots):
    _base, data, install, backup_parent = roots
    backup = backup_parent / "snapshot"
    create_backup(data_root=data, install_root=install, destination=backup, production=False)
    manifest = json.loads((backup / "manifest.json").read_text())
    member = backup / manifest["files"][0]["member"]
    member.write_bytes(member.read_bytes()[:-1] + b"X")
    with pytest.raises(BackupError, match="hash mismatch"):
        verify_backup(backup, production=False)


def test_existing_destination_and_outside_custody_fail_closed(roots):
    base, data, install, backup_parent = roots
    with pytest.raises(BackupError, match="outside"):
        create_backup(data_root=data, install_root=install,
                      destination=data / "snapshot", production=False)
    destination = backup_parent / "snapshot"
    destination.mkdir()
    with pytest.raises(BackupError, match="already exists"):
        create_backup(data_root=data, install_root=install,
                      destination=destination, production=False)


def test_windows_dpapi_backup_key_round_trip_is_machine_bound():
    if os.name != "nt":
        pytest.skip("Windows DPAPI")
    from backend.application.ops.server_backup import _unwrap_key, _wrap_key
    key = os.urandom(32)
    wrapped = _wrap_key(key)
    assert key not in wrapped
    assert _unwrap_key(wrapped) == key
    with pytest.raises(Exception):
        _unwrap_key(wrapped[:-1] + bytes([wrapped[-1] ^ 1]))


def test_online_backup_includes_uncheckpointed_wal_record(roots):
    base, data, install, backup_parent = roots
    db = sqlite3.connect(data / "raven_x.db")
    try:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        db.execute("INSERT INTO records VALUES (2, 'committed in WAL')")
        db.commit()
        assert (data / "raven_x.db-wal").exists()
        backup = backup_parent / "wal-snapshot"
        create_backup(data_root=data, install_root=install, destination=backup, production=False)
        restored = restore_isolated(backup_root=backup, destination=base / "wal-restored",
                                    production=False, network_isolated=True)
        assert restored["counts"]["records"] == 2
    finally:
        db.close()


def test_corrupt_database_blocks_backup_before_manifest(roots):
    _base, data, install, backup_parent = roots
    database = data / "raven_x.db"
    database.write_bytes(b"not-a-sqlite-database")
    backup = backup_parent / "corrupt-snapshot"
    with pytest.raises((BackupError, sqlite3.DatabaseError)):
        create_backup(data_root=data, install_root=install, destination=backup, production=False)
    assert not (backup / "manifest.json").exists()


def test_verifier_key_must_match_database_identity(roots):
    _base, data, install, backup_parent = roots
    from backend.infrastructure.security.verifier_key import verifier_key_id
    key_path = data / "credential-hmac.key"
    key_path.write_bytes(b"K" * 32)
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_secret_file
        protect_private_secret_file(key_path)
    else:
        key_path.chmod(0o600)
    with sqlite3.connect(data / "raven_x.db") as db:
        db.execute("CREATE TABLE ravenx_verifier_keys (id INTEGER PRIMARY KEY, key_id TEXT)")
        db.execute("INSERT INTO ravenx_verifier_keys VALUES (1, ?)", (verifier_key_id(b"Q" * 32),))
    with pytest.raises(BackupError, match="does not match"):
        create_backup(data_root=data, install_root=install,
                      destination=backup_parent / "mismatch", production=False)


def test_row_comparison_detects_same_count_authority_change(roots):
    base, data, _install, _backup_parent = roots
    from backend.application.ops.server_backup import compare_existing_records
    before = data / "raven_x.db"
    after = base / "after.db"
    shutil.copyfile(before, after)
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_secret_file
        protect_private_secret_file(after)
    else:
        after.chmod(0o600)
    with sqlite3.connect(after) as db:
        db.execute("CREATE TABLE new_migration_table (id INTEGER)")
    assert compare_existing_records(before, after, production=False)["preserved"]
    with sqlite3.connect(after) as db:
        db.execute("UPDATE records SET value='changed' WHERE id=1")
    result = compare_existing_records(before, after, production=False)
    assert result == {"preserved": False, "checked_tables": 1, "changed_tables": ["records"]}


def test_writable_backup_parent_is_rejected_before_source_copy(roots):
    base, data, install, _backup_parent = roots
    unsafe = base / "unsafe"
    unsafe.mkdir()
    if os.name == "nt":
        import ntsecuritycon
        import win32security
        everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid)
        descriptor = win32security.GetFileSecurity(str(unsafe), win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, everyone)
        descriptor.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(str(unsafe), win32security.DACL_SECURITY_INFORMATION, descriptor)
    else:
        unsafe.chmod(0o777)
    with pytest.raises(Exception, match="private|unexpected|unsafe|untrusted"):
        create_backup(data_root=data, install_root=install,
                      destination=unsafe / "snapshot", production=False)
    assert not (unsafe / "snapshot").exists()


def test_backup_parent_reparse_point_is_rejected(roots):
    base, data, install, backup_parent = roots
    link = base / "linked-parent"
    if os.name == "nt":
        command = ("New-Item -ItemType Junction -Path '" + str(link).replace("'", "''") +
                   "' -Target '" + str(backup_parent).replace("'", "''") + "' | Out-Null")
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                       check=True, capture_output=True, text=True)
    else:
        link.symlink_to(backup_parent, target_is_directory=True)
    try:
        with pytest.raises(Exception):
            create_backup(data_root=data, install_root=install,
                          destination=link / "snapshot", production=False)
        assert not (backup_parent / "snapshot").exists()
    finally:
        if os.name == "nt":
            link.rmdir()
        else:
            link.unlink()


def test_mismatched_tls_key_is_refused_before_backup_creation(roots):
    base, data, install, backup_parent = roots
    other = base / "other-tls"
    other.mkdir(mode=0o700)
    generate_local_tls(other, ["192.168.1.121"], protect=lambda _path: None)
    key = data / "tls" / "server-key.pem"
    key.write_bytes((other / "server-key.pem").read_bytes())
    with pytest.raises(BackupError, match="identities do not match"):
        create_backup(data_root=data, install_root=install,
                      destination=backup_parent / "bad-tls", production=False)
    assert not (backup_parent / "bad-tls").exists()
