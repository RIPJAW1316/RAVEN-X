from pathlib import Path
from types import SimpleNamespace
import stat

import pytest

from backend.infrastructure.security import windows_files


def test_protected_directory_rejects_reparse_components_before_acl_read(tmp_path, monkeypatch):
    protected = tmp_path / "protected"
    protected.mkdir()
    original_lstat = windows_files.os.lstat

    def lstat(path):
        if Path(path) == protected:
            return SimpleNamespace(st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return original_lstat(path)

    monkeypatch.setattr(windows_files.os, "lstat", lstat)
    monkeypatch.setattr(windows_files, "_verify_acl", lambda *a, **kw: pytest.fail("ACL read followed reparse"))
    with pytest.raises(windows_files.WindowsFileSecurityError, match="reparse"):
        windows_files.verify_directory(protected)


def test_protected_directory_rejects_untrusted_acl(tmp_path, monkeypatch):
    protected = tmp_path / "protected"
    protected.mkdir()
    class Dacl:
        def GetAceCount(self):
            return 2

        def GetAce(self, index):
            sid = ("S-1-5-18", "S-1-5-32-545")[index]
            return ((0, 3), 0x1f01ff, sid)

    class Descriptor:
        def GetSecurityDescriptorOwner(self):
            return "S-1-5-32-544"

        def GetSecurityDescriptorControl(self):
            return (4, 0)

        def GetSecurityDescriptorDacl(self):
            return Dacl()

    class Security:
        OWNER_SECURITY_INFORMATION = 1
        DACL_SECURITY_INFORMATION = 2
        SE_DACL_PROTECTED = 4
        ACCESS_ALLOWED_ACE_TYPE = 0
        OBJECT_INHERIT_ACE = 1
        CONTAINER_INHERIT_ACE = 2

        @staticmethod
        def GetFileSecurity(*_):
            return Descriptor()

        @staticmethod
        def ConvertSidToStringSid(sid):
            return sid

    class FileRights:
        FILE_ALL_ACCESS = 0x1f01ff

    monkeypatch.setattr(windows_files, "_windows_security", lambda: (Security, FileRights))
    with pytest.raises(windows_files.WindowsFileSecurityError, match="unexpected access"):
        windows_files.verify_directory(protected)


def test_path_normalization_rejects_parent_traversal(tmp_path):
    with pytest.raises(windows_files.WindowsFileSecurityError, match="absolute local path"):
        windows_files.verify_directory(tmp_path / "subdir" / ".." / "elsewhere")


def test_atomic_write_protected_applies_and_verifies_private_acl_and_preserves_target_on_interruption(
    tmp_path, monkeypatch
):
    protected = tmp_path / "protected"
    protected.mkdir()
    target = protected / "credential.bin"
    target.write_bytes(b"original-protected-state")

    acl_applied = []
    verified_paths = []

    monkeypatch.setattr(windows_files, "verify_directory", lambda path: Path(path))
    monkeypatch.setattr(windows_files, "_assert_no_reparse", lambda path: None)
    monkeypatch.setattr(
        windows_files,
        "_set_private_acl",
        lambda path, *, directory: acl_applied.append((Path(path).name, directory)),
    )
    monkeypatch.setattr(
        windows_files,
        "verify_protected_file",
        lambda path: verified_paths.append(Path(path).name) or Path(path),
    )

    windows_files.atomic_write_protected(target, b"renewed-protected-state")
    assert target.read_bytes() == b"renewed-protected-state"
    assert list(protected.glob("*.tmp")) == []
    # Temporary file received explicit non-directory private ACL before replace
    assert len(acl_applied) == 1
    assert acl_applied[0][0].startswith("credential.bin.") and acl_applied[0][0].endswith(".tmp")
    assert acl_applied[0][1] is False

    # Now simulate an interruption during os.replace: target must remain intact and .tmp must be unlinked
    def interrupted_replace(src, dst):
        raise OSError("simulated crash during atomic replace")

    monkeypatch.setattr(windows_files.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="simulated crash"):
        windows_files.atomic_write_protected(target, b"corrupted-state")
    assert target.read_bytes() == b"renewed-protected-state"
    assert list(protected.glob("*.tmp")) == []


def _callback_directory(path):
    import win32api
    import win32security
    path.mkdir(parents=True, exist_ok=True)
    user = win32security.LookupAccountName(None, win32api.GetUserName())[0]
    user_sid = win32security.ConvertSidToStringSid(user)
    sddl = (
        "D:P(A;;FA;;;SY)(A;;FA;;;%s)"
        "(XA;;FA;;;S-1-15-3-1;(Member_of {SID(S-1-5-32-545)}))"
    ) % user_sid
    try:
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
        win32security.SetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    except Exception as error:
        pytest.skip("this account cannot attach a callback ACE: %s" % error)


def test_real_callback_ace_fails_closed_before_snapshot_or_key_publication(tmp_path, monkeypatch):
    if windows_files.os.name != "nt":
        pytest.skip("Windows callback ACEs are the case under test")
    import os
    import sqlite3
    from uuid import uuid4
    blocked = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "ws01-callback-ace" / uuid4().hex
    _callback_directory(blocked)
    with pytest.raises(windows_files.WindowsFileSecurityError, match="cannot decode") as decoded:
        windows_files.assert_ancestry_not_substitutable(blocked)
    assert isinstance(decoded.value.__cause__, NotImplementedError)
    assert "S-1-" not in str(decoded.value)

    marker = b"callback-ace-must-not-be-copied"
    database = tmp_path / "raven_x.db"
    database.write_bytes(marker)
    monkeypatch.setenv("RAVENX_ROLLBACK_SNAPSHOT_ROOT", str(blocked / "snapshots"))
    from backend.application.ops.rollback import RollbackInspectionError, inspect_existing_sqlite_readonly
    with pytest.raises(RollbackInspectionError, match="not trusted") as refused:
        with inspect_existing_sqlite_readonly(database):
            pass
    assert isinstance(refused.value.__cause__, windows_files.WindowsFileSecurityError)
    assert not any(path.is_file() and path.read_bytes() == marker for path in blocked.rglob("*"))

    key_dir = blocked / "keys"
    key_dir.mkdir(exist_ok=True)
    key_database = key_dir / "raven_x.db"
    connection = sqlite3.connect(key_database)
    connection.execute("CREATE TABLE sample (id INTEGER)")
    connection.commit()
    connection.close()
    from backend.infrastructure.security.verifier_key import VerifierKeyError, prepare_persistent_verifier_key
    with pytest.raises(VerifierKeyError, match="lock parent") as unpublished:
        prepare_persistent_verifier_key(key_database, environ={}, environment="development")
    assert isinstance(unpublished.value.__cause__, windows_files.WindowsFileSecurityError)
    assert not (key_dir / "credential-hmac.key").exists()


def test_injected_ace_decoder_failure_is_not_trusted(tmp_path, monkeypatch):
    if windows_files.os.name != "nt":
        pytest.skip("Windows ACL decoding is the case under test")
    import os
    probe = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "injected-ace"
    probe.mkdir(parents=True, exist_ok=True)
    windows_files.protect_private_directory(probe)
    real = windows_files._security_descriptor

    class Undecodable:
        def __init__(self, inner):
            self.inner = inner

        def GetSecurityDescriptorOwner(self):
            return self.inner.GetSecurityDescriptorOwner()

        def GetSecurityDescriptorDacl(self):
            return self

        def GetAceCount(self):
            return 1

        def GetAce(self, index):
            raise NotImplementedError("Ace type 9 is not supported yet")

    monkeypatch.setattr(
        windows_files, "_security_descriptor",
        lambda path: Undecodable(real(path)) if Path(path).name == "injected-ace" else real(path))
    with pytest.raises(windows_files.WindowsFileSecurityError, match="cannot decode") as caught:
        windows_files.assert_ancestry_not_substitutable(probe)
    assert isinstance(caught.value.__cause__, NotImplementedError)


def _ancestry_with_aces(monkeypatch, name, aces):
    import os
    probe = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / name
    probe.mkdir(parents=True, exist_ok=True)
    windows_files.protect_private_directory(probe)
    real = windows_files._security_descriptor

    class Scripted:
        def __init__(self, inner):
            self.inner = inner

        def GetSecurityDescriptorOwner(self):
            return self.inner.GetSecurityDescriptorOwner()

        def GetSecurityDescriptorDacl(self):
            return self

        def GetAceCount(self):
            return len(aces)

        def GetAce(self, index):
            return aces[index]

    monkeypatch.setattr(
        windows_files, "_security_descriptor",
        lambda path: Scripted(real(path)) if Path(path).name == name else real(path))
    return probe


def test_decoded_callback_allow_and_malformed_aces_fail_closed(tmp_path, monkeypatch):
    if windows_files.os.name != "nt":
        pytest.skip("Windows ACL decoding is the case under test")
    import os
    import sqlite3
    capability = "S-1-15-3-1"
    cases = (
        ("type9-delete-child", ((0x09, 0), 0x40, capability), "cannot evaluate"),
        ("type9-write-dac", ((0x09, 0), 0x40000, capability), "cannot evaluate"),
        ("malformed-mask", ((0x00, 0), "0x40", capability), "cannot decode"),
        ("malformed-sid", ((0x00, 0), 0x40, None), "cannot decode"),
        ("malformed-header", (("allow", 0), 0x40, capability), "cannot decode"),
        ("malformed-tuple", ((0x00, 0), 0x40), "cannot decode"),
        ("unknown-type", ((0x99, 0), 0x40, capability), "cannot evaluate"),
    )
    for name, ace, match in cases:
        probe = _ancestry_with_aces(monkeypatch, name, (ace,))
        with pytest.raises(windows_files.WindowsFileSecurityError, match=match):
            windows_files.assert_ancestry_not_substitutable(probe)

    trusted_allow = _ancestry_with_aces(monkeypatch, "ordinary-allow", (((0x00, 0), 0x1200A9, "S-1-5-18"),))
    windows_files.assert_ancestry_not_substitutable(trusted_allow)
    deny = _ancestry_with_aces(monkeypatch, "ordinary-deny", (((0x01, 0), 0x40, capability),))
    windows_files.assert_ancestry_not_substitutable(deny)
    traverse = _ancestry_with_aces(monkeypatch, "harmless-traverse", (((0x00, 0), 0x100020, capability),))
    windows_files.assert_ancestry_not_substitutable(traverse)
    owner_rights = _ancestry_with_aces(
        monkeypatch, "owner-rights", (((0x00, 0), 0x40, "S-1-3-4"),))
    windows_files.assert_ancestry_not_substitutable(owner_rights)

    blocked = _ancestry_with_aces(
        monkeypatch, "type9-blocks-publication", (((0x09, 0), 0x40, capability),))
    marker = b"decoded-type9-must-not-be-copied"
    database = tmp_path / "raven_x.db"
    database.write_bytes(marker)
    monkeypatch.setenv("RAVENX_ROLLBACK_SNAPSHOT_ROOT", str(blocked / "snapshots"))
    from backend.application.ops.rollback import RollbackInspectionError, inspect_existing_sqlite_readonly
    with pytest.raises(RollbackInspectionError, match="not trusted"):
        with inspect_existing_sqlite_readonly(database):
            pass
    assert not (blocked / "snapshots").exists()
    assert database.read_bytes() == marker

    key_database = tmp_path / "keyed.db"
    connection = sqlite3.connect(key_database)
    connection.execute("CREATE TABLE sample (id INTEGER)")
    connection.commit()
    connection.close()
    # The database file is outside the refused directory. Pointing its parent
    # at the refused directory is what publication checks.
    refused_parent = _ancestry_with_aces(
        monkeypatch, "type9-key-parent", (((0x09, 0), 0x40, capability),))
    placed = refused_parent / "raven_x.db"
    placed.write_bytes(key_database.read_bytes())
    from backend.infrastructure.security.verifier_key import VerifierKeyError, prepare_persistent_verifier_key
    with pytest.raises(VerifierKeyError, match="lock parent"):
        prepare_persistent_verifier_key(placed, environ={}, environment="development")
    assert not (refused_parent / "credential-hmac.key").exists()
