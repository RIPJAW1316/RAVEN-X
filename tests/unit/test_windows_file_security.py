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
