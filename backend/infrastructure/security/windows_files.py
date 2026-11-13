"""Fail-closed Windows filesystem protection for machine credentials and keys.

Only SYSTEM and the local Administrators group may own/read/write a protected
object. The directory DACL is explicit and protected from inheritance. Callers
must run elevated when creating or repairing a directory.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from uuid import uuid4


_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_OWNER_RIGHTS = "S-1-3-4"
_ALLOWED = frozenset({_SYSTEM, _ADMINS})
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")


class WindowsFileSecurityError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class DurabilityError(WindowsFileSecurityError):
    """A required file flush or open failed. The message does not include file contents."""


@dataclass(frozen=True)
class FlushResult:
    """File durability is required. Directory metadata may be unconfirmed."""

    file_durable: bool
    directory_metadata_confirmed: bool
    limitation: str | None = None


def _windows_security():
    if os.name != "nt":
        raise WindowsFileSecurityError("protected agent storage requires Windows")
    try:
        import win32security
        import ntsecuritycon
    except ImportError as error:
        raise WindowsFileSecurityError("pywin32 is required for protected storage") from error
    return win32security, ntsecuritycon


def _absolute_local_path(path) -> Path:
    value = Path(path)
    if not value.is_absolute() or str(value).startswith("\\\\") or ".." in value.parts:
        raise WindowsFileSecurityError("storage path must be an absolute local path")
    return value


def _assert_no_reparse(path: Path) -> None:
    """Reject symlinks, junctions, mount points, and other reparse components."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            attributes = os.lstat(current).st_file_attributes
        except FileNotFoundError:
            continue
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsFileSecurityError("storage path contains a reparse point")


def _security_descriptor(path: Path):
    win32security, _ = _windows_security()
    return win32security.GetFileSecurity(
        str(path), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    )


_ACE_ALLOW = 0x00
_ACE_DENY = 0x01
_ACE_AUDIT = 0x02
_ACE_ALARM = 0x03
# These do not grant access. Callback and object allow forms are not in this set.
_NON_GRANTING_ACE_TYPES = frozenset({
    _ACE_DENY, _ACE_AUDIT, _ACE_ALARM,
    0x11,  # SYSTEM_MANDATORY_LABEL
})
# Allow forms other than a plain ACCESS_ALLOWED ACE. Their conditions or
# object GUIDs are not evaluated, so any of them can hide a grant.
_UNSUPPORTED_GRANTING_ACE_TYPES = frozenset({
    0x04,  # ACCESS_ALLOWED_COMPOUND
    0x05,  # ACCESS_ALLOWED_OBJECT
    0x09,  # ACCESS_ALLOWED_CALLBACK
    0x0B,  # ACCESS_ALLOWED_CALLBACK_OBJECT
})


def _undecodable(error: Exception | None = None) -> WindowsFileSecurityError:
    message = "storage access list contains an entry this process cannot decode"
    if error is None:
        return WindowsFileSecurityError(message)
    return WindowsFileSecurityError(message)


def _read_ace(dacl, index):
    """Return one ACE, or fail closed if its shape cannot be trusted.

    pywin32 raises NotImplementedError for a real callback ACE. A decoded
    tuple still has to carry an integer header, an integer mask, and a SID
    this process can turn into an SID string. Anything else is refused.
    """
    try:
        entry = dacl.GetAce(index)
    except NotImplementedError as error:
        raise _undecodable() from error
    if not isinstance(entry, tuple) or len(entry) != 3:
        raise _undecodable()
    header, mask, sid = entry
    if (not isinstance(header, tuple) or len(header) != 2
            or type(header[0]) is not int or type(header[1]) is not int
            or not 0 <= header[0] <= 0xFF or not 0 <= header[1] <= 0xFF):
        raise _undecodable()
    # pywin32 returns the 32-bit mask as a signed int. GENERIC_READ sets the high bit.
    if type(mask) is not int:
        raise _undecodable()
    _validated_sid(sid)
    return header, mask & 0xFFFFFFFF, sid


def _validated_sid(sid) -> str:
    """Return an SID string, or fail closed without echoing the value."""
    if isinstance(sid, str):
        parts = sid.split("-")
        if (len(parts) < 3 or parts[0] != "S" or parts[1] != "1"
                or not all(part.isdigit() for part in parts[2:])):
            raise _undecodable()
        return sid
    try:
        win32security, _ntsecuritycon = _windows_security()
        text = win32security.ConvertSidToStringSid(sid)
    except Exception as error:
        raise _undecodable() from error
    if not isinstance(text, str) or not text.startswith("S-1-"):
        raise _undecodable()
    return text


def _set_private_acl(path: Path, *, directory: bool) -> None:
    win32security, ntsecuritycon = _windows_security()
    admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    dacl = win32security.ACL()
    inherit = (win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE) if directory else 0
    for sid in (system_sid, admin_sid):
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inherit,
                                   ntsecuritycon.FILE_ALL_ACCESS, sid)
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(admin_sid, False)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    descriptor.SetSecurityDescriptorControl(win32security.SE_DACL_PROTECTED,
                                            win32security.SE_DACL_PROTECTED)
    win32security.SetFileSecurity(
        str(path),
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION |
        win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        descriptor,
    )


def _verify_acl(path: Path, *, directory: bool) -> None:
    win32security, ntsecuritycon = _windows_security()
    descriptor = _security_descriptor(path)
    owner = descriptor.GetSecurityDescriptorOwner()
    if win32security.ConvertSidToStringSid(owner) not in _ALLOWED:
        raise WindowsFileSecurityError("protected path has an untrusted owner")
    control, _ = descriptor.GetSecurityDescriptorControl()
    if not control & win32security.SE_DACL_PROTECTED:
        raise WindowsFileSecurityError("protected path inherits access rules")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or dacl.GetAceCount() != 2:
        raise WindowsFileSecurityError("protected path has unexpected access rules")
    seen = set()
    for index in range(dacl.GetAceCount()):
        header, mask, sid = _read_ace(dacl, index)
        ace_type, flags = header
        identity = win32security.ConvertSidToStringSid(sid)
        if (ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in _ALLOWED or
                identity in seen or (mask & ntsecuritycon.FILE_ALL_ACCESS) != ntsecuritycon.FILE_ALL_ACCESS):
            raise WindowsFileSecurityError("protected path grants unexpected access")
        if directory and not (flags & win32security.OBJECT_INHERIT_ACE and
                              flags & win32security.CONTAINER_INHERIT_ACE):
            raise WindowsFileSecurityError("protected directory does not protect child objects")
        seen.add(identity)
    if seen != _ALLOWED:
        raise WindowsFileSecurityError("protected path lacks SYSTEM or Administrators access")


def verify_directory(path) -> Path:
    """Return a secure directory or fail without following reparse points."""
    directory = _absolute_local_path(path)
    _assert_no_reparse(directory)
    if not directory.is_dir():
        raise WindowsFileSecurityError("protected directory does not exist")
    _verify_acl(directory, directory=True)
    return directory


def protect_directory(path) -> Path:
    """Create or lock a directory before secrets are written beneath it."""
    directory = _absolute_local_path(path)
    _assert_no_reparse(directory.parent)
    if not directory.parent.is_dir():
        raise WindowsFileSecurityError("protected directory parent must already exist")
    if not directory.exists():
        directory.mkdir()
    _assert_no_reparse(directory)
    if not directory.is_dir():
        raise WindowsFileSecurityError("protected path is not a directory")
    _set_private_acl(directory, directory=True)
    return verify_directory(directory)


def protect_private_directory(path) -> Path:
    """Give a directory a protected DACL for the current user, SYSTEM, and Administrators.

    Children inherit that DACL. This is process custody for a rollback snapshot,
    not the installed SYSTEM-only agent directory.
    """
    directory = _absolute_local_path(path)
    _assert_no_reparse(directory)
    if not directory.is_dir():
        raise WindowsFileSecurityError("protected directory does not exist")
    win32security, ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
    dacl = win32security.ACL()
    inherit = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    seen = set()
    for sid in (user_sid, system_sid, admin_sid):
        identity = win32security.ConvertSidToStringSid(sid)
        if identity in seen:
            continue
        seen.add(identity)
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inherit, ntsecuritycon.FILE_ALL_ACCESS, sid)
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(user_sid, False)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
    win32security.SetFileSecurity(
        str(directory),
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION |
        win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        descriptor,
    )
    verify_private_directory(directory)
    return directory


def verify_private_directory(path) -> Path:
    """Verify an existing private directory without changing its ACL."""
    directory = _absolute_local_path(path)
    _assert_no_reparse(directory)
    if not directory.is_dir():
        raise WindowsFileSecurityError("protected directory does not exist")
    _verify_private_directory(directory)
    return directory


def _verify_private_directory(path: Path) -> None:
    win32security, ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    owners = {win32security.ConvertSidToStringSid(user_sid), _SYSTEM, _ADMINS}
    allowed = owners | {_OWNER_RIGHTS}
    descriptor = _security_descriptor(path)
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    if owner not in owners:
        raise WindowsFileSecurityError("protected path has an untrusted owner")
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if not control & win32security.SE_DACL_PROTECTED:
        raise WindowsFileSecurityError("protected path inherits access rules")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or not 1 <= dacl.GetAceCount() <= 4:
        raise WindowsFileSecurityError("protected path has unexpected access rules")
    seen = set()
    for index in range(dacl.GetAceCount()):
        header, mask, sid = _read_ace(dacl, index)
        ace_type, flags = header
        identity = win32security.ConvertSidToStringSid(sid)
        if (ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in allowed or identity in seen
                or mask & ntsecuritycon.FILE_ALL_ACCESS != ntsecuritycon.FILE_ALL_ACCESS
                or not (flags & win32security.OBJECT_INHERIT_ACE and flags & win32security.CONTAINER_INHERIT_ACE)):
            raise WindowsFileSecurityError("protected path grants unexpected access")
        seen.add(identity)
    if _SYSTEM not in seen or _ADMINS not in seen:
        raise WindowsFileSecurityError("protected path lacks SYSTEM or Administrators access")


_DELETE_CHILD = 0x00000040
_DELETE = 0x00010000
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_SYNCHRONIZE = 0x00100000
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_INHERIT_ONLY = 0x08
_REPARSE = 0x400
_FILE_READ_EA = 0x00000008
_FILE_WRITE_EA = 0x00000010
_FILE_WRITE_ATTRIBUTES = 0x00000100
# Directory handles use the documented file-right bits that NT interprets for
# directories: list, add file, add subdirectory, traverse, delete-child,
# read attributes, delete, read control, and synchronize (0x001300E7).
# Read/write EA, write attributes, write-DACL, and write-owner are omitted.
# The DACL is supplied to NtCreateFile at creation; children are removed with
# DELETE on the opened child or FILE_DELETE_CHILD on this handle.
# FileDispositionInfo (SetFileInformationByHandle class 4) removes the object
# when its last handle closes. Assumes NTFS on Windows 10 or later.
DIRECTORY_HANDLE_ACCESS = (
    0x0001 | 0x0002 | 0x0004 | 0x0020 | _DELETE_CHILD | 0x0080
    | _DELETE | _READ_CONTROL | _SYNCHRONIZE)
_SUBSTITUTION_RIGHTS = _DELETE_CHILD | _DELETE | _WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL | _GENERIC_WRITE
# Windows Component Servicing owns the volume root. This is that one service
# SID, not every service SID.
_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_LOCAL_SERVICE = "S-1-5-19"
_NETWORK_SERVICE = "S-1-5-20"


# Windows Module Installer (TrustedInstaller) owns the system volume root.
_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_LOCAL_SERVICE = "S-1-5-19"
_NETWORK_SERVICE = "S-1-5-20"

# Rights for a directory handle used to create, inspect, and remove children.
# Directory semantics of the file access bits (Win32 file-security reference):
# FILE_LIST_DIRECTORY, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_TRAVERSE,
# FILE_DELETE_CHILD, FILE_READ_ATTRIBUTES, DELETE, READ_CONTROL, SYNCHRONIZE.
# FILE_READ_EA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, WRITE_DAC and WRITE_OWNER
# are not requested. The DACL is supplied to NtCreateFile at creation, and a
# child is removed with DELETE on that child's handle.
# Assumes NTFS on Windows 10/11. SetFileInformationByHandle FileDispositionInfo
# (class 4) deletes that same object when its last handle closes.
DIRECTORY_HANDLE_ACCESS = 0x001300E7


def trusted_owner_sids() -> set[str]:
    """Principals that may own an ancestor of protected storage.

    This is the current user plus the built-in system, service, and
    administrator identities that own a normal Windows profile and volume.
    Capability SIDs and ordinary group SIDs are not owners we trust.
    """
    win32security, _ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    return {
        win32security.ConvertSidToStringSid(user_sid),
        _SYSTEM, _ADMINS, _LOCAL_SERVICE, _NETWORK_SERVICE, _TRUSTED_INSTALLER,
    }


def trusted_identity_sids() -> set[str]:
    win32security, _ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    return {win32security.ConvertSidToStringSid(user_sid), _SYSTEM, _ADMINS, _OWNER_RIGHTS}


def assert_ancestry_not_substitutable(path) -> Path:
    """Refuse a path whose ancestor is untrusted or can be renamed by one.

    Every ancestor owner must be the current user, SYSTEM, Administrators,
    LocalService, NetworkService, or TrustedInstaller. An effective allow ACE
    for anyone else that includes delete-child, delete, write-DACL, write-owner,
    generic-write, or generic-all is refused. An OWNER RIGHTS ACE is judged as
    the verified owner of that directory, not as a separate trusted principal.
    Inherit-only ACEs are ignored. A reparse point is refused. A traverse or
    list right is not a substitution right. Ownership that cannot be read fails
    closed. This does not stop the trusted owner from racing a rename.
    """
    if os.name != "nt":
        return Path(path)
    directory = _absolute_local_path(path)
    win32security, _ntsecuritycon = _windows_security()
    trusted = trusted_owner_sids()
    current = directory if directory.exists() or directory.is_symlink() else directory.parent
    while True:
        try:
            attributes = os.lstat(current).st_file_attributes
        except FileNotFoundError:
            if current == current.parent:
                break
            current = current.parent
            continue
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsFileSecurityError("storage ancestry contains a reparse point")
        if current.is_dir():
            try:
                descriptor = _security_descriptor(current)
                owner = descriptor.GetSecurityDescriptorOwner()
                owner_sid = win32security.ConvertSidToStringSid(owner)
            except Exception as error:
                raise WindowsFileSecurityError("storage ancestry owner could not be read") from error
            if owner_sid not in trusted:
                raise WindowsFileSecurityError("storage ancestry owner is not trusted")
            dacl = descriptor.GetSecurityDescriptorDacl()
            if dacl is None:
                raise WindowsFileSecurityError("storage ancestry has no access list")
            for index in range(dacl.GetAceCount()):
                header, mask, sid = _read_ace(dacl, index)
                ace_type, flags = header
                identity = _validated_sid(sid)
                if ace_type == _ACE_ALLOW:
                    if flags & _INHERIT_ONLY:
                        continue
                    principal = owner_sid if identity == _OWNER_RIGHTS else identity
                    if principal not in trusted and (mask & _SUBSTITUTION_RIGHTS):
                        raise WindowsFileSecurityError(
                            "storage ancestry allows an untrusted principal to substitute it")
                    continue
                if ace_type in _NON_GRANTING_ACE_TYPES:
                    continue
                raise WindowsFileSecurityError(
                    "storage access list contains an entry this process cannot evaluate")
        if current == current.parent:
            break
        current = current.parent
    return directory


class BoundDirectory:
    """An open directory object. Child creates and writes use this handle, not a path re-lookup."""

    def __init__(self, handle, identity: tuple, name: str):
        self.handle = handle
        self.identity = identity
        self.name = name
        self.created: dict[str, tuple] = {}

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle is not None:
            import win32file
            win32file.CloseHandle(handle)

    def same_object(self) -> bool:
        return self.handle is not None and _file_identity(self.handle) == self.identity

    def write_file(self, name: str, data: bytes) -> None:
        if not self.same_object():
            raise WindowsFileSecurityError("bound directory no longer names the validated object")
        handle = _create_relative(self.handle, name, directory=False)
        consumed = False
        try:
            if _file_identity(handle)[0] != self.identity[0]:
                raise WindowsFileSecurityError("bound file is on a different volume")
            consumed = True
            _write_handle(handle, data)
        except Exception:
            if not consumed:
                import win32file
                win32file.CloseHandle(handle)
            try:
                self.delete_named(name)
            except Exception:
                pass
            raise
        opened = _open_relative(self.handle, name, directory=False, access=0x12019F)
        try:
            if _read_handle(opened) != data:
                raise WindowsFileSecurityError("bound file did not retain its contents")
            self.created[name] = _file_identity(opened)
        finally:
            import win32file
            win32file.CloseHandle(opened)

    def identity_named(self, name: str) -> tuple:
        if not self.same_object():
            raise WindowsFileSecurityError("bound directory no longer names the validated object")
        handle = _open_relative(self.handle, name, directory=False, access=0x100080)
        try:
            return _file_identity(handle)
        finally:
            import win32file
            win32file.CloseHandle(handle)

    def read_file(self, name: str) -> bytes:
        if not self.same_object():
            raise WindowsFileSecurityError("bound directory no longer names the validated object")
        handle = _open_relative(self.handle, name, directory=False, access=0x12019F)
        try:
            _file_identity(handle)
            _security_from_handle(handle, directory=False)
            return _read_handle(handle)
        finally:
            import win32file
            win32file.CloseHandle(handle)

    def link_named(self, existing_name: str, new_name: str) -> None:
        """Add a hard link inside this directory object. A substituted path is not used."""
        if not self.same_object() or not new_name or "/" in new_name or "\\" in new_name:
            raise WindowsFileSecurityError("refusing to link through a directory that was substituted")
        import ctypes
        import ctypes.wintypes as wintypes
        source = _open_relative(self.handle, existing_name, directory=False, access=0x12019F)
        try:
            class Header(ctypes.Structure):
                _pack_ = 1
                _fields_ = [("ReplaceIfExists", wintypes.BOOLEAN), ("_pad", ctypes.c_byte * 7),
                            ("RootDirectory", wintypes.HANDLE), ("FileNameLength", wintypes.ULONG)]

            encoded = new_name.encode("utf-16-le")
            size = ctypes.sizeof(Header) + len(encoded)
            buffer = (ctypes.c_char * size)()
            header = Header.from_buffer(buffer)
            header.ReplaceIfExists = False
            header.RootDirectory = wintypes.HANDLE(int(self.handle))
            header.FileNameLength = len(encoded)
            ctypes.memmove(ctypes.addressof(buffer) + ctypes.sizeof(Header), encoded, len(encoded))
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

            class IO_STATUS_BLOCK(ctypes.Structure):
                _fields_ = [("Pointer", ctypes.c_void_p), ("Information", ctypes.c_void_p)]

            status_block = IO_STATUS_BLOCK()
            status = ntdll.NtSetInformationFile(
                wintypes.HANDLE(int(source)), ctypes.byref(status_block), buffer, size, 11)
            if (status & 0xFFFFFFFF) >= 0x80000000:
                raise WindowsFileSecurityError("bound file could not be linked", status=status & 0xFFFFFFFF)
        finally:
            import win32file
            win32file.CloseHandle(source)

    def make_directory(self, name: str) -> "BoundDirectory":
        if not self.same_object():
            raise WindowsFileSecurityError("bound directory no longer names the validated object")
        handle = _create_relative(self.handle, name, directory=True)
        try:
            identity = _file_identity(handle)
        except Exception:
            import win32file
            win32file.CloseHandle(handle)
            raise
        return BoundDirectory(handle, identity, name)

    def delete_named(self, name: str, expected_identity: tuple | None = None) -> None:
        """Delete one child of this directory object.

        The child is opened relative to the held directory. Its file identity
        is compared before FileDispositionInfo is set, so a different file that
        now uses the name is closed without being deleted.
        """
        if not self.same_object():
            raise WindowsFileSecurityError("refusing to delete through a directory that was substituted")
        import ctypes
        import ctypes.wintypes as wintypes
        handle = _open_relative(self.handle, name, directory=False, access=0x110080)
        try:
            identity = _file_identity(handle)
            if expected_identity is not None and identity != expected_identity:
                raise WindowsFileSecurityError("refusing to delete a substituted file")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class FILE_DISPOSITION_INFO(ctypes.Structure):
                _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

            info = FILE_DISPOSITION_INFO(True)
            if not kernel32.SetFileInformationByHandle(
                    wintypes.HANDLE(int(handle)), 4, ctypes.byref(info), ctypes.sizeof(info)):
                raise WindowsFileSecurityError("bound file could not be removed", status=ctypes.get_last_error())
        finally:
            import win32file
            win32file.CloseHandle(handle)

    def delete_self(self) -> None:
        if not self.same_object():
            raise WindowsFileSecurityError("refusing to delete a substituted directory")
        import ctypes
        import ctypes.wintypes as wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class FILE_DISPOSITION_INFO(ctypes.Structure):
            _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

        info = FILE_DISPOSITION_INFO(True)
        if not kernel32.SetFileInformationByHandle(wintypes.HANDLE(int(self.handle)), 4, ctypes.byref(info), ctypes.sizeof(info)):
            raise WindowsFileSecurityError("bound directory could not be removed")
        self.close()


def open_bound_directory(path, *, share_delete: bool = True) -> BoundDirectory:
    """Open a directory without following a reparse point.

    ``share_delete`` lets another caller open the same directory. Cleanup of a
    snapshot passes False so the name cannot be replaced while the handle is
    used to delete that object. Desired access is ``DIRECTORY_HANDLE_ACCESS``.
    """
    assert_ancestry_not_substitutable(path)
    directory = verify_private_directory(path)
    import win32file
    share = 0x00000001 | 0x00000002 | (0x00000004 if share_delete else 0)
    handle = win32file.CreateFile(
        str(directory),
        DIRECTORY_HANDLE_ACCESS,
        share,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    try:
        identity = _file_identity(handle)
        _security_from_handle(handle, directory=True)
    except Exception:
        win32file.CloseHandle(handle)
        raise
    return BoundDirectory(handle, identity, directory.name)


def path_file_identity(path) -> tuple:
    """File id of a path opened without following a reparse point."""
    import win32file
    handle = win32file.CreateFile(
        str(path), 0x80, 0x00000001 | 0x00000002 | 0x00000004, None, 3, 0x02000000 | 0x00200000, None)
    try:
        return _file_identity(handle)
    finally:
        win32file.CloseHandle(handle)


def _file_identity(handle) -> tuple:
    import ctypes
    import ctypes.wintypes as wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class FILETIME(ctypes.Structure):
        _fields_ = [("Low", wintypes.DWORD), ("High", wintypes.DWORD)]

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FILETIME), ("ftLastAccessTime", FILETIME), ("ftLastWriteTime", FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD), ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD),
        ]

    info = BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(wintypes.HANDLE(int(handle)), ctypes.byref(info)):
        raise WindowsFileSecurityError("bound object identity is unavailable")
    if info.dwFileAttributes & _REPARSE:
        raise WindowsFileSecurityError("bound object is a reparse point")
    return (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow)


def _security_from_handle(handle, *, directory: bool) -> None:
    win32security, ntsecuritycon = _windows_security()
    security = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    if isinstance(security, tuple):
        owner, _group, dacl = security[0], security[1], security[2]
    else:
        owner = security.GetSecurityDescriptorOwner()
        dacl = security.GetSecurityDescriptorDacl()
    trusted = trusted_identity_sids()
    if win32security.ConvertSidToStringSid(owner) not in trusted - {_OWNER_RIGHTS}:
        raise WindowsFileSecurityError("bound object has an untrusted owner")
    if dacl is None:
        raise WindowsFileSecurityError("bound object has no access list")
    for index in range(dacl.GetAceCount()):
        header, mask, sid = _read_ace(dacl, index)
        ace_type, flags = header
        if flags & _INHERIT_ONLY:
            continue
        identity = win32security.ConvertSidToStringSid(sid)
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in trusted:
            raise WindowsFileSecurityError("bound object grants unexpected access")
        if (mask & ntsecuritycon.FILE_ALL_ACCESS) != ntsecuritycon.FILE_ALL_ACCESS:
            raise WindowsFileSecurityError("bound object grants unexpected access")
        if directory and not (flags & win32security.OBJECT_INHERIT_ACE and flags & win32security.CONTAINER_INHERIT_ACE):
            raise WindowsFileSecurityError("bound directory does not protect child objects")


def _private_security_descriptor(*, directory: bool):
    win32security, _ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    user = win32security.ConvertSidToStringSid(user_sid)
    inherit = "OICI" if directory else ""
    aces = []
    for sid in (_SYSTEM, _ADMINS, user):
        if sid not in {item.split(";;;")[-1] for item in aces}:
            aces.append("(A;%s;FA;;;%s)" % (inherit, sid))
    sddl = "O:%sD:P%s" % (user, "".join(aces))
    return win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1), sddl


def _sd_pointer(sd):
    win32security, _ntsecuritycon = _windows_security()
    sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        sd, 1, win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    advapi32 = __import__("ctypes").WinDLL("advapi32", use_last_error=True)
    kernel32 = __import__("ctypes").WinDLL("kernel32", use_last_error=True)
    pointer = __import__("ctypes").c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, __import__("ctypes").byref(pointer), None):
        raise WindowsFileSecurityError("private security descriptor could not be formed")
    return pointer, kernel32


def _create_relative(root_handle, name: str, *, directory: bool):
    import ctypes
    import ctypes.wintypes as wintypes
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UNICODE_STRING)), ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p),
        ]

    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [("Pointer", ctypes.c_void_p), ("Information", ctypes.c_void_p)]

    sd, _sddl = _private_security_descriptor(directory=directory)
    sd_pointer, kernel32 = _sd_pointer(sd)
    try:
        character_buffer = ctypes.create_unicode_buffer(name)
        name_string = UNICODE_STRING(len(name) * 2, (len(name) + 1) * 2, ctypes.cast(character_buffer, wintypes.LPWSTR))
        attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), wintypes.HANDLE(int(root_handle)),
                                       ctypes.pointer(name_string), 0x40, sd_pointer, None)
        status_block = IO_STATUS_BLOCK()
        handle = wintypes.HANDLE()
        options = 0x20 | 0x00200000 | (0x1 if directory else 0x40)
        # A file is created without DELETE access so another opener can share it.
        # A directory is created without delete sharing so its name cannot move
        # while this handle is open.
        access = DIRECTORY_HANDLE_ACCESS if directory else 0x12019F
        share = 0x3
        status = ntdll.NtCreateFile(
            ctypes.byref(handle), ctypes.c_uint32(access), ctypes.byref(attributes), ctypes.byref(status_block),
            None, ctypes.c_uint32(0x80), ctypes.c_uint32(share), ctypes.c_uint32(2), ctypes.c_uint32(options), None,
            ctypes.c_uint32(0))
        if (status & 0xFFFFFFFF) >= 0x80000000:
            raise WindowsFileSecurityError("bound object could not be created")
        return handle.value
    finally:
        kernel32.LocalFree(sd_pointer)


def _open_relative(root_handle, name: str, *, directory: bool, delete: bool = False,
                  access: int | None = None):
    import ctypes
    import ctypes.wintypes as wintypes
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UNICODE_STRING)), ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p),
        ]

    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [("Pointer", ctypes.c_void_p), ("Information", ctypes.c_void_p)]

    if access is None:
        access = DIRECTORY_HANDLE_ACCESS if directory else 0x12019F
    character_buffer = ctypes.create_unicode_buffer(name)
    name_string = UNICODE_STRING(len(name) * 2, (len(name) + 1) * 2, ctypes.cast(character_buffer, wintypes.LPWSTR))
    attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), wintypes.HANDLE(int(root_handle)),
                                   ctypes.pointer(name_string), 0x40, None, None)
    status_block = IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()
    options = 0x20 | 0x00200000 | (0x1 if directory else 0x40)
    if delete:
        options |= 0x1000
    status = ntdll.NtCreateFile(
        ctypes.byref(handle), ctypes.c_uint32(access), ctypes.byref(attributes), ctypes.byref(status_block),
        None, ctypes.c_uint32(0x80), ctypes.c_uint32(0x3), ctypes.c_uint32(1), ctypes.c_uint32(options), None,
        ctypes.c_uint32(0))
    if (status & 0xFFFFFFFF) >= 0x80000000:
        raise WindowsFileSecurityError("bound object could not be opened", status=status & 0xFFFFFFFF)
    return handle.value


def _write_handle(handle, data: bytes) -> None:
    """Write through the open handle. The handle is closed before this returns."""
    import msvcrt
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_BINARY)
    except Exception:
        import win32file
        win32file.CloseHandle(handle)
        raise
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if not isinstance(written, int) or written <= 0 or written > len(view):
                raise WindowsFileSecurityError("bound file write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_handle(handle) -> bytes:
    import ctypes
    import ctypes.wintypes as wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    chunks = []
    while True:
        buffer = ctypes.create_string_buffer(65536)
        read = ctypes.wintypes.DWORD()
        if not kernel32.ReadFile(wintypes.HANDLE(int(handle)), buffer, 65536, ctypes.byref(read), None):
            raise WindowsFileSecurityError("bound file could not be read")
        if read.value == 0:
            break
        chunks.append(buffer.raw[:read.value])
    return b"".join(chunks)


def parent_has_everyone_write(path) -> bool:
    """True when a directory grants Everyone write. Used to refuse an unsafe lock parent."""
    if os.name != "nt":
        mode = Path(path).stat().st_mode
        return bool(mode & 0o002)
    win32security, ntsecuritycon = _windows_security()
    descriptor = _security_descriptor(Path(path))
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        return True
    everyone = "S-1-1-0"
    write = ntsecuritycon.FILE_WRITE_DATA | ntsecuritycon.FILE_APPEND_DATA | ntsecuritycon.FILE_WRITE_ATTRIBUTES
    for index in range(dacl.GetAceCount()):
        header, mask, sid = _read_ace(dacl, index)
        ace_type, _flags = header
        if (ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE
                and win32security.ConvertSidToStringSid(sid) == everyone
                and mask & write):
            return True
    return False


def protect_private_secret_file(path) -> Path:
    """Restrict a secret file to the current user, SYSTEM, and Administrators.

    This is the unelevated custody check for a development key file. It does
    not claim the installed SYSTEM-owned DACL. That remains a physical gate.
    """
    file_path = _absolute_local_path(path)
    _assert_no_reparse(file_path)
    if not file_path.is_file():
        raise WindowsFileSecurityError("protected file does not exist")
    win32security, ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
    dacl = win32security.ACL()
    seen = set()
    for sid in (user_sid, system_sid, admin_sid):
        identity = win32security.ConvertSidToStringSid(sid)
        if identity in seen:
            continue
        seen.add(identity)
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS, 0, ntsecuritycon.FILE_ALL_ACCESS, sid)
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(user_sid, False)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
    win32security.SetFileSecurity(
        str(file_path),
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION |
        win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        descriptor,
    )
    verify_verifier_key_custody(file_path, production=False)
    return file_path


def verify_verifier_key_custody(path, *, production: bool) -> Path:
    """Reject reparse points, unexpected types, and permissive DACLs before a key is read.

    Production accepts only the installed SYSTEM/Administrators DACL. Other
    file-backed processes also accept a protected DACL limited to the current
    user, SYSTEM, and Administrators. Parent reparse points are refused.
    """
    file_path = _absolute_local_path(path)
    _assert_no_reparse(file_path)
    if not file_path.is_file():
        raise WindowsFileSecurityError("protected file does not exist")
    if os.name != "nt":
        mode = file_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise WindowsFileSecurityError("protected path grants unexpected access")
        return file_path
    if production:
        verify_directory(file_path.parent)
        _verify_acl(file_path, directory=False)
        return file_path
    try:
        _verify_acl(file_path, directory=False)
        return file_path
    except WindowsFileSecurityError:
        _verify_private_key_acl(file_path)
        return file_path


def _verify_private_key_acl(path: Path) -> None:
    win32security, ntsecuritycon = _windows_security()
    import win32api
    user_sid, _domain, _account_type = win32security.LookupAccountName(None, win32api.GetUserName())
    allowed = {
        win32security.ConvertSidToStringSid(user_sid),
        _SYSTEM,
        _ADMINS,
    }
    descriptor = _security_descriptor(path)
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    if owner not in allowed:
        raise WindowsFileSecurityError("protected path has an untrusted owner")
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if not control & win32security.SE_DACL_PROTECTED:
        raise WindowsFileSecurityError("protected path inherits access rules")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or dacl.GetAceCount() == 0 or dacl.GetAceCount() > 3:
        raise WindowsFileSecurityError("protected path has unexpected access rules")
    seen = set()
    for index in range(dacl.GetAceCount()):
        header, mask, sid = _read_ace(dacl, index)
        ace_type, _flags = header
        identity = win32security.ConvertSidToStringSid(sid)
        if (ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in allowed
                or identity in seen or mask & ntsecuritycon.FILE_ALL_ACCESS != ntsecuritycon.FILE_ALL_ACCESS):
            raise WindowsFileSecurityError("protected path grants unexpected access")
        seen.add(identity)
    if _SYSTEM not in seen or _ADMINS not in seen:
        raise WindowsFileSecurityError("protected path lacks SYSTEM or Administrators access")


def protect_secret_file(path) -> Path:
    """Restrict an existing secret file to SYSTEM and Administrators.

    The parent directory is not required to already be a protected agent
    directory. Setting the owner to Administrators requires an elevated token;
    failure is reported without including file contents.
    """
    file_path = _absolute_local_path(path)
    _assert_no_reparse(file_path)
    if not file_path.is_file():
        raise WindowsFileSecurityError("protected file does not exist")
    _set_private_acl(file_path, directory=False)
    _verify_acl(file_path, directory=False)
    return file_path


def verify_protected_file(path) -> Path:
    file_path = _absolute_local_path(path)
    verify_directory(file_path.parent)
    _assert_no_reparse(file_path)
    if not file_path.is_file():
        raise WindowsFileSecurityError("protected file does not exist")
    _verify_acl(file_path, directory=False)
    return file_path


def verify_protected_child_file(path) -> Path:
    """Verify a file inheriting only SYSTEM/Administrators from a protected parent.

    SQLite creates its database with inherited access rules under the installed
    protected data directory. This accepts that existing custody without
    changing the file ACL, while rejecting any extra principal or reparse point.
    Private keys should continue to use ``verify_protected_file``.
    """
    file_path = _absolute_local_path(path)
    verify_directory(file_path.parent)
    _assert_no_reparse(file_path)
    if not file_path.is_file():
        raise WindowsFileSecurityError("protected file does not exist")
    win32security, ntsecuritycon = _windows_security()
    descriptor = _security_descriptor(file_path)
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    if owner not in _ALLOWED:
        raise WindowsFileSecurityError("protected file has an untrusted owner")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or dacl.GetAceCount() != 2:
        raise WindowsFileSecurityError("protected file has unexpected access rules")
    seen = set()
    for index in range(2):
        header, mask, sid = _read_ace(dacl, index)
        identity = win32security.ConvertSidToStringSid(sid)
        if (header[0] != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in _ALLOWED
                or identity in seen or mask & ntsecuritycon.FILE_ALL_ACCESS != ntsecuritycon.FILE_ALL_ACCESS):
            raise WindowsFileSecurityError("protected file grants unexpected access")
        seen.add(identity)
    if seen != _ALLOWED:
        raise WindowsFileSecurityError("protected file lacks SYSTEM or Administrators access")
    return file_path


def atomic_write_protected(path, contents: bytes) -> None:
    """Write bytes in a verified directory, protect temp, then atomically swap."""
    if not isinstance(contents, bytes):
        raise TypeError("protected contents must be bytes")
    file_path = _absolute_local_path(path)
    if not _SAFE_FILENAME.fullmatch(file_path.name):
        raise WindowsFileSecurityError("protected filename is invalid")
    verify_directory(file_path.parent)
    if file_path.exists():
        verify_protected_file(file_path)
    temporary = file_path.with_name(file_path.name + "." + uuid4().hex + ".tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        _assert_no_reparse(temporary)
        _set_private_acl(temporary, directory=False)
        verify_protected_file(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        verify_directory(file_path.parent)
        os.replace(temporary, file_path)
        flush_published(file_path)
        verify_protected_file(file_path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def atomic_create_protected(path, contents: bytes) -> None:
    """Publish a protected new file atomically, refusing an existing target.

    A same-directory hard link makes the fully written, ACL-verified temporary
    file visible at the target only if that name is still absent. Unlike
    ``atomic_write_protected``, this operation can never replace a key that a
    concurrent TLS initializer has already published.
    """
    if not isinstance(contents, bytes):
        raise TypeError("protected contents must be bytes")
    file_path = _absolute_local_path(path)
    if not _SAFE_FILENAME.fullmatch(file_path.name):
        raise WindowsFileSecurityError("protected filename is invalid")
    verify_directory(file_path.parent)
    temporary = file_path.with_name(file_path.name + "." + uuid4().hex + ".tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        _assert_no_reparse(temporary)
        _set_private_acl(temporary, directory=False)
        verify_protected_file(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        verify_directory(file_path.parent)
        # os.link fails with FileExistsError if the destination name exists;
        # source and destination are on the same protected filesystem.
        os.link(temporary, file_path)
        flush_published(file_path)
        verify_protected_file(file_path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def flush_published(path) -> FlushResult:
    """Flush a published file. The file flush is required; directory metadata is not.

    On Windows, ``os.fsync`` is ``FlushFileBuffers``. A successful file flush
    asks the file system to persist that file. It is not a proof that a disk
    write cache survived power loss. Opening a parent directory for
    ``FlushFileBuffers`` commonly fails with access denied, so directory
    metadata is reported as unconfirmed instead of being treated as durable.
    That limitation is an isolated physical gate, not a successful
    flush. Required file open or flush failures raise ``DurabilityError`` and
    must stop the caller before any network publication. A later retry must flush
    the same file again. Decrypting the file is not a durability check. Directory
    metadata and hardware power loss remain a physical gate.
    """
    target = _absolute_local_path(path)
    _fsync_required(target)
    confirmed, limitation = _fsync_directory_best_effort(target.parent)
    return FlushResult(True, confirmed, limitation)


def require_durable_file(path) -> FlushResult:
    """Retry the required file flush. A successful read is not durability.

    Directory metadata may still be unconfirmed. That is a physical gate, not
    permission to skip the file flush.
    """
    result = flush_published(path)
    if not result.file_durable:
        raise DurabilityError("required file durability flush failed")
    return result


def _fsync_required(path: Path) -> None:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    descriptor = None
    try:
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise DurabilityError("required file durability flush failed") from error
        try:
            os.fsync(descriptor)
        except OSError as error:
            raise DurabilityError("required file durability flush failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory_best_effort(path: Path) -> tuple[bool, str | None]:
    """Try to flush directory metadata. Windows often cannot; that is not success."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    descriptor = None
    try:
        try:
            descriptor = os.open(path, flags)
            os.fsync(descriptor)
        except OSError:
            return False, "ntfs_directory_metadata_not_flushable"
        return True, None
    finally:
        if descriptor is not None:
            os.close(descriptor)
