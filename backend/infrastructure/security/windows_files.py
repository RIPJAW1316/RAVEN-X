"""Fail-closed Windows filesystem protection for machine credentials and keys.

Only SYSTEM and the local Administrators group may own/read/write a protected
object. The directory DACL is explicit and protected from inheritance. Callers
must run elevated when creating or repairing a directory.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from uuid import uuid4


_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_ALLOWED = frozenset({_SYSTEM, _ADMINS})
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")


class WindowsFileSecurityError(RuntimeError):
    pass


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
        header, mask, sid = dacl.GetAce(index)
        ace_type, flags = header
        identity = win32security.ConvertSidToStringSid(sid)
        if (ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in _ALLOWED or
                identity in seen or mask & ntsecuritycon.FILE_ALL_ACCESS != ntsecuritycon.FILE_ALL_ACCESS):
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


def verify_protected_file(path) -> Path:
    file_path = _absolute_local_path(path)
    verify_directory(file_path.parent)
    _assert_no_reparse(file_path)
    if not file_path.is_file():
        raise WindowsFileSecurityError("protected file does not exist")
    _verify_acl(file_path, directory=False)
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
        verify_protected_file(file_path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
