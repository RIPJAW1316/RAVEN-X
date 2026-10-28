"""Persistent HMAC verifier-key custody.

The key is not a database secret and must never be printed or logged. Its
SHA-256 identity is stored in ``ravenx_verifier_keys`` so a later process can
detect a missing, replaced, or environment-substituted key before it serves
traffic.

Backup the key file and the database together. There is no in-place rotation:
a different key cannot verify existing ``token-hmac-v2`` credentials. If the
key is lost, do not generate a replacement over a database that may contain
HMAC credentials. Recovery is an operator procedure: restore the original key
bytes that match the stored identity, or revoke those credentials and
re-enroll. This module does not perform that recovery.

Ephemeral keys are allowed only for an explicit in-memory test database
(``RAVENX_VERIFIER_KEY_MODE=ephemeral`` and a ``:memory:`` SQLite path). Every
file-backed database, including development, uses the sidecar and the stored
identity. A published key file is never deleted after another process could
have observed it.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
from uuid import uuid4


class VerifierKeyError(RuntimeError):
    """Startup or custody failure. Messages never include key bytes."""


_KEY_BYTES = 32
_IDENTITY_ALGORITHM = "sha256-v1"


def verifier_key_id(key: bytes) -> str:
    """Non-secret fingerprint of a verifier key."""
    if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
        raise VerifierKeyError("credential verifier key is not usable")
    return hashlib.sha256(key).hexdigest()


def load_verifier_key(path) -> bytes:
    """Read an existing 32-byte key. Never creates or logs it."""
    file_path = Path(path)
    if not file_path.is_file():
        raise VerifierKeyError("credential verifier key file is missing")
    try:
        data = file_path.read_bytes()
    except OSError as error:
        raise VerifierKeyError("credential verifier key file is not usable") from error
    if len(data) != _KEY_BYTES:
        raise VerifierKeyError("credential verifier key file is not usable")
    return data


def load_or_create_verifier_key(path) -> bytes:
    """Load an existing key.

    Implicit creation is refused. A missing sidecar must go through
    ``prepare_persistent_verifier_key``, which creates a key only for an empty
    database and records its identity.
    """
    if not Path(path).is_file():
        raise VerifierKeyError("refusing to create a credential verifier key implicitly")
    return load_verifier_key(path)


def resolve_verifier_key(*, environ=None, default_path=None) -> bytes:
    """Return an already configured key.

    An ephemeral key is returned only for an explicit in-memory test database.
    A file-backed path never receives one, in development or production.
    """
    environ = os.environ if environ is None else environ
    environment = (environ.get("RAVENX_ENVIRONMENT") or "development").strip().lower()
    mode = (environ.get("RAVENX_VERIFIER_KEY_MODE") or "").strip().lower()
    database = (environ.get("RAVENX_DATABASE_PATH") or "").strip()
    memory = database == ":memory:"
    file_backed = bool(database) and not memory
    sidecar = Path(database).expanduser().with_name("credential-hmac.key") if file_backed else None
    if default_path is not None and sidecar is not None and Path(default_path) != sidecar:
        raise VerifierKeyError("credential verifier key configuration is ambiguous")
    explicit = _explicit_key(environ)
    if mode == "ephemeral":
        if environment == "production" or file_backed or default_path is not None or not memory:
            raise VerifierKeyError(
                "ephemeral verifier keys are allowed only for an explicit in-memory test database")
        if explicit is not None:
            raise VerifierKeyError(
                "ephemeral verifier keys are allowed only for an explicit in-memory test database")
        return secrets.token_bytes(_KEY_BYTES)
    path = Path(default_path) if default_path is not None else sidecar
    if file_backed:
        database_path = Path(database).expanduser()
        if not database_path.is_file() or path is None or not path.is_file():
            raise VerifierKeyError("persistent verifier key is not available")
        verify_existing_verifier_key(path, environment == "production")
        key = load_verifier_key(path)
        if explicit is not None and verifier_key_id(explicit) != verifier_key_id(key):
            raise VerifierKeyError("configured verifier key does not match the persistent key file")
        try:
            _hmac_count, identity = _read_custody(database_path)
        except sqlite3.Error as error:
            raise VerifierKeyError("database verifier-key identity is not usable") from error
        if identity is None or identity != verifier_key_id(key):
            raise VerifierKeyError("credential verifier key does not match the database identity")
        return key
    raise VerifierKeyError("database identity is not configured for verifier-key resolution")


def enforce_verifier_key_file_acl(path: Path, production: bool = False) -> None:
    """Restrict a key file before it is published. The key itself is never part of an error."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        if (path.stat().st_mode & 0o077) != 0:
            raise VerifierKeyError("credential verifier key file could not be protected")
        return
    try:
        from .windows_files import protect_private_secret_file, protect_secret_file
        if production:
            protect_secret_file(path)
        else:
            try:
                protect_secret_file(path)
            except Exception:
                protect_private_secret_file(path)
    except VerifierKeyError:
        raise
    except Exception as error:
        raise VerifierKeyError("credential verifier key file could not be protected") from error


def verify_existing_verifier_key(path: Path, production: bool = False) -> None:
    """Refuse to read a key whose path or DACL is not trustworthy."""
    if os.name != "nt":
        mode = Path(path).stat().st_mode & 0o777
        if mode & 0o077:
            raise VerifierKeyError("credential verifier key file is not usable")
        return
    try:
        from .windows_files import verify_verifier_key_custody
        verify_verifier_key_custody(path, production=production)
    except VerifierKeyError:
        raise
    except Exception as error:
        raise VerifierKeyError("credential verifier key file is not usable") from error


def prepare_persistent_verifier_key(database_path, *, environ=None, environment: str = "production") -> bytes:
    """Load or bootstrap the key for one persistent SQLite file.

    The key file and its database identity are published under an OS file lock.
    Bootstrap happens only when the database has no verifier-key identity and
    no active HMAC credentials. A missing key is never recreated over HMAC
    state. After the final name is published, this function does not delete it:
    another process may already have bound that file.
    """
    environ = os.environ if environ is None else environ
    production = environment == "production"
    if production and (environ.get("RAVENX_VERIFIER_KEY_MODE") or "").strip().lower() == "ephemeral":
        raise VerifierKeyError("ephemeral verifier keys are refused in production")
    path = Path(database_path)
    if not path.is_file():
        raise VerifierKeyError("database file does not exist; refusing to create a verifier key")
    key_path = path.with_name("credential-hmac.key")
    lock_fd = _acquire_key_lock(key_path.with_name("credential-hmac.key.lock"))
    try:
        directory = lock_fd[1] if isinstance(lock_fd, tuple) else None
        return _prepare_locked(path, key_path, environ, production=production, directory=directory)
    finally:
        _release_key_lock(lock_fd)


def bind_control_plane_verifier_key(database_manager, enrollment_service, *, environment: str, environ=None) -> None:
    """Bind the process verifier key before the API reports ready.

    A file-backed database always uses the persistent sidecar. An ephemeral key
    is issued only for an explicit in-memory test database.
    """
    environ = os.environ if environ is None else environ
    if database_manager.config.get("type", "sqlite") != "sqlite":
        raise VerifierKeyError("persistent verifier keys for this database type are not implemented")
    database_path = _sqlite_file(database_manager, environ)
    mode = (environ.get("RAVENX_VERIFIER_KEY_MODE") or "").strip().lower()
    if database_path is None:
        if environment == "production" or mode != "ephemeral":
            raise VerifierKeyError(
                "ephemeral verifier keys are allowed only for an explicit in-memory test database")
        enrollment_service.bind_verifier_key(secrets.token_bytes(_KEY_BYTES))
        return
    enrollment_service.bind_verifier_key(
        prepare_persistent_verifier_key(database_path, environ=environ, environment=environment))


def _explicit_key(environ) -> bytes | None:
    raw = (environ.get("RAVENX_CREDENTIAL_VERIFIER_KEY") or "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError as error:
        raise VerifierKeyError("credential verifier key is not usable") from error
    if len(key) != _KEY_BYTES:
        raise VerifierKeyError("credential verifier key is not usable")
    return key


def _sqlite_file(database_manager, environ) -> Path | None:
    override = environ.get("RAVENX_DATABASE_PATH")
    if override is not None and not str(override).strip():
        raise VerifierKeyError("RAVENX_DATABASE_PATH must not be empty")
    selected = override if override is not None else database_manager.config.get("sqlite_path", "data/raven_x.db")
    if str(selected) == ":memory:":
        return None
    path = Path(str(selected)).expanduser()
    if not path.is_absolute():
        from ...core.database.database import DEFAULT_CONFIG_PATH, PROJECT_ROOT
        base = PROJECT_ROOT if database_manager.config_path == DEFAULT_CONFIG_PATH else database_manager.config_path.parent
        path = base / path
    return path.resolve()


def _connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA query_only=OFF")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def _read_custody(database_path: Path) -> tuple[int, str | None]:
    connection = sqlite3.connect(f"file:{database_path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        return _custody(connection)
    finally:
        connection.close()


def _custody(connection: sqlite3.Connection) -> tuple[int, str | None]:
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    hmac_count = 0
    if "endpoint_credentials" in tables:
        hmac_count = int(connection.execute(
            "SELECT COUNT(*) FROM endpoint_credentials "
            "WHERE status = 'active' AND verifier LIKE 'token-hmac-v2$%'"
        ).fetchone()[0])
    identity = None
    if "ravenx_verifier_keys" in tables:
        row = connection.execute("SELECT key_id FROM ravenx_verifier_keys WHERE id = 1").fetchone()
        identity = None if row is None else str(row[0])
    return hmac_count, identity


def _require_matching_identity(database_path: Path, key: bytes) -> None:
    identity = verifier_key_id(key)
    connection = _connect(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        hmac_count, stored = _custody(connection)
        if stored is not None and stored != identity:
            raise VerifierKeyError("credential verifier key does not match the database identity")
        if stored is None and hmac_count:
            raise VerifierKeyError("verifier-key identity is missing for existing HMAC credentials")
        if stored is None:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS ravenx_verifier_keys ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), "
                "algorithm VARCHAR(40) NOT NULL, "
                "key_id VARCHAR(64) NOT NULL, "
                "created_at DATETIME NOT NULL)"
            )
            connection.execute(
                "INSERT INTO ravenx_verifier_keys (id, algorithm, key_id, created_at) VALUES (1, ?, ?, datetime('now'))",
                (_IDENTITY_ALGORITHM, identity),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _prepare_locked(database_path: Path, key_path: Path, environ, *, production: bool, directory=None) -> bytes:
    explicit = _explicit_key(environ)
    if directory is not None:
        return _prepare_locked_bound(database_path, key_path, directory, explicit, production=production)
    if key_path.is_file():
        file_key = _read_verified_key(key_path, production=production)
        if explicit is not None and verifier_key_id(explicit) != verifier_key_id(file_key):
            raise VerifierKeyError("configured verifier key does not match the persistent key file")
        configured = explicit if explicit is not None else file_key
        if verifier_key_id(configured) != verifier_key_id(file_key):
            raise VerifierKeyError("credential verifier key does not match the database identity")
        _require_matching_identity(database_path, file_key)
        return file_key
    hmac_count, identity = _read_custody(database_path)
    if hmac_count or identity:
        raise VerifierKeyError("credential verifier key is missing and will not be regenerated")
    key = explicit if explicit is not None else secrets.token_bytes(_KEY_BYTES)
    temporary = key_path.with_name("credential-hmac.key." + uuid4().hex + ".tmp")
    published = False
    try:
        _write_complete_temp(temporary, key)
        enforce_verifier_key_file_acl(temporary, production)
        if _read_verified_key(temporary, production=production) != key:
            raise VerifierKeyError("credential verifier key file is not usable")
        try:
            os.link(temporary, key_path)
        except FileExistsError:
            temporary.unlink(missing_ok=True)
            existing = _read_verified_key(key_path, production=production)
            _require_matching_identity(database_path, existing)
            return existing
        published = True
        stored = _read_verified_key(key_path, production=production)
        if stored != key:
            raise VerifierKeyError("credential verifier key file is not usable")
        _require_matching_identity(database_path, stored)
        return stored
    except Exception:
        if temporary.exists() and not published:
            temporary.unlink()
        raise
    finally:
        if published and temporary.exists():
            temporary.unlink()


def _read_verified_key(path: Path, *, production: bool) -> bytes:
    verify_existing_verifier_key(path, production)
    key = load_verifier_key(path)
    reopened = path.read_bytes()
    if reopened != key or len(reopened) != _KEY_BYTES:
        raise VerifierKeyError("credential verifier key file is not usable")
    return reopened


def _write_complete_temp(path: Path, key: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, key)
        os.fsync(descriptor)
    except Exception as error:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        if isinstance(error, VerifierKeyError):
            raise
        raise VerifierKeyError("credential verifier key file is not usable") from error
    else:
        os.close(descriptor)
    reopened = path.read_bytes()
    if reopened != key:
        path.unlink(missing_ok=True)
        raise VerifierKeyError("credential verifier key file is not usable")


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if not isinstance(written, int) or written <= 0 or written > len(view):
            raise VerifierKeyError("credential verifier key file is not usable")
        view = view[written:]


lock_fault_hooks = []


def _lock_fault(stage: str, info) -> None:
    for hook in tuple(lock_fault_hooks):
        hook(stage, info)


def _native_path_errors():
    """OSError plus the pywin32 error type, which does not subclass OSError."""
    if os.name != "nt":
        return (OSError,)
    try:
        import pywintypes
    except ImportError:
        return (OSError,)
    native = pywintypes.error
    if issubclass(native, OSError):
        return (OSError,)
    return (OSError, native)


def _require_bound_parent(parent, parent_path: Path) -> None:
    from .windows_files import path_file_identity
    if parent is None or not parent.same_object():
        raise VerifierKeyError("credential verifier key lock parent was substituted")
    try:
        current = path_file_identity(parent_path)
    except _native_path_errors() as error:
        raise VerifierKeyError("credential verifier key lock parent was substituted") from error
    if current != parent.identity:
        raise VerifierKeyError("credential verifier key lock parent was substituted")


def _prepare_locked_bound(database_path: Path, key_path: Path, directory, explicit, *, production: bool) -> bytes:
    """Publish or reload the key through the directory object that holds the lock."""
    from .windows_files import WindowsFileSecurityError
    _require_bound_parent(directory, key_path.parent)
    missing = {0xC0000034, 0xC000003A}
    try:
        file_key = directory.read_file(key_path.name)
    except WindowsFileSecurityError as error:
        if error.status not in missing:
            raise VerifierKeyError("credential verifier key file is not usable") from error
        file_key = None
    if file_key is not None:
        if len(file_key) != _KEY_BYTES:
            raise VerifierKeyError("credential verifier key file is not usable")
        if explicit is not None and verifier_key_id(explicit) != verifier_key_id(file_key):
            raise VerifierKeyError("configured verifier key does not match the persistent key file")
        _require_matching_identity(database_path, file_key)
        return file_key
    hmac_count, identity = _read_custody(database_path)
    if hmac_count or identity:
        raise VerifierKeyError("credential verifier key is missing and will not be regenerated")
    key = explicit if explicit is not None else secrets.token_bytes(_KEY_BYTES)
    temporary_name = key_path.name + "." + uuid4().hex + ".tmp"
    published = False
    try:
        _require_bound_parent(directory, key_path.parent)
        try:
            directory.write_file(temporary_name, key)
        except OSError as error:
            raise VerifierKeyError("credential verifier key file is not usable") from error
        if production:
            _require_bound_parent(directory, key_path.parent)
            enforce_verifier_key_file_acl(key_path.with_name(temporary_name), production)
        if directory.read_file(temporary_name) != key:
            raise VerifierKeyError("credential verifier key file is not usable")
        try:
            directory.link_named(temporary_name, key_path.name)
        except WindowsFileSecurityError as error:
            if error.status not in (183, 0xC0000035):
                raise VerifierKeyError("credential verifier key file is not usable") from error
            existing = directory.read_file(key_path.name)
            if len(existing) != _KEY_BYTES:
                raise VerifierKeyError("credential verifier key file is not usable")
            _require_matching_identity(database_path, existing)
            return existing
        published = True
        stored = directory.read_file(key_path.name)
        if stored != key:
            raise VerifierKeyError("credential verifier key file is not usable")
        _require_matching_identity(database_path, stored)
        return stored
    finally:
        try:
            directory.delete_named(temporary_name)
        except Exception:
            pass


def _acquire_key_lock(path: Path):
    """Bind the lock to the validated parent directory object.

    Opens are relative to that object. A path that no longer names it is
    refused before a key is published. The published HMAC key is not deleted.
    """
    path = Path(path)
    if os.name != "nt":
        return _acquire_key_lock_posix(path)
    from .windows_files import WindowsFileSecurityError, open_bound_directory
    try:
        parent = open_bound_directory(path.parent)
    except (WindowsFileSecurityError,) + _native_path_errors() as error:
        raise VerifierKeyError("credential verifier key lock parent is not usable") from error
    _lock_fault("after-parent-open", path.parent)
    try:
        _require_bound_parent(parent, path.parent)
        _lock_fault("before-lock-open", path)
        _require_bound_parent(parent, path.parent)
        if path.is_symlink():
            raise VerifierKeyError("credential verifier key lock is not usable")
        if not path.exists():
            try:
                parent.write_file(path.name, b"\x00")
            except WindowsFileSecurityError:
                _require_bound_parent(parent, path.parent)
                if not path.exists():
                    raise
        _require_existing_lock(path)
        return _lock_bound_file(parent, path.name)
    except Exception:
        parent.close()
        raise


def _lock_bound_file(parent, name: str):
    from .windows_files import _open_relative
    import ctypes
    import ctypes.wintypes as wintypes
    # Read/write without DELETE so a second initializer can open the same lock
    # object while neither opener can unlink it out from under the other.
    handle = _open_relative(parent.handle, name, directory=False, access=0x12019F)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("Event", wintypes.HANDLE)]

    overlapped = OVERLAPPED()
    if not kernel32.LockFileEx(wintypes.HANDLE(int(handle)), 2, 0, 1, 0, ctypes.byref(overlapped)):
        kernel32.CloseHandle(wintypes.HANDLE(int(handle)))
        raise VerifierKeyError("credential verifier key lock is not usable")
    return (handle, parent, overlapped)


def _acquire_key_lock_posix(path: Path):
    _require_lock_parent(path.parent)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if not path.exists():
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | flags, 0o600)
        os.close(descriptor)
        _protect_new_lock(path)
    _require_existing_lock(path)
    descriptor = os.open(path, flags)
    try:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _require_lock_parent(parent: Path) -> None:
    if not parent.is_dir() or parent.is_symlink():
        raise VerifierKeyError("credential verifier key lock parent is not usable")
    if os.name == "nt":
        from .windows_files import WindowsFileSecurityError, verify_private_directory
        try:
            verify_private_directory(parent)
        except WindowsFileSecurityError as error:
            raise VerifierKeyError("credential verifier key lock parent is not usable") from error
    elif parent.stat().st_mode & 0o002:
        raise VerifierKeyError("credential verifier key lock parent is not usable")


def _protect_new_lock(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, 0o600)
        if path.stat().st_mode & 0o077:
            raise VerifierKeyError("credential verifier key lock could not be protected")
        return
    from .windows_files import protect_private_secret_file
    protect_private_secret_file(path)


def _require_existing_lock(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise VerifierKeyError("credential verifier key lock is not usable")
    if os.name != "nt":
        if path.stat().st_mode & 0o077:
            raise VerifierKeyError("credential verifier key lock is not usable")
        return
    from .windows_files import WindowsFileSecurityError, verify_verifier_key_custody
    try:
        verify_verifier_key_custody(path, production=False)
    except WindowsFileSecurityError as error:
        raise VerifierKeyError("credential verifier key lock is not usable") from error


def _release_key_lock(token) -> None:
    if isinstance(token, tuple):
        handle, parent, overlapped = token
        import ctypes
        import ctypes.wintypes as wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.UnlockFileEx(wintypes.HANDLE(int(handle)), 0, 1, 0, ctypes.byref(overlapped))
        kernel32.CloseHandle(wintypes.HANDLE(int(handle)))
        parent.close()
        return
    try:
        import fcntl
        fcntl.flock(token, fcntl.LOCK_UN)
    finally:
        os.close(token)
