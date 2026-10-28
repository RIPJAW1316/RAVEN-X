"""Read-only rollback and backup-restore safety checks.

An older control-plane binary cannot recover a committed-but-unconfirmed
renewal: it has no confirmation route and treats a ROTATED predecessor as
unusable. This module refuses that rollback instead of documenting it only.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import threading
import re
import shutil
import sqlite3
import stat
from typing import Tuple
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from .schema import (
    CURRENT_SCHEMA_VERSION,
    PRE_RENEWAL_SCHEMA_VERSION,
    SchemaVersionError,
    renewal_capability_counts,
    schema_version,
)


@dataclass(frozen=True)
class RollbackDecision:
    allowed: bool
    code: str
    message: str
    open_lineage_count: int = 0
    current_schema: int = CURRENT_SCHEMA_VERSION
    target_schema: int = PRE_RENEWAL_SCHEMA_VERSION
    operator_action: str = ""


_UNSAFE_PENDING = (
    "Rollback of the control-plane binary is refused while a renewal lineage "
    "is unconfirmed or still grants predecessor overlap. Wait until every "
    "endpoint confirms, or revoke those endpoints and re-enroll them. "
    "Do not restore an older database backup."
)

_UNSAFE_HMAC = (
    "Rollback to a pre-renewal binary is refused while an ACTIVE credential "
    "uses the WS-01 keyed verifier (token-hmac-v2). That binary cannot "
    "authenticate those successors and has no confirmation route. Keep a "
    "WS-01-compatible control plane, or revoke the renewed endpoints and "
    "re-enroll them onto enrollment secrets before any older binary is started."
)

_UNSAFE_RESTORE = (
    "Restoring this backup is refused: the live database already holds "
    "credentials that the backup does not. Agents that already stored the "
    "newer secret would be stranded. Keep the current database and roll "
    "back code only after evaluate_server_rollback allows it."
)


@dataclass(frozen=True)
class RestoreCredential:
    credential_id: str
    status: str
    endpoint_id: str
    organization_id: str | None
    verifier_key_id: str
    issued_at: str | None = None
    revoked_at: str | None = None


@dataclass(frozen=True)
class RestoreLineage:
    predecessor_credential_id: str
    successor_credential_id: str
    confirmed: bool
    endpoint_id: str | None = None
    organization_id: str | None = None


class RollbackInspectionError(RuntimeError):
    """The database could not be inspected without changing the source files."""

    def __init__(self, message: str, residue: str | None = None):
        super().__init__(message)
        self.residue = residue


_SNAPSHOT_PURPOSE = "rollback-check"
_MARKER_NAME = "ravenx-snapshot-owner.json"
_SNAPSHOT_NAME = re.compile(r"ravenx-rollback-([1-9][0-9]*)-([0-9a-f]{32})\Z")
_bindings: dict[str, object] = {}
_active = threading.local()
_root_lock = threading.Lock()
snapshot_fault_hooks = []


def _fault(stage: str, info) -> None:
    for hook in tuple(snapshot_fault_hooks):
        hook(stage, info)


_SNAPSHOT_ROOT_DIAGNOSTIC = (
    "rollback snapshot storage is not trusted. Set RAVENX_ROLLBACK_SNAPSHOT_ROOT to a "
    "private directory whose owner is the operator, SYSTEM, Administrators, LocalService, "
    "NetworkService, or TrustedInstaller, and whose ancestors grant substitution rights "
    "only to those principals. The process temp folder is not used."
)


def _snapshot_root_path() -> Path:
    override = (os.environ.get("RAVENX_ROLLBACK_SNAPSHOT_ROOT") or "").strip()
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "RAVEN-X" / "rollback-snapshots"


def _verify_snapshot_directory(path: Path) -> None:
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import WindowsFileSecurityError, verify_private_directory
        try:
            verify_private_directory(path)
        except (WindowsFileSecurityError, OSError) as error:
            raise RollbackInspectionError("rollback snapshot directory is not private") from error
        return
    try:
        details = path.lstat()
    except OSError as error:
        raise RollbackInspectionError("rollback snapshot directory is not private") from error
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid()
            or details.st_mode & 0o077):
        raise RollbackInspectionError("rollback snapshot directory is not private")


def rollback_snapshot_root() -> Path:
    """Private directory for owned rollback copies. Not the process-wide temp folder."""
    base = _snapshot_root_path()
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import WindowsFileSecurityError, assert_ancestry_not_substitutable
        try:
            assert_ancestry_not_substitutable(base if base.exists() or base.is_symlink() else base.parent)
        except WindowsFileSecurityError as error:
            raise RollbackInspectionError(_SNAPSHOT_ROOT_DIAGNOSTIC) from error
    with _root_lock:
        # Two inspections can otherwise observe the new directory before its
        # access list is set. An existing directory is not rewritten.
        created = False
        if not base.exists() and not base.is_symlink():
            try:
                base.mkdir(parents=True)
                created = True
            except FileExistsError:
                created = False
        if created:
            _restrict_snapshot_directory(base)
        _verify_snapshot_directory(base)
    return base


def recover_stale_rollback_snapshots() -> Tuple[str, ...]:
    """Remove owned snapshots whose creating process is gone.

    Directories without this tool's marker are left alone. A snapshot whose
    process is still alive is left alone. Paths that cannot be removed are
    returned by directory name so the caller can report them.
    """
    root = _snapshot_root_path()
    if not root.exists() and not root.is_symlink():
        return ()
    _verify_snapshot_directory(root)
    residues = []
    for child in tuple(root.iterdir()):
        if not _SNAPSHOT_NAME.fullmatch(child.name):
            continue
        try:
            meta = _validate_owned_snapshot(child)
        except RollbackInspectionError:
            residues.append(child.name)
            continue
        if meta["pid"] == os.getpid() or _pid_alive(meta["pid"]):
            continue
        try:
            _destroy_owned_snapshot(child)
        except RollbackInspectionError:
            residues.append(child.name)
    return tuple(residues)


def _snapshot_for_inspection(database_path: Path) -> Path:
    """Copy the database and WAL into an owned, access-restricted directory.

    Permissions are verified before any database bytes are copied. SQLite may
    create ``-shm`` inside that copy. The source directory is not opened for
    the inspection connection.
    """
    residues = recover_stale_rollback_snapshots()
    if residues:
        raise RollbackInspectionError(
            "an owned rollback snapshot remains after its process ended; "
            "delete only that named directory under the private rollback-snapshot root",
            residue=residues[0])
    path = Path(database_path)
    if not path.is_file():
        raise FileNotFoundError(path.name)
    root = rollback_snapshot_root()
    try:
        from backend.infrastructure.security.windows_files import WindowsFileSecurityError, assert_ancestry_not_substitutable
        if os.name == "nt":
            assert_ancestry_not_substitutable(root)
    except WindowsFileSecurityError as error:
        raise RollbackInspectionError(_SNAPSHOT_ROOT_DIAGNOSTIC) from error
    from backend.infrastructure.security.windows_files import BoundDirectory, open_bound_directory
    root_binding = open_bound_directory(root) if os.name == "nt" else None
    snapshot_name = "ravenx-rollback-%s-%s" % (os.getpid(), uuid4().hex)
    snapshot = root / snapshot_name
    child = None
    try:
        _fault("after-root-open", root)
        if root_binding is not None and not root_binding.same_object():
            raise RollbackInspectionError("rollback snapshot root was substituted")
        if root_binding is not None:
            child = root_binding.make_directory(snapshot_name)
            _bindings[snapshot_name] = child
        else:
            snapshot.mkdir()
            _restrict_snapshot_directory(snapshot)
        _fault("after-child-create", snapshot)
        if child is not None and not child.same_object():
            raise RollbackInspectionError("rollback snapshot directory was substituted", residue=snapshot_name)
        _active.directory = child
        _write_marker(snapshot, path.name)
        destination = snapshot / path.name
        _copy_verified(path, destination)
        wal = Path(str(path) + "-wal")
        if wal.is_file():
            _copy_verified(wal, snapshot / (path.name + "-wal"))
        if child is not None and not child.same_object():
            raise RollbackInspectionError("rollback snapshot directory was substituted", residue=snapshot_name)
        if child is not None:
            _write_marker(snapshot, path.name)
    except Exception as error:
        try:
            if snapshot_name in _bindings or snapshot.exists():
                _destroy_owned_snapshot(snapshot)
        except RollbackInspectionError as cleanup:
            raise RollbackInspectionError(
                "rollback snapshot construction failed and the owned copy could not be removed. "
                "Confirm the named directory is owned by the operator and its access list is only "
                "that user, SYSTEM, and Administrators before deleting it",
                residue=cleanup.residue or snapshot_name) from cleanup
        if isinstance(error, RollbackInspectionError):
            raise
        raise RollbackInspectionError("rollback snapshot could not be constructed") from error
    finally:
        _active.directory = None
        if root_binding is not None:
            root_binding.close()
    return snapshot


def _copy_verified(source: Path, destination: Path) -> None:
    data = source.read_bytes()
    stage = "before-wal-copy" if str(source).endswith("-wal") else "before-db-copy"
    _fault(stage, destination)
    binding = getattr(_active, "directory", None)
    if binding is not None:
        if not binding.same_object():
            raise RollbackInspectionError("rollback snapshot directory was substituted", residue=binding.name)
        binding.write_file(destination.name, data)
        return
    shutil.copyfile(source, destination)
    _protect_snapshot_file(destination)
    if not _snapshot_bytes_match(source, destination):
        raise RollbackInspectionError("rollback snapshot does not match the source file")


def _snapshot_bytes_match(source: Path, destination: Path) -> bool:
    return destination.read_bytes() == source.read_bytes()


def _open_snapshot_engine(snapshot: Path, database_name: str):
    destination = snapshot / database_name
    uri = "file:" + destination.resolve().as_posix() + "?mode=ro"

    def connect():
        return sqlite3.connect(uri, uri=True)

    return create_engine("sqlite://", creator=connect, poolclass=NullPool)


@contextmanager
def inspect_existing_sqlite_readonly(database_path: Path):
    """Yield a read-only engine and remove the owned snapshot before returning.

    A cleanup failure becomes ``RollbackInspectionError`` and is not turned
    into a successful inspection. This is the only supported way to open a
    rollback snapshot.
    """
    snapshot = None
    engine = None
    try:
        snapshot = _snapshot_for_inspection(database_path)
        try:
            engine = _open_snapshot_engine(snapshot, Path(database_path).name)
        except RollbackInspectionError:
            raise
        except Exception as error:
            raise RollbackInspectionError("rollback snapshot could not be opened") from error
        yield engine
    finally:
        disposal_error = None
        if engine is not None:
            try:
                engine.dispose()
            except Exception as error:
                disposal_error = error
        if snapshot is not None:
            _destroy_owned_snapshot(snapshot)
        if disposal_error is not None:
            raise RollbackInspectionError("rollback inspection engine could not be disposed") from disposal_error


def _restrict_snapshot_directory(path: Path) -> None:
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_directory
        protect_private_directory(path)
        _verify_snapshot_directory(path)
        return
    os.chmod(path, 0o700)
    _verify_snapshot_directory(path)


def _marker_payload(snapshot_name: str, database_name: str, binding) -> bytes:
    payload = {"purpose": _SNAPSHOT_PURPOSE, "pid": os.getpid(),
               "name": snapshot_name, "database": database_name}
    if binding is not None:
        volume, high, low = binding.identity
        payload["volume"] = volume
        payload["file_index_high"] = high
        payload["file_index_low"] = low
        files = {name: list(identity) for name, identity in binding.created.items() if name != _MARKER_NAME}
        if files:
            payload["files"] = files
    return json.dumps(payload).encode("utf-8")


def _write_marker(snapshot: Path, database_name: str) -> None:
    binding = getattr(_active, "directory", None)
    payload = _marker_payload(snapshot.name, database_name, binding)
    if binding is not None:
        previous = binding.created.get(_MARKER_NAME)
        if previous is not None:
            from backend.infrastructure.security.windows_files import WindowsFileSecurityError
            try:
                binding.delete_named(_MARKER_NAME, expected_identity=previous)
            except WindowsFileSecurityError:
                pass
        binding.write_file(_MARKER_NAME, payload)
        return
    marker = snapshot / _MARKER_NAME
    marker.write_bytes(payload)
    _protect_snapshot_file(marker)


def _protect_snapshot_file(path: Path) -> None:
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import protect_private_secret_file
        protect_private_secret_file(path)
        return
    os.chmod(path, 0o600)
    if path.lstat().st_mode & 0o077:
        raise RollbackInspectionError("rollback snapshot file could not be protected")


def _validate_owned_snapshot(snapshot: Path) -> dict:
    root = _snapshot_root_path()
    match = _SNAPSHOT_NAME.fullmatch(snapshot.name)
    if snapshot.parent != root or match is None:
        raise RollbackInspectionError("refusing to inspect an unrelated snapshot directory")
    try:
        _verify_snapshot_directory(root)
        _verify_snapshot_directory(snapshot)
        marker = snapshot / _MARKER_NAME
        if marker.is_symlink() or not marker.is_file():
            raise RollbackInspectionError("owned rollback snapshot marker is missing", residue=snapshot.name)
        if os.name == "nt":
            from backend.infrastructure.security.windows_files import _assert_no_reparse
            _assert_no_reparse(marker)
        meta = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as error:
        raise RollbackInspectionError("owned rollback snapshot is not verifiable",
                                      residue=snapshot.name) from error
    if (not isinstance(meta, dict) or meta.get("purpose") != _SNAPSHOT_PURPOSE
            or type(meta.get("pid")) is not int
            or str(meta["pid"]) != match.group(1) or meta.get("name") != snapshot.name
            or not isinstance(meta.get("database"), str)
            or meta["database"] in ("", ".", "..")
            or "/" in meta["database"] or "\\" in meta["database"]):
        raise RollbackInspectionError("owned rollback snapshot marker is invalid",
                                      residue=snapshot.name)
    return meta


def _discard_unmarked_snapshot(snapshot: Path) -> None:
    """Remove only a newly made directory before any database copy has begun."""
    if snapshot.parent != _snapshot_root_path() or not _SNAPSHOT_NAME.fullmatch(snapshot.name):
        raise RollbackInspectionError("refusing to remove an unrelated snapshot directory")
    try:
        for item in snapshot.iterdir():
            if item.name != _MARKER_NAME or item.is_symlink() or not item.is_file():
                raise RollbackInspectionError("unmarked snapshot needs reviewed cleanup",
                                              residue=snapshot.name)
            item.unlink()
        snapshot.rmdir()
    except OSError as error:
        raise RollbackInspectionError("unmarked snapshot could not be removed",
                                      residue=snapshot.name) from error


def _residue(snapshot_name: str, message: str) -> RollbackInspectionError:
    return RollbackInspectionError(
        message + " Confirm it is owned by the operator and its access list is only that user, "
        "SYSTEM, and Administrators before manual cleanup",
        residue=snapshot_name)


def _validated_marker(payload: bytes, snapshot_name: str) -> dict:
    match = _SNAPSHOT_NAME.fullmatch(snapshot_name)
    try:
        meta = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError) as error:
        raise RollbackInspectionError("owned rollback snapshot is not verifiable",
                                      residue=snapshot_name) from error
    if (match is None or not isinstance(meta, dict) or meta.get("purpose") != _SNAPSHOT_PURPOSE
            or type(meta.get("pid")) is not int
            or str(meta["pid"]) != match.group(1) or meta.get("name") != snapshot_name
            or not isinstance(meta.get("database"), str)
            or meta["database"] in ("", ".", "..")
            or "/" in meta["database"] or "\\" in meta["database"]):
        raise RollbackInspectionError("owned rollback snapshot marker is invalid", residue=snapshot_name)
    return meta


def _expected_identity(meta: dict, binding, name: str):
    recorded = binding.created.get(name)
    if recorded is not None:
        return recorded
    files = meta.get("files")
    if isinstance(files, dict) and isinstance(files.get(name), list) and len(files[name]) == 3:
        return tuple(files[name])
    return None


def _destroy_through_binding(binding, snapshot_name: str) -> None:
    """Remove the directory object held by ``binding``. The path is not deleted."""
    from backend.infrastructure.security.windows_files import WindowsFileSecurityError
    if not binding.same_object():
        binding.close()
        raise _residue(snapshot_name, "rollback snapshot directory was substituted; the named directory was not deleted.")
    try:
        from backend.infrastructure.security.windows_files import _security_from_handle
        _security_from_handle(binding.handle, directory=True)
    except Exception as error:
        binding.close()
        raise RollbackInspectionError("rollback snapshot directory is not private", residue=snapshot_name) from error
    _fault("before-bound-delete", binding)
    if not binding.same_object():
        binding.close()
        raise _residue(snapshot_name, "rollback snapshot directory was substituted; the named directory was not deleted.")
    try:
        meta = _validated_marker(binding.read_file(_MARKER_NAME), snapshot_name)
    except RollbackInspectionError:
        binding.close()
        raise
    except Exception as error:
        binding.close()
        raise RollbackInspectionError("owned rollback snapshot is not verifiable", residue=snapshot_name) from error
    if "volume" in meta:
        recorded = (int(meta["volume"]), int(meta["file_index_high"]), int(meta["file_index_low"]))
        if recorded != binding.identity:
            binding.close()
            raise _residue(snapshot_name, "rollback snapshot directory was substituted; the named directory was not deleted.")
    if _MARKER_NAME not in binding.created:
        try:
            binding.created[_MARKER_NAME] = binding.identity_named(_MARKER_NAME)
        except WindowsFileSecurityError as error:
            binding.close()
            raise _residue(snapshot_name, "owned rollback snapshot could not be removed; review the named directory "
                           "under the private rollback-snapshot root and confirm its owner and access list") from error
    database = meta["database"]
    missing = {0xC0000034, 0xC000003A}
    try:
        for name in (database, database + "-wal", database + "-shm", database + "-journal", _MARKER_NAME):
            _fault("before-child-delete", name)
            if not binding.same_object():
                raise _residue(snapshot_name, "rollback snapshot directory was substituted; the named directory was not deleted.")
            try:
                binding.delete_named(name, expected_identity=_expected_identity(meta, binding, name))
            except WindowsFileSecurityError as error:
                if getattr(error, "status", None) in missing:
                    continue
                raise
        binding.delete_self()
    except RollbackInspectionError:
        if binding.handle is not None:
            binding.close()
        raise
    except Exception as error:
        if binding.handle is not None:
            binding.close()
        raise _residue(snapshot_name, "owned rollback snapshot could not be removed; review the named directory "
                       "under the private rollback-snapshot root and confirm its owner and access list") from error


def _destroy_owned_snapshot(snapshot: Path) -> None:
    binding = _bindings.pop(snapshot.name, None)
    if binding is None and os.name == "nt":
        from backend.infrastructure.security.windows_files import WindowsFileSecurityError, open_bound_directory
        try:
            binding = open_bound_directory(snapshot, share_delete=False)
        except (WindowsFileSecurityError, OSError) as error:
            raise _residue(snapshot.name, "owned rollback snapshot could not be removed; review the named directory "
                           "under the private rollback-snapshot root and confirm its owner and access list") from error
    if binding is not None:
        _destroy_through_binding(binding, snapshot.name)
        return
    meta = _validate_owned_snapshot(snapshot)
    marker = snapshot / _MARKER_NAME
    database = meta["database"]
    allowed = {database, database + "-wal", database + "-shm", database + "-journal"}
    try:
        for item in tuple(snapshot.iterdir()):
            if item.name == _MARKER_NAME:
                continue
            if item.name not in allowed or item.is_symlink() or not item.is_file():
                raise RollbackInspectionError("owned rollback snapshot contains an unexpected path",
                                              residue=snapshot.name)
            if os.name == "nt":
                from backend.infrastructure.security.windows_files import _assert_no_reparse
                _assert_no_reparse(item)
            item.unlink()
        # Delete the marker last. A failed data-file deletion leaves the proof of
        # ownership available for the next conservative recovery attempt.
        marker.unlink()
        try:
            snapshot.rmdir()
        except OSError:
            _write_marker(snapshot, database)
            raise
    except RollbackInspectionError:
        raise
    except Exception as error:
        raise RollbackInspectionError(
            "owned rollback snapshot could not be removed; review the named directory "
            "under the private rollback-snapshot root and confirm its owner and access list "
            "before manual cleanup",
            residue=snapshot.name) from error


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        # Access denied or an unknown probe failure is not proof of death.
        return ctypes.get_last_error() != 87  # ERROR_INVALID_PARAMETER
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def evaluate_server_rollback(enrollment_repository=None, *, target_schema: int = PRE_RENEWAL_SCHEMA_VERSION,
                             engine=None) -> RollbackDecision:
    try:
        current = schema_version(engine) if engine is not None else CURRENT_SCHEMA_VERSION
    except SchemaVersionError as error:
        return RollbackDecision(
            False, "ambiguous_schema", str(error),
            current_schema=0, target_schema=target_schema,
            operator_action="review_schema_metadata_before_rollback",
        )
    open_count = 0
    keyed = 0
    if enrollment_repository is not None:
        open_count = len(tuple(enrollment_repository.list_open_renewal_lineages()))
        keyed = int(enrollment_repository.count_active_keyed_verifiers())
    if engine is not None:
        engine_open, engine_keyed = renewal_capability_counts(engine)
        open_count = max(open_count, engine_open)
        keyed = max(keyed, engine_keyed)
    # A downgrade is never "already compatible" merely because version metadata
    # is missing or claims an older schema. HMAC credentials and open lineages
    # are checked before that answer.
    if target_schema < CURRENT_SCHEMA_VERSION and (open_count or keyed):
        if open_count:
            return RollbackDecision(
                False, "pending_renewal_lineage", _UNSAFE_PENDING,
                open_lineage_count=open_count, current_schema=current, target_schema=target_schema,
                operator_action="wait_for_confirmation_or_revoke_and_reenroll",
            )
        return RollbackDecision(
            False, "incompatible_hmac_successors", _UNSAFE_HMAC,
            open_lineage_count=0, current_schema=current, target_schema=target_schema,
            operator_action="keep_ws01_compatible_binary_or_revoke_and_reenroll",
        )
    if target_schema >= current:
        return RollbackDecision(True, "already_compatible",
                                "target schema is not older than the current schema; "
                                "active HMAC credentials and open lineages were checked",
                                open_lineage_count=open_count, current_schema=current, target_schema=target_schema)
    return RollbackDecision(
        True, "code_rollback_safe",
        "No open renewal lineages and no ACTIVE keyed verifiers. A pre-renewal "
        "binary may run against this database if the newer table is left in "
        "place and no older backup is restored.",
        current_schema=current, target_schema=target_schema,
        operator_action="keep_current_database",
    )


def evaluate_database_restore(*, live_credential_ids: Tuple[str, ...] = (),
                              backup_credential_ids: Tuple[str, ...] = (),
                              live_credentials: Tuple[RestoreCredential, ...] = (),
                              backup_credentials: Tuple[RestoreCredential, ...] = (),
                              live_verifier_key_id: str | None = None,
                              backup_verifier_key_id: str | None = None,
                              live_lineages: Tuple[RestoreLineage, ...] = (),
                              backup_lineages: Tuple[RestoreLineage, ...] = (),
                              revocation_event_ids: Tuple[str, ...] = (),
                              history_complete: bool = False) -> RollbackDecision:
    """Decide whether a backup is eligible. This function does not restore anything."""
    if not history_complete or not live_credentials or not backup_credentials:
        live_ids = {item.credential_id for item in live_credentials} or set(live_credential_ids)
        backup_ids = {item.credential_id for item in backup_credentials} or set(backup_credential_ids)
        if live_ids - backup_ids:
            return RollbackDecision(
                False, "backup_missing_live_credentials", _UNSAFE_RESTORE,
                operator_action="keep_current_database",
            )
        return RollbackDecision(
            False, "restore_history_incomplete",
            "Credential identifiers alone cannot prove status, revocation history, "
            "lineage, or verifier-key identity. Refusing the backup until a reviewed "
            "recovery procedure establishes those facts. No restore was performed.",
            operator_action="reviewed_recovery_required",
        )
    if not live_verifier_key_id or live_verifier_key_id != backup_verifier_key_id:
        return RollbackDecision(
            False, "verifier_key_mismatch",
            "The backup verifier-key identity does not match the live database. "
            "Restoring it could resurrect credentials this key cannot honestly verify. "
            "No restore was performed.",
            operator_action="reviewed_recovery_required",
        )
    live_by = {item.credential_id: item for item in live_credentials}
    backup_by = {item.credential_id: item for item in backup_credentials}
    if set(live_by) - set(backup_by):
        return RollbackDecision(
            False, "backup_missing_live_credentials", _UNSAFE_RESTORE,
            operator_action="keep_current_database",
        )
    for credential_id, live in live_by.items():
        backup = backup_by[credential_id]
        if live.status != backup.status or bool(live.revoked_at) != bool(backup.revoked_at):
            return RollbackDecision(
                False, "credential_status_mismatch",
                "The same credential identifier has a different effective status in the "
                "backup. Restoring it could resurrect revoked authority. No restore was performed.",
                operator_action="reviewed_recovery_required",
            )
        if (live.endpoint_id != backup.endpoint_id or live.organization_id != backup.organization_id
                or live.verifier_key_id != backup.verifier_key_id
                or live.verifier_key_id != live_verifier_key_id):
            return RollbackDecision(
                False, "tenant_or_endpoint_mismatch",
                "Backup credential lineage, endpoint, or verifier-key identity does not "
                "match the live record. No restore was performed.",
                operator_action="reviewed_recovery_required",
            )
    revoked_ids = {item.credential_id for item in live_credentials if item.status == "revoked" or item.revoked_at}
    if not revoked_ids <= set(revocation_event_ids):
        return RollbackDecision(
            False, "missing_revocation_history",
            "Revoked credentials have no matching revocation history. Freshness is "
            "uncertain, so the backup is refused. No restore was performed.",
            operator_action="reviewed_recovery_required",
        )
    for event_id in revocation_event_ids:
        backup = backup_by.get(event_id)
        if backup is not None and backup.status == "active":
            return RollbackDecision(
                False, "pre_revocation_restore",
                "The backup still grants active authority for a credential the live "
                "history has revoked. No restore was performed.",
                operator_action="reviewed_recovery_required",
            )
    def _lineage_rows(items, *, confirmed: bool):
        return {(item.predecessor_credential_id, item.successor_credential_id, item.endpoint_id,
                 item.organization_id, bool(item.confirmed))
                for item in items if bool(item.confirmed) is confirmed}
    if _lineage_rows(live_lineages, confirmed=False) != _lineage_rows(backup_lineages, confirmed=False):
        return RollbackDecision(
            False, "pending_lineage_mismatch",
            "Pending renewal lineage differs between the live database and the backup. "
            "No restore was performed.",
            operator_action="reviewed_recovery_required",
        )
    if _lineage_rows(live_lineages, confirmed=True) != _lineage_rows(backup_lineages, confirmed=True):
        return RollbackDecision(
            False, "confirmed_lineage_mismatch",
            "A confirmed predecessor-successor relationship is missing or different in "
            "the backup. Restoring it could break descendant revocation. "
            "history_complete is not proof. No restore was performed.",
            operator_action="reviewed_recovery_required",
        )
    return RollbackDecision(
        True, "restore_eligible",
        "Backup matches live credential status, lineage, revocation history, and "
        "verifier-key identity. This check does not restore the database.",
        operator_action="reviewed_recovery_may_proceed_outside_this_check",
    )
