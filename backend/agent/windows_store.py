"""Machine-scoped DPAPI state for a Windows agent running as SYSTEM.

The encrypted record binds endpoint identity, credential lifetime, server URL,
and optional CA certificate digest in one atomic file. File confidentiality
depends on the verified Administrators/SYSTEM ACL: DPAPI machine scope alone
allows any local account that can read the blob to decrypt it.

Credential renewal adds a second protected file, ``renewal.bin``, holding the
agent-generated successor credential *before* it is proposed to the server.
``credential.bin`` keeps its version-1 schema unchanged, so an older agent can
still read it after a rollback; older agents ignore ``renewal.bin``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit
from uuid import UUID

from ..domain.endpoint import EndpointId
from ..domain.enrollment import CredentialId
from ..infrastructure.security import windows_files
from .file_lock import ExclusiveFileLock, FileLockBusyError
from .runtime import AgentCredential


_MAX_RECORD_BYTES = 8192
_PENDING_RENEWAL_KIND = "ravenx.agent.pending_renewal"
_OPAQUE_SECRET = re.compile(r"[A-Za-z0-9_-]{43,128}")


class AgentStateError(RuntimeError):
    pass


def _prepared_state(pending) -> tuple:
    """Identity of one prepared successor. The timestamp is not a different successor."""
    return (
        str(pending.endpoint_id),
        str(pending.organization_id),
        str(pending.predecessor_credential_id),
        str(pending.successor_credential_id),
        pending.successor_credential_secret,
    )


class RenewalLockBusyError(AgentStateError):
    """Another process or thread is performing credential renewal for this agent."""


@dataclass(frozen=True)
class AgentRecord:
    endpoint_id: EndpointId
    credential_id: CredentialId
    credential_secret: str = field(repr=False)
    organization_id: str = ""
    protocol_version: str = ""
    credential_expires_at: datetime | None = None
    server_url: str = ""
    ca_sha256: str | None = None

    def __post_init__(self):
        if not self.credential_secret or len(self.credential_secret) < 32:
            raise AgentStateError("stored credential is invalid")
        if not self.credential_expires_at or self.credential_expires_at.tzinfo is None:
            raise AgentStateError("stored credential has no expiry")
        if not self.organization_id or not self.protocol_version:
            raise AgentStateError("stored endpoint identity is incomplete")
        try:
            UUID(self.organization_id)
        except ValueError as error:
            raise AgentStateError("stored organization identity is invalid") from error
        parsed = urlsplit(self.server_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise AgentStateError("stored control-plane URL is invalid")
        if self.ca_sha256 is not None and (len(self.ca_sha256) != 64 or
                                           any(c not in "0123456789abcdef" for c in self.ca_sha256)):
            raise AgentStateError("stored CA digest is invalid")

    def __repr__(self):
        return (f"AgentRecord(endpoint_id={self.endpoint_id!s}, credential_id={self.credential_id!s}, "
                "credential_secret=<redacted>)")

    def to_json_bytes(self) -> bytes:
        document = {
            "version": 1,
            "endpoint_id": str(self.endpoint_id), "credential_id": str(self.credential_id),
            "credential_secret": self.credential_secret,
            "organization_id": self.organization_id,
            "protocol_version": self.protocol_version,
            "credential_expires_at": self.credential_expires_at.isoformat(),
            "server_url": self.server_url,
            "ca_sha256": self.ca_sha256,
        }
        return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "AgentRecord":
        try:
            data = json.loads(raw.decode("utf-8"))
            if data["version"] != 1:
                raise ValueError("state version mismatch")
            return cls(EndpointId(data["endpoint_id"]), CredentialId(data["credential_id"]),
                       data["credential_secret"], data["organization_id"],
                       data["protocol_version"], datetime.fromisoformat(data["credential_expires_at"]),
                       data["server_url"], data.get("ca_sha256"))
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise AgentStateError("protected agent state is invalid") from error


@dataclass(frozen=True)
class PendingRenewal:
    """Agent-generated successor credential, persisted before it is ever sent.

    Holding this durably is what makes renewal recoverable: whether or not the
    server committed it, and whether or not its response arrived, the agent can
    later prove possession of exactly this successor.
    """

    endpoint_id: EndpointId
    organization_id: str
    predecessor_credential_id: CredentialId
    successor_credential_id: CredentialId
    successor_credential_secret: str = field(repr=False)
    prepared_at: datetime | None = None

    def __post_init__(self):
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(str(self.endpoint_id)))
        for name in ("predecessor_credential_id", "successor_credential_id"):
            value = getattr(self, name)
            if not isinstance(value, CredentialId):
                object.__setattr__(self, name, CredentialId(str(value)))
        if self.predecessor_credential_id == self.successor_credential_id:
            raise AgentStateError("prepared renewal must name a new credential")
        try:
            UUID(self.organization_id)
        except (TypeError, ValueError, AttributeError) as error:
            raise AgentStateError("prepared renewal organization is invalid") from error
        if (not isinstance(self.successor_credential_secret, str)
                or _OPAQUE_SECRET.fullmatch(self.successor_credential_secret) is None):
            raise AgentStateError("prepared renewal secret is invalid")
        if self.prepared_at is None or self.prepared_at.tzinfo is None or self.prepared_at.utcoffset() is None:
            raise AgentStateError("prepared renewal has no preparation time")

    def __repr__(self):
        return (f"PendingRenewal(endpoint_id={self.endpoint_id!s}, "
                f"predecessor_credential_id={self.predecessor_credential_id!s}, "
                f"successor_credential_id={self.successor_credential_id!s}, successor_credential_secret=<redacted>)")

    def as_credential(self) -> AgentCredential:
        return AgentCredential(self.successor_credential_id, self.successor_credential_secret)

    def to_json_bytes(self) -> bytes:
        document = {
            "kind": _PENDING_RENEWAL_KIND, "version": 1,
            "endpoint_id": str(self.endpoint_id), "organization_id": self.organization_id,
            "predecessor_credential_id": str(self.predecessor_credential_id),
            "successor_credential_id": str(self.successor_credential_id),
            "successor_credential_secret": self.successor_credential_secret,
            "prepared_at": self.prepared_at.isoformat(),
        }
        return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "PendingRenewal":
        try:
            data = json.loads(raw.decode("utf-8"))
            if data["kind"] != _PENDING_RENEWAL_KIND or data["version"] != 1:
                raise ValueError("pending renewal format mismatch")
            return cls(EndpointId(data["endpoint_id"]), data["organization_id"],
                       CredentialId(data["predecessor_credential_id"]), CredentialId(data["successor_credential_id"]),
                       data["successor_credential_secret"], datetime.fromisoformat(data["prepared_at"]))
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise AgentStateError("protected renewal state is invalid") from error


class DpapiMachineProtector:
    def __init__(self, *, max_bytes: int = _MAX_RECORD_BYTES):
        if os.name != "nt":
            raise AgentStateError("machine DPAPI storage requires Windows")
        try:
            import win32crypt
            import win32cryptcon
        except ImportError as error:
            raise AgentStateError("pywin32 is required for DPAPI storage") from error
        self._crypt = win32crypt
        self._flags = win32cryptcon.CRYPTPROTECT_LOCAL_MACHINE
        self._max_bytes = max_bytes

    def protect(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes) or len(plaintext) > self._max_bytes:
            raise AgentStateError("agent state exceeds its size limit")
        return self._crypt.CryptProtectData(plaintext, "RAVEN-X Agent", None, None, None, self._flags)

    def unprotect(self, ciphertext: bytes) -> bytes:
        try:
            _, plaintext = self._crypt.CryptUnprotectData(ciphertext, None, None, None, 0)
        except Exception as error:
            raise AgentStateError("protected agent state could not be decrypted") from error
        if len(plaintext) > self._max_bytes:
            raise AgentStateError("protected agent state exceeds its size limit")
        return plaintext


def default_agent_data_directory() -> Path:
    if os.name != "nt" or not os.environ.get("PROGRAMDATA"):
        raise AgentStateError("PROGRAMDATA is required for Windows agent storage")
    return Path(os.environ["PROGRAMDATA"]) / "RavenX" / "agent"


class WindowsAgentStateStore:
    def __init__(self, directory: Path | None = None, *, protector=None, files=None):
        self.directory = Path(directory) if directory is not None else default_agent_data_directory()
        self._protector = protector or DpapiMachineProtector()
        self._files = files or windows_files
        self._files.verify_directory(self.directory)
        self.path = self.directory / "credential.bin"
        self.renewal_path = self.directory / "renewal.bin"
        self.renewal_lock_path = self.directory / ".renewal.lock"
        self.identity_store = _IdentityView(self)
        self.credential_store = _CredentialView(self)

    def load_record(self) -> AgentRecord | None:
        self._files.verify_directory(self.directory)
        if not self.path.exists():
            return None
        self._files.verify_protected_file(self.path)
        ciphertext = self.path.read_bytes()
        if len(ciphertext) > _MAX_RECORD_BYTES * 2:
            raise AgentStateError("protected agent state exceeds its size limit")
        return AgentRecord.from_json_bytes(self._protector.unprotect(ciphertext))

    def save_enrollment(self, grant, *, server_url: str, ca_sha256: str | None = None) -> AgentRecord:
        if self.load_record() is not None:
            raise AgentStateError("agent is already enrolled")
        # A renewal file without an enrolled identity cannot be used: discard it
        # before installing the new identity so it can never be misapplied.
        self._discard_pending_renewal()
        record = AgentRecord(
            grant.endpoint_id, CredentialId(grant.credential_id), grant.credential_secret,
            grant.organization_id, grant.protocol_version, grant.credential_expires_at,
            server_url.rstrip("/"), ca_sha256,
        )
        try:
            self._files.atomic_create_protected(self.path, self._protector.protect(record.to_json_bytes()))
        except FileExistsError as error:
            raise AgentStateError("agent is already enrolled") from error
        restored = self.load_record()
        if restored != record:
            raise AgentStateError("protected agent state failed verification")
        return restored

    def load_pending_renewal(self) -> PendingRenewal | None:
        self._files.verify_directory(self.directory)
        if not self.renewal_path.exists():
            return None
        self._files.verify_protected_file(self.renewal_path)
        ciphertext = self.renewal_path.read_bytes()
        if len(ciphertext) > _MAX_RECORD_BYTES * 2:
            raise AgentStateError("protected renewal state exceeds its size limit")
        return PendingRenewal.from_json_bytes(self._protector.unprotect(ciphertext))

    def reconcile_renewal_state(self) -> tuple[AgentRecord | None, PendingRenewal | None]:
        """Return (current record, pending renewal), discarding a renewal that was already promoted.

        Call while holding ``renewal_lock``. A pending renewal that belongs to a
        different identity or lineage fails closed: it indicates restored or
        tampered state that needs an operator.
        """
        self.recover_prepared_publication()
        record = self.load_record()
        pending = self.load_pending_renewal()
        if record is None or pending is None:
            return record, pending
        if pending.endpoint_id != record.endpoint_id or pending.organization_id != record.organization_id:
            raise AgentStateError("prepared renewal belongs to a different endpoint identity")
        if pending.successor_credential_id == record.credential_id:
            self._discard_pending_renewal()
            return record, None
        if pending.predecessor_credential_id != record.credential_id:
            raise AgentStateError("prepared renewal does not extend the stored credential")
        self.require_prepared_durable()
        return record, pending

    def require_prepared_durable(self) -> None:
        """Flush the published successor again. Decryption is not durability."""
        if not self.renewal_path.is_file():
            raise AgentStateError("prepared renewal is not available for a durability check")
        checker = getattr(self._files, "require_durable_file", None)
        if checker is None:
            from ..infrastructure.security.windows_files import require_durable_file as checker
        checker(self.renewal_path)

    def prepare_renewal(self, *, now: datetime, secret_factory=None) -> PendingRenewal:
        """Generate and durably store a successor before any network request; never overwrites one."""
        if self.recover_prepared_publication() is not None or self.renewal_path.exists():
            raise AgentStateError("a credential renewal is already prepared")
        record = self.load_record()
        if record is None:
            raise AgentStateError("agent is not enrolled")
        secret = (secret_factory or (lambda: secrets.token_urlsafe(32)))()
        if secret == record.credential_secret:
            raise AgentStateError("prepared renewal secret must differ from the current secret")
        pending = PendingRenewal(record.endpoint_id, record.organization_id, record.credential_id,
                                 CredentialId.new(), secret, now.astimezone(timezone.utc))
        ciphertext = self._protector.protect(pending.to_json_bytes())
        if len(ciphertext) > _MAX_RECORD_BYTES * 2:
            raise AgentStateError("protected renewal state exceeds its size limit")
        if PendingRenewal.from_json_bytes(self._protector.unprotect(ciphertext)) != pending:
            raise AgentStateError("protected renewal state failed pre-write verification")
        self.cleanup_interrupted_writes()
        try:
            self._files.atomic_create_protected(self.renewal_path, ciphertext)
        except FileExistsError as error:
            raise AgentStateError("a credential renewal is already prepared") from error
        if self.load_pending_renewal() != pending:
            raise AgentStateError("protected renewal state failed verification")
        self.require_prepared_durable()
        return pending

    def promote_renewal(self, pending: PendingRenewal, *, credential_expires_at: datetime) -> AgentRecord:
        """Make the prepared successor the stored credential after the server acknowledged it.

        Duplicate or delayed acknowledgements are no-ops once the successor is
        current; an acknowledgement for anything other than the prepared
        successor of the current credential is rejected without changing state.
        """
        current = self.load_record()
        if current is None:
            raise AgentStateError("agent is not enrolled")
        if current.credential_id == pending.successor_credential_id:
            stored = self.load_pending_renewal()
            if stored is not None and stored.successor_credential_id == current.credential_id:
                self._discard_pending_renewal(best_effort=True)
            return current
        stored = self.load_pending_renewal()
        if stored is None or stored != pending:
            raise AgentStateError("renewal acknowledgement does not match the prepared renewal")
        if (pending.predecessor_credential_id != current.credential_id or pending.endpoint_id != current.endpoint_id
                or pending.organization_id != current.organization_id):
            raise AgentStateError("prepared renewal does not extend the stored credential")
        if credential_expires_at is None or credential_expires_at.tzinfo is None:
            raise AgentStateError("renewed credential has no valid expiry")
        record = AgentRecord(
            current.endpoint_id, pending.successor_credential_id, pending.successor_credential_secret,
            current.organization_id, current.protocol_version, credential_expires_at.astimezone(timezone.utc),
            current.server_url, current.ca_sha256,
        )
        ciphertext = self._protector.protect(record.to_json_bytes())
        if len(ciphertext) > _MAX_RECORD_BYTES * 2:
            raise AgentStateError("protected agent state exceeds its size limit")
        if AgentRecord.from_json_bytes(self._protector.unprotect(ciphertext)) != record:
            raise AgentStateError("protected agent state failed pre-write verification")
        previous_ciphertext = self.path.read_bytes()
        self.cleanup_interrupted_writes()
        self._files.atomic_write_protected(self.path, ciphertext)
        try:
            restored = self.load_record()
            if restored != record:
                raise AgentStateError("protected agent state failed verification")
        except Exception:
            try:
                self._files.atomic_write_protected(self.path, previous_ciphertext)
            except Exception:
                pass
            raise
        # The successor is now durable in credential.bin; a renewal.bin left by
        # a failure here is recognised as already promoted and removed later.
        self._discard_pending_renewal(best_effort=True)
        return restored

    def recover_prepared_publication(self) -> PendingRenewal | None:
        """Republish a valid orphaned prepared successor instead of deleting it.

        ``renewal.bin.*.tmp`` files are recovery material until ``renewal.bin``
        itself verifies. Corrupt or foreign files are left in place.
        """
        self._files.verify_directory(self.directory)
        record = self.load_record() if self.path.exists() else None
        published = None
        if self.renewal_path.exists():
            try:
                published = self.load_pending_renewal()
            except AgentStateError:
                published = None
        orphans = []
        for candidate in tuple(self.directory.glob("renewal.bin.*.tmp")):
            try:
                self._files.verify_protected_file(candidate)
                pending = PendingRenewal.from_json_bytes(self._protector.unprotect(candidate.read_bytes()))
            except Exception:
                continue
            if (record is not None and pending.endpoint_id == record.endpoint_id
                    and pending.organization_id == record.organization_id
                    and pending.predecessor_credential_id == record.credential_id):
                orphans.append((candidate, pending))
        states = {_prepared_state(pending) for _candidate, pending in orphans}
        if published is not None:
            states.add(_prepared_state(published))
        if len(states) > 1:
            raise AgentStateError("prepared renewal state is ambiguous")
        if published is None and orphans:
            source, pending = orphans[0]
            if not self.renewal_path.exists():
                try:
                    self._files.atomic_create_protected(self.renewal_path, source.read_bytes())
                except FileExistsError:
                    pass
            published = self.load_pending_renewal()
            if published is not None and _prepared_state(published) != _prepared_state(pending):
                raise AgentStateError("prepared renewal state is ambiguous")
        if published is not None:
            published_state = _prepared_state(published)
            for candidate, pending in orphans:
                if _prepared_state(pending) == published_state:
                    try:
                        candidate.unlink()
                    except OSError:
                        pass
        return published

    def cleanup_interrupted_writes(self) -> int:
        """Remove leftover credential write temps only after credential.bin verifies.

        Prepared-successor temps are recovered, not deleted here.
        """
        self._files.verify_directory(self.directory)
        if self.path.exists():
            self.load_record()
        removed = 0
        for candidate in tuple(self.directory.glob("credential.bin.*.tmp")):
            self._files.verify_protected_file(candidate)
            candidate.unlink()
            removed += 1
        return removed

    @contextmanager
    def renewal_lock(self):
        """Serialize renewal across threads and processes using an OS-held exclusive lock.

        The lock is released by the operating system if the holder dies; it is
        never reclaimed by age and its file is never deleted.
        """
        self._files.verify_directory(self.directory)
        if not self.renewal_lock_path.exists():
            try:
                self._files.atomic_create_protected(self.renewal_lock_path, b"\x00")
            except FileExistsError:
                pass
        self._files.verify_protected_file(self.renewal_lock_path)
        lock = ExclusiveFileLock(self.renewal_lock_path)
        try:
            lock.acquire()
        except FileLockBusyError as error:
            raise RenewalLockBusyError("agent credential renewal is already in progress") from error
        try:
            yield
        finally:
            lock.release()

    @contextmanager
    def enrollment_lock(self):
        """Reserve local enrollment before consuming a server bootstrap token."""
        lock = self.directory / ".enrollment.lock"
        try:
            self._files.atomic_create_protected(lock, b"")
        except FileExistsError as error:
            raise AgentStateError("agent enrollment is already in progress") from error
        try:
            if self.load_record() is not None:
                raise AgentStateError("agent is already enrolled")
            yield
        finally:
            self._files.verify_protected_file(lock)
            lock.unlink()

    def clear(self) -> None:
        if self.path.exists():
            self._files.verify_protected_file(self.path)
            self.path.unlink()
        self._discard_pending_renewal()

    def _discard_pending_renewal(self, *, best_effort: bool = False) -> None:
        try:
            if self.renewal_path.exists():
                self._files.verify_protected_file(self.renewal_path)
                self.renewal_path.unlink()
        except Exception:
            if not best_effort:
                raise


class _IdentityView:
    def __init__(self, store: WindowsAgentStateStore):
        self._store = store

    def load(self):
        record = self._store.load_record()
        return record.endpoint_id if record else None

    def exists(self):
        return self.load() is not None

    def store(self, _):
        raise AgentStateError("use atomic enrollment state installation")


class _CredentialView:
    def __init__(self, store: WindowsAgentStateStore):
        self._store = store

    def load(self):
        record = self._store.load_record()
        if record is None or record.credential_expires_at <= datetime.now(timezone.utc):
            return None
        return AgentCredential(record.credential_id, record.credential_secret)

    def store(self, _):
        raise AgentStateError("use atomic enrollment state installation")

    def clear(self):
        self._store.clear()
