"""Machine-scoped DPAPI state for a Windows agent running as SYSTEM.

The encrypted record binds endpoint identity, credential lifetime, server URL,
and optional CA certificate digest in one atomic file. File confidentiality
depends on the verified Administrators/SYSTEM ACL: DPAPI machine scope alone
allows any local account that can read the blob to decrypt it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from ..domain.endpoint import EndpointId
from ..domain.enrollment import CredentialId
from ..infrastructure.security import windows_files
from .runtime import AgentCredential


_MAX_RECORD_BYTES = 8192


class AgentStateError(RuntimeError):
    pass


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
