"""Small encrypted retry queue for completed assessment results."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from ..infrastructure.security import windows_files
from ..infrastructure.transport.http.client import HttpTransportError
from ..protocol.agent import AgentMessageEnvelope, AgentMessageType
from .windows_store import AgentStateError, DpapiMachineProtector


_MAX_MESSAGE_BYTES = 1_000_000
_MAX_PENDING_RESULTS = 16


class DurableResultSender:
    """Persist results before sending; transient progress failures may be retried by state polling."""

    def __init__(self, transport, directory: Path, *, protector=None, files=None):
        self.transport = transport
        self.directory = Path(directory)
        self._protector = protector or DpapiMachineProtector(max_bytes=_MAX_MESSAGE_BYTES)
        self._files = files or windows_files
        self._files.verify_directory(self.directory)

    def send(self, envelope: AgentMessageEnvelope) -> None:
        if envelope.message_type is AgentMessageType.ASSESSMENT_RESULT:
            self._enqueue(envelope)
            self.flush()
            return
        if envelope.message_type is AgentMessageType.ASSESSMENT_PROGRESS:
            try:
                self.transport.send(envelope)
            except HttpTransportError as error:
                if not _transient(error):
                    raise
            return
        self.transport.send(envelope)

    def flush(self) -> None:
        self._files.verify_directory(self.directory)
        paths = sorted(self.directory.glob("*.msg"))
        if len(paths) > _MAX_PENDING_RESULTS:
            raise AgentStateError("agent result queue exceeds its limit")
        for path in paths:
            self._files.verify_protected_file(path)
            raw = path.read_bytes()
            if len(raw) > _MAX_MESSAGE_BYTES + 4096:
                raise AgentStateError("agent result queue item exceeds its size limit")
            try:
                envelope = AgentMessageEnvelope.from_dict(json.loads(self._protector.unprotect(raw)))
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
                raise AgentStateError("agent result queue item is invalid") from error
            if envelope.message_type is not AgentMessageType.ASSESSMENT_RESULT:
                raise AgentStateError("agent result queue contains non-result traffic")
            try:
                self.transport.send(envelope)
            except HttpTransportError as error:
                if error.status_code != 409:
                    raise
                # A timeout after successful acceptance can be followed by a
                # replay rejection. The same message_id is already recorded.
            path.unlink()

    def _enqueue(self, envelope: AgentMessageEnvelope) -> None:
        self._files.verify_directory(self.directory)
        paths = tuple(self.directory.glob("*.msg"))
        if len(paths) >= _MAX_PENDING_RESULTS:
            raise AgentStateError("agent result queue is full")
        name = str(UUID(str(envelope.message_id))) + ".msg"
        path = self.directory / name
        if path.exists():
            self._files.verify_protected_file(path)
            return
        plaintext = json.dumps(envelope.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(plaintext) > _MAX_MESSAGE_BYTES:
            raise AgentStateError("agent result exceeds its size limit")
        self._files.atomic_write_protected(path, self._protector.protect(plaintext))


def _transient(error: HttpTransportError) -> bool:
    return error.code in {"timeout", "network_error"} or bool(error.status_code and error.status_code >= 500)
