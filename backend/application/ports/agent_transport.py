"""Transport-neutral boundaries for future agent connections."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from ...protocol.agent import AgentMessageEnvelope
from ...domain.enrollment import CredentialId


@dataclass(frozen=True)
class PresentedCredential:
    """Credential proof kept outside normal protocol payloads."""

    secret: str
    method: str = "opaque"
    credential_id: CredentialId = None

    def __post_init__(self) -> None:
        if not self.secret:
            raise ValueError("presented credential must not be empty")
        if self.credential_id is not None and not isinstance(self.credential_id, CredentialId):
            object.__setattr__(self, "credential_id", CredentialId(self.credential_id))

    def __repr__(self) -> str:
        return "PresentedCredential(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True)
class TransportContext:
    received_at: datetime
    transport_kind: str = "in_process"
    remote_address: str = ""

    def __post_init__(self) -> None:
        if self.received_at.tzinfo is None or self.received_at.utcoffset() is None:
            raise ValueError("received_at must be timezone-aware")


class AgentMessageReceiver(Protocol):
    def receive(self, raw_message: bytes, credential: PresentedCredential): ...


class AgentMessageSender(Protocol):
    def send(self, envelope: AgentMessageEnvelope) -> None: ...


class InMemoryAgentMessageSender:
    """Test/local sender proving outbound transport remains replaceable."""
    def __init__(self):
        self.messages = []

    def send(self, envelope: AgentMessageEnvelope) -> None:
        self.messages.append(envelope)
