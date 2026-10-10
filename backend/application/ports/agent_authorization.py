"""Authentication and authorization ports for agent messages."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional, Protocol

from ...domain.endpoint import EndpointId
from ...domain.enrollment import CredentialId
from ...protocol.agent import AgentMessageEnvelope
from .agent_transport import PresentedCredential


@dataclass(frozen=True)
class AuthenticatedEndpointContext:
    endpoint_id: EndpointId
    credential_id: CredentialId
    authenticated_at: datetime
    authentication_method: str = "opaque"


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str = ""
    code: str = "allowed"


class EndpointAuthenticator(Protocol):
    def authenticate(self, envelope: AgentMessageEnvelope, presented: PresentedCredential, now: datetime) -> AuthenticatedEndpointContext: ...


class AgentMessageAuthorizer(Protocol):
    def authorize(self, context: AuthenticatedEndpointContext, envelope: AgentMessageEnvelope) -> AuthorizationDecision: ...


class AuditEventSink(Protocol):
    def emit(self, event_type: str, *, endpoint_id: Optional[EndpointId] = None, details: Optional[Mapping[str, Any]] = None) -> None: ...


class NullAuditEventSink:
    def emit(self, event_type: str, *, endpoint_id=None, details=None) -> None:
        return None
