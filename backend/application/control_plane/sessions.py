"""Ephemeral control-plane sessions, distinct from durable Endpoint identity."""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, Tuple

from ...domain.endpoint import EndpointId
from ...domain.scanner import TargetCapabilities


class AgentSessionState(str, Enum):
    CONNECTED = "connected"
    READY = "ready"
    BUSY = "busy"
    DEGRADED = "degraded"
    DISCONNECTED = "disconnected"


@dataclass(frozen=True)
class AgentSession:
    endpoint_id: EndpointId
    protocol_version: str
    agent_version: str
    state: AgentSessionState
    last_seen: datetime
    capabilities: TargetCapabilities = TargetCapabilities()
    runtime_state: Optional[str] = None
    transport: object = None

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if self.last_seen.tzinfo is None or self.last_seen.utcoffset() is None:
            raise ValueError("last_seen must be timezone-aware")
        object.__setattr__(self, "state", AgentSessionState(self.state))

    def is_stale(self, now: datetime, threshold: timedelta) -> bool:
        if now.tzinfo is None or now.utcoffset() is None or threshold < timedelta(0):
            raise ValueError("now must be aware and threshold must be non-negative")
        return now.astimezone(timezone.utc) - self.last_seen.astimezone(timezone.utc) > threshold


class DuplicateAgentSessionError(ValueError): ...


class UnknownAgentSessionError(KeyError): ...


class AgentSessionRegistry:
    def __init__(self):
        self._sessions = {}

    def register(self, session: AgentSession) -> None:
        if session.endpoint_id in self._sessions and self._sessions[session.endpoint_id].state is not AgentSessionState.DISCONNECTED:
            raise DuplicateAgentSessionError(f"active session already exists for {session.endpoint_id}")
        self._sessions[session.endpoint_id] = session

    def get(self, endpoint_id: EndpointId) -> Optional[AgentSession]:
        return self._sessions.get(endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(endpoint_id))

    def list(self) -> Tuple[AgentSession, ...]:
        return tuple(self._sessions.values())

    def update(self, session: AgentSession) -> AgentSession:
        if self.get(session.endpoint_id) is None:
            raise UnknownAgentSessionError(session.endpoint_id)
        self._sessions[session.endpoint_id] = session
        return session

    def mark_disconnected(self, endpoint_id: EndpointId, *, now: Optional[datetime] = None) -> AgentSession:
        session = self.get(endpoint_id)
        if session is None:
            raise UnknownAgentSessionError(endpoint_id)
        timestamp = now or datetime.now(timezone.utc)
        updated = replace(session, state=AgentSessionState.DISCONNECTED, last_seen=timestamp)
        self._sessions[session.endpoint_id] = updated
        return updated

    def mark_stale(self, now: datetime, threshold: timedelta) -> Tuple[AgentSession, ...]:
        stale = []
        for session in self.list():
            if session.state is not AgentSessionState.DISCONNECTED and session.is_stale(now, threshold):
                stale.append(self.update(replace(session, state=AgentSessionState.DISCONNECTED)))
        return tuple(stale)
