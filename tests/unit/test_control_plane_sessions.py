from datetime import datetime, timedelta, timezone

import pytest

from backend.application.control_plane.sessions import (
    AgentSession,
    AgentSessionRegistry,
    AgentSessionState,
    DuplicateAgentSessionError,
    UnknownAgentSessionError,
)
from backend.domain.endpoint import EndpointId


def _session(endpoint_id=None, *, state=AgentSessionState.CONNECTED, last_seen=None):
    return AgentSession(
        endpoint_id or EndpointId.new(), "1.0", "agent-test", state,
        last_seen or datetime.now(timezone.utc),
    )


def test_session_registry_rejects_duplicate_active_and_allows_reconnect_after_disconnect():
    registry = AgentSessionRegistry()
    first = _session()
    registry.register(first)
    with pytest.raises(DuplicateAgentSessionError):
        registry.register(_session(first.endpoint_id))

    disconnected = registry.mark_disconnected(first.endpoint_id)
    assert disconnected.state is AgentSessionState.DISCONNECTED
    replacement = _session(first.endpoint_id, state=AgentSessionState.READY)
    registry.register(replacement)
    assert registry.get(first.endpoint_id) == replacement


def test_session_registry_marks_stale_sessions_without_touching_disconnected():
    now = datetime.now(timezone.utc)
    registry = AgentSessionRegistry()
    stale = _session(last_seen=now - timedelta(minutes=10))
    fresh = _session(last_seen=now)
    disconnected = _session(state=AgentSessionState.DISCONNECTED, last_seen=now - timedelta(hours=1))
    registry.register(stale)
    registry.register(fresh)
    registry.register(disconnected)

    marked = registry.mark_stale(now, timedelta(minutes=5))
    assert len(marked) == 1
    assert marked[0].endpoint_id == stale.endpoint_id
    assert registry.get(stale.endpoint_id).state is AgentSessionState.DISCONNECTED
    assert registry.get(fresh.endpoint_id).state is AgentSessionState.CONNECTED
    assert registry.get(disconnected.endpoint_id).state is AgentSessionState.DISCONNECTED


def test_unknown_session_update_is_explicit():
    with pytest.raises(UnknownAgentSessionError):
        AgentSessionRegistry().update(_session())
