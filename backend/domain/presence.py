"""Pure endpoint liveness contracts driven by server-observed heartbeats."""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional


class PresenceState(str, Enum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"


@dataclass(frozen=True)
class PresencePolicy:
    heartbeat_interval_seconds: int = 60
    stale_after_seconds: int = 180
    offline_after_seconds: int = 600

    def __post_init__(self):
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat interval must be positive")
        if self.stale_after_seconds <= self.heartbeat_interval_seconds:
            raise ValueError("stale threshold must exceed heartbeat interval")
        if self.offline_after_seconds <= self.stale_after_seconds:
            raise ValueError("offline threshold must exceed stale threshold")


@dataclass(frozen=True)
class EndpointPresence:
    endpoint_id: str
    organization_id: Optional[str] = None
    state: PresenceState = PresenceState.UNKNOWN
    last_seen_at: Optional[datetime] = None
    last_heartbeat_at: Optional[datetime] = None
    connected_since: Optional[datetime] = None
    stale_since: Optional[datetime] = None
    offline_since: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if not isinstance(self.endpoint_id, str) or not self.endpoint_id.strip():
            raise ValueError("endpoint_id is required")
        object.__setattr__(self, "state", PresenceState(self.state))
        for name in ("last_seen_at", "last_heartbeat_at", "connected_since", "stale_since", "offline_since", "updated_at"):
            value = getattr(self, name)
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"{name} must be timezone-aware")

    def to_dict(self):
        return {"endpoint_id": self.endpoint_id, "organization_id": self.organization_id,
                "state": self.state.value, "last_seen_at": _iso(self.last_seen_at),
                "last_heartbeat_at": _iso(self.last_heartbeat_at), "connected_since": _iso(self.connected_since),
                "stale_since": _iso(self.stale_since), "offline_since": _iso(self.offline_since),
                "updated_at": _iso(self.updated_at)}


class EndpointPresenceEvaluator:
    @staticmethod
    def evaluate(presence: EndpointPresence, now: datetime, policy: PresencePolicy) -> EndpointPresence:
        _aware(now)
        if presence.last_seen_at is None:
            return presence if presence.state is PresenceState.UNKNOWN else replace(presence, state=PresenceState.UNKNOWN, updated_at=now)
        age = now.astimezone(timezone.utc) - presence.last_seen_at.astimezone(timezone.utc)
        if age < timedelta(seconds=policy.stale_after_seconds):
            state = PresenceState.ONLINE
        elif age < timedelta(seconds=policy.offline_after_seconds):
            state = PresenceState.STALE
        else:
            state = PresenceState.OFFLINE
        if state is presence.state:
            return presence
        return replace(presence, state=state,
                       stale_since=now if state is PresenceState.STALE else presence.stale_since,
                       offline_since=now if state is PresenceState.OFFLINE else presence.offline_since,
                       updated_at=now)


def _aware(value):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")


def _iso(value):
    return value.astimezone(timezone.utc).isoformat() if value else None
