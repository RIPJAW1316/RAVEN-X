"""Controllable heartbeat scheduling primitive; no unmanaged background loop."""

from datetime import datetime, timezone

from .runtime import AgentLifecycleState


class HeartbeatScheduler:
    def __init__(self, agent, *, interval_seconds=None, clock=None):
        self.agent = agent
        self.interval_seconds = float(interval_seconds or agent.config.heartbeat_interval_seconds)
        if self.interval_seconds <= 0:
            raise ValueError("heartbeat interval must be positive")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def run_once(self, *, now=None):
        timestamp = now or self.clock()
        try:
            envelope = self.agent.heartbeat(now=timestamp)
            self.agent.sender.send(envelope)
            if self.agent.state is AgentLifecycleState.DEGRADED:
                self.agent.state = AgentLifecycleState.READY
            return envelope
        except Exception:
            # Network failure must not erase local identity or credential.
            if self.agent.endpoint_id is not None:
                self.agent.state = AgentLifecycleState.DEGRADED
            raise
