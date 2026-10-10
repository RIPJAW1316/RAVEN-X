"""Controlled, explicit presence reconciliation; not a generic scheduler."""

from dataclasses import dataclass
from datetime import datetime, timezone

from ...domain.endpoint import EndpointStatus
from ...domain.presence import PresenceState


@dataclass(frozen=True)
class PresenceMaintenanceResult:
    evaluated: int = 0
    unchanged: int = 0
    became_stale: int = 0
    became_offline: int = 0
    errors: int = 0


class PresenceMaintenanceRunner:
    def __init__(self, presence_service, *, batch_size=100, clock=None):
        if batch_size <= 0:
            raise ValueError("presence evaluation batch size must be positive")
        self.presence_service = presence_service
        self.batch_size = int(batch_size)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run_once(self, *, now=None):
        timestamp = now or self.clock()
        repository = self.presence_service.presence
        records = repository.list_all()[:self.batch_size]
        evaluated = unchanged = stale = offline = errors = 0
        for record in records:
            evaluated += 1
            try:
                before = record.state
                # evaluate() reloads the current snapshot immediately before
                # writing, so a newer heartbeat wins over an old scan.
                after = self.presence_service.evaluate(record.endpoint_id, now=timestamp)
                if after.state is before:
                    unchanged += 1
                elif after.state is PresenceState.STALE:
                    stale += 1
                elif after.state is PresenceState.OFFLINE:
                    offline += 1
            except Exception:
                errors += 1
        self.presence_service._metric("presence.evaluations_total", evaluated)
        self.presence_service._metric("presence.evaluation_errors_total", errors)
        return PresenceMaintenanceResult(evaluated, unchanged, stale, offline, errors)
