"""Pure, bounded assessment scheduling contracts."""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..endpoint import EndpointId, EndpointStatus
from ..organization import OrganizationId


class _Id:
    def __init_subclass__(cls):
        cls.__str__ = lambda self: self.value
    value: str
    def __post_init__(self):
        try: object.__setattr__(self, "value", str(UUID(str(self.value))))
        except (TypeError, ValueError, AttributeError) as exc: raise ValueError("id must be a valid UUID") from exc
    @classmethod
    def new(cls): return cls(str(uuid4()))
    @classmethod
    def parse(cls, value): return cls(value)


@dataclass(frozen=True)
class AssessmentScheduleId(_Id):
    value: str


@dataclass(frozen=True)
class AssessmentScheduleRunId(_Id):
    value: str


class ScheduleStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    REVOKED = "revoked"


class ScheduleRunStatus(str, Enum):
    CREATED = "created"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


class ScheduleFrequency(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    INTERVAL = "interval"


class MisfirePolicy(str, Enum):
    COALESCE = "coalesce"


class OverlapPolicy(str, Enum):
    SKIP_IF_ACTIVE = "skip_if_active"

class ScheduleTargetType(str, Enum):
    EXPLICIT_ENDPOINTS = "explicit_endpoints"
    ENDPOINT_GROUP = "endpoint_group"
    SAVED_FLEET_SCOPE = "saved_fleet_scope"

@dataclass(frozen=True)
class AssessmentScheduleTarget:
    target_type: ScheduleTargetType
    endpoint_ids: tuple[EndpointId, ...] = ()
    reference_id: str | None = None
    def __post_init__(self):
        object.__setattr__(self,"target_type",ScheduleTargetType(self.target_type)); object.__setattr__(self,"endpoint_ids",tuple(x if isinstance(x,EndpointId) else EndpointId(x) for x in self.endpoint_ids))
        if self.target_type is ScheduleTargetType.EXPLICIT_ENDPOINTS:
            if not self.endpoint_ids or self.reference_id is not None: raise ValueError("explicit target requires endpoint_ids only")
        elif not isinstance(self.reference_id,str) or not self.reference_id.strip() or self.endpoint_ids:
            raise ValueError("referenced target requires reference_id only")
    def to_dict(self): return {"type":self.target_type.value,"endpoint_ids":[str(x) for x in self.endpoint_ids],"reference_id":self.reference_id}


def _aware(value, name):
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True)
class AssessmentRecurrence:
    frequency: ScheduleFrequency
    interval: int = 1
    hour: int | None = None
    minute: int | None = None
    days_of_week: tuple[int, ...] = ()
    timezone: str = "UTC"
    starts_at: datetime | None = None
    misfire_policy: MisfirePolicy = MisfirePolicy.COALESCE

    def __post_init__(self):
        object.__setattr__(self, "frequency", ScheduleFrequency(self.frequency))
        object.__setattr__(self, "misfire_policy", MisfirePolicy(self.misfire_policy))
        if self.interval < 1: raise ValueError("interval must be positive")
        if self.hour is not None and not 0 <= self.hour <= 23: raise ValueError("hour must be 0..23")
        if self.minute is not None and not 0 <= self.minute <= 59: raise ValueError("minute must be 0..59")
        days = tuple(sorted(set(self.days_of_week)))
        if any(day < 0 or day > 6 for day in days): raise ValueError("days_of_week must use 0..6")
        object.__setattr__(self, "days_of_week", days)
        try: ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, TypeError): raise ValueError("timezone must be a valid IANA timezone")
        if self.starts_at is not None: _aware(self.starts_at, "starts_at")
        if self.frequency is ScheduleFrequency.WEEKLY and not days: raise ValueError("weekly recurrence requires days_of_week")
        if self.frequency is ScheduleFrequency.INTERVAL and self.hour is not None: raise ValueError("interval recurrence does not use hour")

    def to_dict(self):
        return {"frequency": self.frequency.value, "interval": self.interval, "hour": self.hour,
                "minute": self.minute, "days_of_week": list(self.days_of_week), "timezone": self.timezone,
                "starts_at": self.starts_at.astimezone(timezone.utc).isoformat() if self.starts_at else None,
                "misfire_policy": self.misfire_policy.value}

    @classmethod
    def from_dict(cls, value):
        starts = value.get("starts_at")
        return cls(value["frequency"], int(value.get("interval", 1)), value.get("hour"), value.get("minute"),
                   tuple(value.get("days_of_week", ())), value.get("timezone", "UTC"),
                   datetime.fromisoformat(starts) if starts else None, value.get("misfire_policy", "coalesce"))


@dataclass(frozen=True)
class AssessmentSchedule:
    schedule_id: AssessmentScheduleId
    organization_id: OrganizationId
    name: str
    target_endpoint_ids: tuple[EndpointId, ...]
    scanner_ids: tuple[str, ...]
    recurrence: AssessmentRecurrence
    next_run_at: datetime
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    last_run_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str | None = None
    overlap_policy: OverlapPolicy = OverlapPolicy.SKIP_IF_ACTIVE
    metadata: Mapping[str, Any] = field(default_factory=dict)
    target: AssessmentScheduleTarget | None = None

    def __post_init__(self):
        object.__setattr__(self, "schedule_id", AssessmentScheduleId.parse(self.schedule_id))
        object.__setattr__(self, "organization_id", OrganizationId.parse(self.organization_id))
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name.strip()) > 200: raise ValueError("schedule name is required and must be <= 200 characters")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "status", ScheduleStatus(self.status)); object.__setattr__(self, "overlap_policy", OverlapPolicy(self.overlap_policy))
        object.__setattr__(self, "target_endpoint_ids", tuple(x if isinstance(x, EndpointId) else EndpointId(x) for x in self.target_endpoint_ids))
        target=self.target or AssessmentScheduleTarget(ScheduleTargetType.EXPLICIT_ENDPOINTS,self.target_endpoint_ids)
        if not isinstance(target,AssessmentScheduleTarget): target=AssessmentScheduleTarget(target["type"],tuple(target.get("endpoint_ids",())),target.get("reference_id"))
        if target.target_type is ScheduleTargetType.EXPLICIT_ENDPOINTS and tuple(target.endpoint_ids)!=self.target_endpoint_ids: raise ValueError("explicit target must match endpoint IDs")
        object.__setattr__(self,"target",target)
        object.__setattr__(self, "scanner_ids", tuple(str(x).strip() for x in self.scanner_ids if str(x).strip()))
        if not self.scanner_ids: raise ValueError("at least one scanner id is required")
        _aware(self.next_run_at, "next_run_at"); _aware(self.created_at, "created_at"); _aware(self.updated_at, "updated_at")
        if self.last_run_at is not None: _aware(self.last_run_at, "last_run_at")
        if self.updated_at < self.created_at: raise ValueError("updated_at cannot precede created_at")
        object.__setattr__(self, "metadata", dict(self.metadata or {}))

    def transition_to(self, status, now):
        status = ScheduleStatus(status); _aware(now, "updated_at")
        allowed = {ScheduleStatus.ACTIVE: {ScheduleStatus.PAUSED, ScheduleStatus.REVOKED}, ScheduleStatus.PAUSED: {ScheduleStatus.ACTIVE, ScheduleStatus.REVOKED}, ScheduleStatus.REVOKED: set()}
        if status not in allowed[self.status]: raise ValueError(f"schedule cannot transition from {self.status.value} to {status.value}")
        return replace(self, status=status, updated_at=now)

    def to_dict(self):
        return {"schedule_id": str(self.schedule_id), "organization_id": str(self.organization_id), "name": self.name,
                "status": self.status.value, "target_endpoint_ids": [str(x) for x in self.target_endpoint_ids],
                "targets": [str(x) for x in self.target_endpoint_ids],
                "scanner_ids": list(self.scanner_ids), "recurrence": self.recurrence.to_dict(),
                "next_run_at": self.next_run_at.astimezone(timezone.utc).isoformat(),
                "last_run_at": self.last_run_at.astimezone(timezone.utc).isoformat() if self.last_run_at else None,
                "created_at": self.created_at.astimezone(timezone.utc).isoformat(), "updated_at": self.updated_at.astimezone(timezone.utc).isoformat(),
                "created_by": self.created_by, "overlap_policy": self.overlap_policy.value, "target":self.target.to_dict()}


@dataclass(frozen=True)
class AssessmentScheduleRun:
    run_id: AssessmentScheduleRunId
    schedule_id: AssessmentScheduleId
    organization_id: OrganizationId
    scheduled_for: datetime
    started_at: datetime
    status: ScheduleRunStatus = ScheduleRunStatus.CREATED
    assessment_ids: tuple[str, ...] = ()
    target_outcomes: Mapping[str, str] = field(default_factory=dict)
    reason: str | None = None
    completed_at: datetime | None = None
    resolved_endpoint_ids: tuple[str, ...] = ()
    targets_resolved_at: datetime | None = None
    target_type: str | None = None
    target_reference_id: str | None = None
    scope_criteria_snapshot: Mapping[str, Any] = field(default_factory=dict)
    resolution_reason: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "run_id", AssessmentScheduleRunId.parse(self.run_id)); object.__setattr__(self, "schedule_id", AssessmentScheduleId.parse(self.schedule_id)); object.__setattr__(self, "organization_id", OrganizationId.parse(self.organization_id)); object.__setattr__(self, "status", ScheduleRunStatus(self.status))
        _aware(self.scheduled_for, "scheduled_for"); _aware(self.started_at, "started_at")
        if self.completed_at is not None: _aware(self.completed_at, "completed_at")
        if self.targets_resolved_at is not None: _aware(self.targets_resolved_at,"targets_resolved_at")
        object.__setattr__(self, "assessment_ids", tuple(self.assessment_ids)); object.__setattr__(self, "target_outcomes", dict(self.target_outcomes)); object.__setattr__(self,"resolved_endpoint_ids",tuple(str(x) for x in self.resolved_endpoint_ids)); object.__setattr__(self,"scope_criteria_snapshot",dict(self.scope_criteria_snapshot or {}))

    def to_dict(self):
        return {"run_id": str(self.run_id), "schedule_id": str(self.schedule_id), "organization_id": str(self.organization_id), "scheduled_for": self.scheduled_for.astimezone(timezone.utc).isoformat(), "started_at": self.started_at.astimezone(timezone.utc).isoformat(), "status": self.status.value, "assessment_ids": list(self.assessment_ids), "target_outcomes": dict(self.target_outcomes), "reason": self.reason, "completed_at": self.completed_at.astimezone(timezone.utc).isoformat() if self.completed_at else None,"resolved_endpoint_ids":list(self.resolved_endpoint_ids),"targets_resolved_at":self.targets_resolved_at.astimezone(timezone.utc).isoformat() if self.targets_resolved_at else None,"target_type":self.target_type,"target_reference_id":self.target_reference_id,"scope_criteria_snapshot":dict(self.scope_criteria_snapshot),"resolution_reason":self.resolution_reason}
