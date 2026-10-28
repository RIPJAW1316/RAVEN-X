"""Bounded, redacted read contracts for the organization security activity feed.

Stored `SecurityAuditEvent` records are an internal forensic structure: their
metadata carries operator email addresses, session identifiers, credential
identifiers and other values that must not reach a tenant-facing feed.

`AuditEventView` is therefore a deliberate projection, not a serialization of
the stored record. Metadata is reduced to an explicit allowlist rather than a
deny-list, so a key added later to an audit write cannot leak by default.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional, Tuple


class AuditSeverity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class AuditOutcomeFilter(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILED = "failed"


MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25
MAX_FILTER_VALUES = 10
MAX_EVENT_TYPE_LENGTH = 100
MAX_ACTOR_LENGTH = 255

# Every authorized request writes one `authorization.allowed` record. That trace
# is valuable forensically but swamps an operator feed by two orders of
# magnitude, so it is excluded unless explicitly requested. The exclusion is an
# explicit, documented query flag rather than a hidden filter: callers can
# always retrieve the complete history with include_permission_checks=true.
PERMISSION_CHECK_EVENT_TYPES = ("authorization.allowed",)

# Event types that represent a security control rejecting something. These are
# what an operator needs to see first in an incident.
_CRITICAL_EVENT_TYPES = frozenset({
    "authorization.denied",
    "agent.message_replay_rejected",
    "agent.message_authorization_denied",
    "credential.authentication_failed",
    # A second, different successor proposed for an already-renewed credential:
    # either corrupted agent state or two holders of one credential.
    "credential.renewal_conflict",
    "credential.lineage_revoked",
    "enrollment.consumption_failed",
    "human.authentication_failed",
    "human.authentication_rate_limited",
    "organization.context_denied",
})

# Lifecycle removals and degradations: meaningful, not alarming on their own.
_WARNING_EVENT_TYPES = frozenset({
    "role.disabled", "role.revoked", "role_binding.disabled", "role_binding.revoked",
    "organization.suspended", "organization.revoked",
    "membership.suspended", "membership.revoked",
    "user.disabled", "user.revoked",
    "session.revoked", "session.expired",
    "endpoint.revoked", "endpoint.presence_offline", "endpoint.presence_stale",
    "enrollment.revoked", "credential.revoked", "credential.rotated",
    "assessment.failed", "assessment.delivery_failed", "assessment.expired",
    "assessment.cancel_requested", "assessment.cancelled",
})


class AuditEventClass(str, Enum):
    """Why an event is retained, per docs/architecture/audit-event-policy.md.

    OPERATIONAL  a security-relevant action a tenant performed or that happened
                 to their estate. Always persisted.
    SECURITY     a control rejecting something. Always persisted; never
                 suppressed by configuration.
    DIAGNOSTIC   internal authorization telemetry. Not persisted by default —
                 it is an implementation detail, not an audit record.
    """
    OPERATIONAL = "operational"
    SECURITY = "security"
    DIAGNOSTIC = "diagnostic"


#: Successful permission checks. One user action produces several of these, so
#: persisting them turns the audit trail into a debug log (measured at 95% of
#: all rows before this policy). See AuthorizationAuditPolicy.
DIAGNOSTIC_EVENT_TYPES = frozenset({"authorization.allowed"})


def classify(event_type: str) -> AuditEventClass:
    """Classify an event type for retention and display."""
    normalized = (event_type or "").strip().lower()
    if normalized in DIAGNOSTIC_EVENT_TYPES:
        return AuditEventClass.DIAGNOSTIC
    if normalized in _CRITICAL_EVENT_TYPES:
        return AuditEventClass.SECURITY
    return AuditEventClass.OPERATIONAL


def derive_severity(event_type: str, outcome: str) -> AuditSeverity:
    """Classify an event for display.

    Severity is **derived**, not stored: the audit record has no severity
    column. The mapping is deterministic so the same event always renders the
    same way, and it is computed server-side so every client agrees.
    """
    normalized = (event_type or "").strip().lower()
    if normalized in _CRITICAL_EVENT_TYPES:
        return AuditSeverity.CRITICAL
    if outcome == AuditOutcomeFilter.DENIED.value:
        return AuditSeverity.CRITICAL
    if outcome == AuditOutcomeFilter.FAILED.value:
        return AuditSeverity.WARNING
    if normalized in _WARNING_EVENT_TYPES:
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


# Metadata keys safe to surface. Everything else is dropped.
#
# Excluded on purpose: login / email (operator PII), session_id, credential_id,
# replacement_credential_id, enrollment_id, client_key, request_id, digest —
# these are either personal data or identifiers that assist an attacker.
_ALLOWED_METADATA_KEYS = frozenset({
    "framework_id", "scope_type", "snapshot_id", "endpoint_count", "row_count", "format",
    "schedule_id", "scheduled_for", "target_type", "target_count", "resolved_count",
    "created_count", "skipped_count", "failed_count", "resolution_reason",
    "scanner_ids", "message_type", "previous_state", "state", "observed_at",
    "reason", "reason_code", "error_category", "duration_ms",
    "deleted_count", "candidate_count", "failure_count", "query_version",
    "capabilities_trust",
})

_MAX_METADATA_VALUE_LENGTH = 200
_MAX_METADATA_LIST_ITEMS = 10


def project_metadata(metadata: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    """Reduce stored metadata to the allowlisted, length-bounded subset."""
    if not isinstance(metadata, Mapping):
        return {}
    projected: dict[str, Any] = {}
    for key, value in metadata.items():
        name = str(key)
        if name not in _ALLOWED_METADATA_KEYS:
            continue
        projected[name] = _bound(value)
    return projected


def _bound(value: Any) -> Any:
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return value
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [_bound(item) for item in list(value)[:_MAX_METADATA_LIST_ITEMS]]
    return str(value)[:_MAX_METADATA_VALUE_LENGTH]


@dataclass(frozen=True)
class AuditActor:
    """Who performed the action, without revealing contact details."""
    principal_type: str
    principal_id: Optional[str] = None
    user_id: Optional[str] = None

    def to_dict(self):
        return {"principal_type": self.principal_type, "principal_id": self.principal_id,
                "user_id": self.user_id}


@dataclass(frozen=True)
class AuditResource:
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None

    def to_dict(self):
        return {"resource_type": self.resource_type, "resource_id": self.resource_id}


@dataclass(frozen=True)
class AuditEventView:
    event_id: str
    event_type: str
    occurred_at: datetime
    outcome: str
    severity: AuditSeverity
    actor: AuditActor
    resource: Optional[AuditResource] = None
    action: Optional[str] = None
    reason_code: Optional[str] = None
    endpoint_id: Optional[str] = None
    assessment_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat(),
            "outcome": self.outcome,
            "severity": self.severity.value,
            "actor": self.actor.to_dict(),
            "resource": self.resource.to_dict() if self.resource else None,
            "action": self.action,
            "reason_code": self.reason_code,
            "endpoint_id": self.endpoint_id,
            "assessment_id": self.assessment_id,
            "correlation_id": self.correlation_id,
            "metadata": dict(self.metadata),
        }


def view_from_event(event) -> AuditEventView:
    """Project a stored `SecurityAuditEvent` into its safe read model."""
    outcome = getattr(event.outcome, "value", str(event.outcome))
    action = getattr(event.action, "value", event.action) if event.action is not None else None
    resource = None
    if event.resource is not None and event.resource.resource_type:
        # Resource metadata is dropped entirely: it is an authorization input,
        # not something the activity feed needs.
        resource = AuditResource(event.resource.resource_type, event.resource.resource_id)
    return AuditEventView(
        event_id=str(event.event_id),
        event_type=event.event_type,
        occurred_at=event.occurred_at,
        outcome=outcome,
        severity=derive_severity(event.event_type, outcome),
        actor=AuditActor(event.principal.principal_type.value, event.principal.principal_id, event.user_id),
        resource=resource,
        action=action if isinstance(action, str) else None,
        reason_code=event.reason_code,
        endpoint_id=event.endpoint_id,
        assessment_id=event.assessment_id,
        correlation_id=event.correlation_id,
        metadata=project_metadata(event.metadata),
    )


@dataclass(frozen=True)
class AuditQuery:
    """Validated, bounded audit feed query.

    Every bound is enforced here so an unvalidated query can never reach the
    database layer.
    """
    event_types: Tuple[str, ...] = ()
    outcomes: Tuple[str, ...] = ()
    severities: Tuple[str, ...] = ()
    actor_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    occurred_after: Optional[datetime] = None
    occurred_before: Optional[datetime] = None
    include_permission_checks: bool = False
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0

    @property
    def excluded_event_types(self) -> Tuple[str, ...]:
        """Event types suppressed by this query, for the caller to display."""
        if self.include_permission_checks:
            return ()
        # An explicit event_type filter is always honoured verbatim: asking for
        # permission checks by name must return them.
        if self.event_types:
            return ()
        return PERMISSION_CHECK_EVENT_TYPES

    def __post_init__(self):
        if not isinstance(self.include_permission_checks, bool):
            raise ValueError("include_permission_checks must be a boolean")
        object.__setattr__(self, "event_types", _string_tuple(self.event_types, "event_types", MAX_EVENT_TYPE_LENGTH))
        object.__setattr__(self, "outcomes", tuple(AuditOutcomeFilter(value).value for value in
                                                   dict.fromkeys(str(item).strip().lower() for item in self.outcomes if str(item).strip())))
        if len(self.outcomes) > MAX_FILTER_VALUES:
            raise ValueError("outcomes supports at most 10 values")
        object.__setattr__(self, "severities", tuple(AuditSeverity(value).value for value in
                                                     dict.fromkeys(str(item).strip().lower() for item in self.severities if str(item).strip())))
        if len(self.severities) > MAX_FILTER_VALUES:
            raise ValueError("severities supports at most 10 values")
        for name, bound in (("actor_id", MAX_ACTOR_LENGTH), ("endpoint_id", MAX_ACTOR_LENGTH)):
            value = getattr(self, name)
            if value is not None:
                text = str(value).strip()
                if not text:
                    object.__setattr__(self, name, None)
                    continue
                if len(text) > bound:
                    raise ValueError(f"{name} must be at most {bound} characters")
                object.__setattr__(self, name, text)
        for name in ("occurred_after", "occurred_before"):
            value = getattr(self, name)
            if value is not None:
                if not isinstance(value, datetime):
                    raise ValueError(f"{name} must be a datetime")
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError(f"{name} must be timezone-aware")
        if (self.occurred_after is not None and self.occurred_before is not None
                and self.occurred_after > self.occurred_before):
            raise ValueError("occurred_after must not be later than occurred_before")
        if not isinstance(self.limit, int) or isinstance(self.limit, bool):
            raise ValueError("limit must be an integer")
        if self.limit <= 0 or self.limit > MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if not isinstance(self.offset, int) or isinstance(self.offset, bool) or self.offset < 0:
            raise ValueError("offset must be a non-negative integer")


def _string_tuple(values, name, max_length):
    cleaned = tuple(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))
    if len(cleaned) > MAX_FILTER_VALUES:
        raise ValueError(f"{name} supports at most {MAX_FILTER_VALUES} values")
    if any(len(item) > max_length for item in cleaned):
        raise ValueError(f"{name} values must be at most {max_length} characters")
    return cleaned


@dataclass(frozen=True)
class AuditPage:
    """Paged audit result using the same shape as the fleet query page."""
    items: Tuple[AuditEventView, ...]
    limit: int
    offset: int
    total: int
    #: Event types this query suppressed, so the client can say so explicitly.
    excluded_event_types: Tuple[str, ...] = ()

    @property
    def returned(self) -> int:
        return len(self.items)

    @property
    def has_next(self) -> bool:
        return self.offset + self.returned < self.total

    def to_dict(self):
        return {
            "items": [item.to_dict() for item in self.items],
            "pagination": {
                "limit": self.limit,
                "offset": self.offset,
                "returned": self.returned,
                "total": self.total,
                "has_next": self.has_next,
            },
            "excluded_event_types": list(self.excluded_event_types),
        }
