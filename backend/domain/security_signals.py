"""Deterministic security signal detection over windowed telemetry.

This is rule-based, not statistical and not machine learning. Every signal is
reproducible from its inputs and carries the numbers that produced it, so an
operator can check the reasoning rather than trust a score.

Two guards keep false positives down on small samples:

* an **absolute floor** — one denial out of one attempt is 100% but is not an
  incident, so a rule only fires once enough events have occurred;
* a **rate threshold** — volume alone is not suspicious for a large busy
  tenant, so the proportion must also be abnormal.

Both must hold. The thresholds are explicit values on `SignalThresholds`, not
magic numbers buried in the rules.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Tuple


class SecuritySignalType(str, Enum):
    AUTHORIZATION_DENIAL_SPIKE = "authorization.denial_spike"
    REPEATED_AUTHENTICATION_FAILURE = "authentication.repeated_failure"
    CROSS_TENANT_PROBING = "authorization.cross_tenant_probing"
    SENSITIVE_ACTION_DENIALS = "authorization.sensitive_action_denials"


class SecuritySignalSeverity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


#: Deny reasons that indicate a caller reaching outside its own tenant, rather
#: than simply lacking a permission inside it.
BOUNDARY_REASON_CODES = frozenset({
    "resource_organization_mismatch",
    "membership_context_mismatch",
    "principal_context_mismatch",
})


@dataclass(frozen=True)
class SignalThresholds:
    """Tunable detection thresholds. Defaults are deliberately conservative."""

    #: Minimum denials in the window before a denial-rate rule can fire.
    denial_floor: int = 20
    #: Denials / attempts above which the denial rate is abnormal.
    denial_rate: float = 0.4
    #: Denial count at which the spike is treated as critical rather than warning.
    denial_critical_floor: int = 60

    #: Minimum failed authentications in the window before firing.
    authentication_failure_floor: int = 10
    authentication_failure_critical_floor: int = 30

    #: Minimum boundary-reason denials before cross-tenant probing fires.
    boundary_denial_floor: int = 5

    #: Minimum denials against a single action before it is called out.
    action_denial_floor: int = 15

    def __post_init__(self):
        for name in ("denial_floor", "denial_critical_floor", "authentication_failure_floor",
                     "authentication_failure_critical_floor", "boundary_denial_floor",
                     "action_denial_floor"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not 0 < self.denial_rate <= 1:
            raise ValueError("denial_rate must be between 0 and 1")
        if self.denial_critical_floor < self.denial_floor:
            raise ValueError("denial_critical_floor must not be below denial_floor")
        if self.authentication_failure_critical_floor < self.authentication_failure_floor:
            raise ValueError("authentication critical floor must not be below its floor")


@dataclass(frozen=True)
class SecuritySignal:
    signal_type: SecuritySignalType
    severity: SecuritySignalSeverity
    detected_at: datetime
    window_minutes: int
    #: Human-readable explanation naming the numbers that fired the rule.
    reason: str
    #: The counts that produced the signal, so the operator can verify it.
    evidence: Mapping[str, Any] = field(default_factory=dict)
    #: What the signal is about, e.g. an action name. Never free-form input.
    scope: str = "organization"

    def __post_init__(self):
        if self.detected_at.tzinfo is None or self.detected_at.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")

    def to_dict(self):
        return {
            "signal_type": self.signal_type.value,
            "severity": self.severity.value,
            "detected_at": self.detected_at.astimezone(timezone.utc).isoformat(),
            "window_minutes": self.window_minutes,
            "scope": self.scope,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class AuthorizationCounts:
    attempts: int = 0
    allowed: int = 0
    denied: int = 0
    #: denied broken down by deny reason code (closed set).
    denied_by_reason: Mapping[str, int] = field(default_factory=dict)
    #: denied broken down by action (closed set from AuthorizationAction).
    denied_by_action: Mapping[str, int] = field(default_factory=dict)

    @property
    def denial_rate(self) -> float:
        return (self.denied / self.attempts) if self.attempts else 0.0

    def to_dict(self):
        return {"attempts": self.attempts, "allowed": self.allowed, "denied": self.denied,
                "denial_rate": round(self.denial_rate, 4),
                "denied_by_reason": dict(self.denied_by_reason),
                "denied_by_action": dict(self.denied_by_action)}


@dataclass(frozen=True)
class AuthenticationCounts:
    success: int = 0
    failure: int = 0

    @property
    def failure_rate(self) -> float:
        total = self.success + self.failure
        return (self.failure / total) if total else 0.0

    def to_dict(self):
        return {"success": self.success, "failure": self.failure,
                "failure_rate": round(self.failure_rate, 4)}


def evaluate_signals(
    authorization: AuthorizationCounts,
    authentication: AuthenticationCounts,
    *,
    window_minutes: int,
    now: datetime,
    thresholds: SignalThresholds | None = None,
) -> Tuple[SecuritySignal, ...]:
    """Apply every rule and return the signals that fired, most severe first."""
    rules = thresholds or SignalThresholds()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    signals: list[SecuritySignal] = []

    signals.extend(_denial_spike(authorization, rules, window_minutes, now))
    signals.extend(_authentication_failures(authentication, rules, window_minutes, now))
    signals.extend(_cross_tenant_probing(authorization, rules, window_minutes, now))
    signals.extend(_sensitive_action_denials(authorization, rules, window_minutes, now))

    order = {SecuritySignalSeverity.CRITICAL: 0, SecuritySignalSeverity.WARNING: 1,
             SecuritySignalSeverity.INFO: 2}
    signals.sort(key=lambda signal: (order[signal.severity], signal.signal_type.value))
    return tuple(signals)


def _denial_spike(counts, rules, window_minutes, now):
    # Both guards must hold: enough denials to matter, and a rate that is
    # abnormal relative to traffic.
    if counts.denied < rules.denial_floor or counts.denial_rate < rules.denial_rate:
        return ()
    severity = (SecuritySignalSeverity.CRITICAL if counts.denied >= rules.denial_critical_floor
                else SecuritySignalSeverity.WARNING)
    percent = round(counts.denial_rate * 100, 1)
    return (SecuritySignal(
        SecuritySignalType.AUTHORIZATION_DENIAL_SPIKE, severity, now, window_minutes,
        reason=(f"{counts.denied} of {counts.attempts} authorization attempts were denied "
                f"({percent}%) in the last {window_minutes} minutes, above the "
                f"{int(rules.denial_rate * 100)}% threshold."),
        evidence={"denied": counts.denied, "attempts": counts.attempts,
                  "denial_rate": round(counts.denial_rate, 4),
                  "threshold_rate": rules.denial_rate, "threshold_floor": rules.denial_floor}),)


def _authentication_failures(counts, rules, window_minutes, now):
    if counts.failure < rules.authentication_failure_floor:
        return ()
    severity = (SecuritySignalSeverity.CRITICAL
                if counts.failure >= rules.authentication_failure_critical_floor
                else SecuritySignalSeverity.WARNING)
    return (SecuritySignal(
        SecuritySignalType.REPEATED_AUTHENTICATION_FAILURE, severity, now, window_minutes,
        reason=(f"{counts.failure} failed sign-in attempts in the last {window_minutes} "
                f"minutes (threshold {rules.authentication_failure_floor})."),
        evidence={"failure": counts.failure, "success": counts.success,
                  "threshold_floor": rules.authentication_failure_floor}),)


def _cross_tenant_probing(counts, rules, window_minutes, now):
    boundary = {reason: count for reason, count in counts.denied_by_reason.items()
                if reason in BOUNDARY_REASON_CODES}
    total = sum(boundary.values())
    if total < rules.boundary_denial_floor:
        return ()
    return (SecuritySignal(
        SecuritySignalType.CROSS_TENANT_PROBING, SecuritySignalSeverity.CRITICAL, now,
        window_minutes,
        reason=(f"{total} authorization denials in the last {window_minutes} minutes were "
                f"tenant-boundary violations rather than missing permissions."),
        evidence={"boundary_denials": total, "by_reason": dict(sorted(boundary.items())),
                  "threshold_floor": rules.boundary_denial_floor}),)


def _sensitive_action_denials(counts, rules, window_minutes, now):
    signals = []
    for action, denied in sorted(counts.denied_by_action.items()):
        if denied < rules.action_denial_floor:
            continue
        signals.append(SecuritySignal(
            SecuritySignalType.SENSITIVE_ACTION_DENIALS, SecuritySignalSeverity.WARNING, now,
            window_minutes, scope=action,
            reason=(f"{denied} denied attempts against {action} in the last "
                    f"{window_minutes} minutes (threshold {rules.action_denial_floor})."),
            evidence={"action": action, "denied": denied,
                      "threshold_floor": rules.action_denial_floor}))
    return tuple(signals)
