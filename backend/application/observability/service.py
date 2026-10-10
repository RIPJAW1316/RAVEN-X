"""Organization-scoped security observability.

Answers the operational questions the audit trail deliberately no longer
carries per-event: how much authorization traffic is there, how much of it is
denied, and is anything anomalous right now.

The tenant is taken from the resolved `OrganizationContext`, never from the
request, so a caller cannot read another tenant's telemetry. Authorization
reuses `AUDIT_READ`: this view is an aggregate over exactly the data that
permission already grants row-level access to, so it exposes nothing extra.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Tuple

from ...domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource,
                                PrincipalType)
from ...domain.security_signals import (AuthenticationCounts, AuthorizationCounts, SecuritySignal,
                                        SignalThresholds, evaluate_signals)
from ..organization.context import OrganizationContext

DEFAULT_WINDOW_MINUTES = 15
MAX_WINDOW_MINUTES = 60


@dataclass(frozen=True)
class SecurityObservabilitySnapshot:
    organization_id: str
    generated_at: datetime
    window_minutes: int
    authorization: AuthorizationCounts
    authentication: AuthenticationCounts
    operations: Mapping[str, int]
    signals: Tuple[SecuritySignal, ...]

    def to_dict(self):
        return {
            "organization_id": self.organization_id,
            "generated_at": self.generated_at.astimezone(timezone.utc).isoformat(),
            "window_minutes": self.window_minutes,
            "authorization": self.authorization.to_dict(),
            "authentication": self.authentication.to_dict(),
            "operations": dict(self.operations),
            "signals": [signal.to_dict() for signal in self.signals],
        }


class TenantSecurityObservabilityService:
    def __init__(self, telemetry, authorizer, *, thresholds: Optional[SignalThresholds] = None,
                 metrics=None, clock=None):
        self.telemetry = telemetry
        self.authorizer = authorizer
        self.thresholds = thresholds or SignalThresholds()
        self.metrics = metrics
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def snapshot(self, principal, context, *, window_minutes: int = DEFAULT_WINDOW_MINUTES
                 ) -> SecurityObservabilitySnapshot:
        self._require_human_context(principal, context)
        self._authorize(principal, context)
        window = self._window(window_minutes)

        organization_id = context.organization_id
        authorization = self.telemetry.authorization_counts(organization_id, window_minutes=window)
        # Sign-in happens before a tenant is chosen, so authentication telemetry
        # is process-wide and is reported as such rather than attributed here.
        authentication = self.telemetry.authentication_counts(window_minutes=window)
        operations = self.telemetry.operation_counts(organization_id, window_minutes=window)

        now = self.clock()
        signals = evaluate_signals(authorization, authentication, window_minutes=window,
                                   now=now, thresholds=self.thresholds)
        if self.metrics is not None:
            self.metrics.increment("security_observability.requests")
            if signals:
                self.metrics.increment("security_observability.signals_returned", len(signals))
        return SecurityObservabilitySnapshot(str(organization_id), now, window, authorization,
                                             authentication, operations, signals)

    @staticmethod
    def _window(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("window_minutes must be an integer")
        if value <= 0 or value > MAX_WINDOW_MINUTES:
            raise ValueError(f"window_minutes must be between 1 and {MAX_WINDOW_MINUTES}")
        return value

    @staticmethod
    def _require_human_context(principal, context):
        if getattr(principal, "principal_type", None) is not PrincipalType.HUMAN:
            raise PermissionError("human principal required")
        if not isinstance(context, OrganizationContext):
            raise PermissionError("organization context required")

    def _authorize(self, principal, context):
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.AUDIT_READ,
            AuthorizationResource("audit", None, {"organization_id": str(context.organization_id)}),
            organization_context=context))
        if not decision.allowed:
            raise PermissionError(getattr(decision, "reason_code", "permission_denied"))
