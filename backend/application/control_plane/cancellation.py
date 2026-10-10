"""Safe control-plane cancellation semantics; no remote cancel command is sent."""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from ...domain.agent_work import AgentWorkStatus
from ...domain.endpoint import EndpointId
from ...domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent,
    SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal,
)
from .assessment_dispatch import RemoteAssessmentState


class CancellationOutcome(str, Enum):
    CANCELLED = "cancelled"
    CANCEL_REQUESTED = "cancel_requested"
    ALREADY_TERMINAL = "already_terminal"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class CancellationResult:
    assessment_id: str
    outcome: CancellationOutcome
    reason: str


class RemoteAssessmentCancellationService:
    def __init__(self, assessment_repository, work_repository, *, authorization_service=None, audit_sink=None,
                 principal: Optional[SecurityPrincipal] = None):
        self.assessments = assessment_repository
        self.work = work_repository
        self.authorization = authorization_service
        self.audit_sink = audit_sink
        self.principal = principal or SecurityPrincipal.system()

    def cancel(self, assessment_id: str, *, endpoint_id: Optional[EndpointId] = None,
               now: Optional[datetime] = None, principal: Optional[SecurityPrincipal] = None,
               organization_context=None) -> CancellationResult:
        now = _utc(now or datetime.now(timezone.utc))
        principal = principal or self.principal
        if organization_context is not None and hasattr(self.assessments, "get_for_organization"):
            assessment = self.assessments.get_for_organization(assessment_id, organization_context.organization_id)
        else:
            assessment = self.assessments.get(assessment_id)
        if assessment is None or endpoint_id is not None and assessment.endpoint_id != _endpoint(endpoint_id):
            return CancellationResult(assessment_id, CancellationOutcome.NOT_FOUND, "assessment was not found")
        if self.authorization is not None:
            request = AuthorizationRequest(
                principal, AuthorizationAction.ASSESSMENT_CANCEL,
                AuthorizationResource("assessment", assessment_id, {"endpoint_id": str(assessment.endpoint_id),
                                                                     "organization_id": str(assessment.organization_id) if assessment.organization_id else None}),
                organization_context=organization_context,
            )
            if hasattr(self.authorization, "authorize"):
                decision = self.authorization.authorize(request)
                if not decision.allowed:
                    raise PermissionError(decision.reason_code)
            else:
                self.authorization.require(request)
        if assessment.terminal:
            self._audit(SecurityAuditEventType.ASSESSMENT_CANCEL_REQUESTED, assessment, SecurityAuditOutcome.DENIED, "already_terminal", principal=principal)
            return CancellationResult(assessment_id, CancellationOutcome.ALREADY_TERMINAL, "terminal assessment was preserved")

        work = self._work_for(assessment)
        if work is None or work.status in (AgentWorkStatus.PENDING, AgentWorkStatus.LEASED):
            if work is not None:
                self.work.cancel(work.work_id, assessment.endpoint_id, now=now)
            self.assessments.update(replace(assessment, state=RemoteAssessmentState.CANCELLED,
                                             cancelled_at=now, failure_code="ASSESSMENT_CANCELLED",
                                             failure_reason="cancelled before acknowledgment", error="assessment cancelled"))
            self._audit(SecurityAuditEventType.ASSESSMENT_CANCELLED, assessment, SecurityAuditOutcome.SUCCESS, "ASSESSMENT_CANCELLED", principal=principal)
            return CancellationResult(assessment_id, CancellationOutcome.CANCELLED, "future delivery was cancelled")

        if work.status is AgentWorkStatus.ACKNOWLEDGED or assessment.state in (RemoteAssessmentState.RUNNING, RemoteAssessmentState.CANCEL_REQUESTED):
            if assessment.state is not RemoteAssessmentState.CANCEL_REQUESTED:
                self.assessments.update(replace(assessment, state=RemoteAssessmentState.CANCEL_REQUESTED,
                                                 cancel_requested_at=now, failure_code="ASSESSMENT_CANCEL_REQUESTED",
                                                 failure_reason="remote cancellation is not implemented"))
                self._audit(SecurityAuditEventType.ASSESSMENT_CANCEL_REQUESTED, assessment, SecurityAuditOutcome.SUCCESS, "ASSESSMENT_CANCEL_REQUESTED", principal=principal)
            return CancellationResult(assessment_id, CancellationOutcome.CANCEL_REQUESTED,
                                      "execution may already be running; cancellation intent recorded")

        return CancellationResult(assessment_id, CancellationOutcome.CANCEL_REQUESTED,
                                  "execution state is not safely cancellable")

    def _audit(self, event_type, assessment, outcome, reason_code, *, principal=None):
        if self.audit_sink is not None:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=principal or self.principal, outcome=outcome,
                reason_code=reason_code, endpoint_id=str(assessment.endpoint_id), assessment_id=assessment.assessment_id,
                correlation_id=str(assessment.correlation_id), organization_id=str(assessment.organization_id) if assessment.organization_id else None,
            ))

    def _work_for(self, assessment):
        items = self.work.list_for_endpoint(assessment.endpoint_id)
        matches = [item for item in items if item.assessment_id == assessment.assessment_id
                   and str(item.correlation_id) == str(assessment.correlation_id)]
        return sorted(matches, key=lambda item: item.created_at)[-1] if matches else None


def _endpoint(value):
    return value if isinstance(value, EndpointId) else EndpointId(value)


def _utc(value):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)
