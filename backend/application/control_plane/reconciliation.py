"""Deterministic reconciliation between remote assessments and delivery work."""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from ...domain.agent_work import AgentWorkStatus
from ...domain.security import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal
from ..ports.agent_work_repository import WorkLeaseError
from .assessment_dispatch import RemoteAssessmentState


@dataclass(frozen=True)
class ReconciliationResult:
    assessment_id: str
    previous_state: RemoteAssessmentState
    state: RemoteAssessmentState
    changed: bool
    reason: str
    execution_timeout_detected: bool = False


class RemoteAssessmentReconciler:
    def __init__(self, assessment_repository, work_repository, *, execution_timeout: Optional[timedelta] = None,
                 audit_sink=None, principal: Optional[SecurityPrincipal] = None):
        self.assessments = assessment_repository
        self.work = work_repository
        if execution_timeout is not None and execution_timeout <= timedelta(0):
            raise ValueError("execution timeout must be positive")
        self.execution_timeout = execution_timeout
        self.audit_sink = audit_sink
        self.principal = principal or SecurityPrincipal.system()

    def reconcile(self, assessment_id: str, *, now: Optional[datetime] = None) -> ReconciliationResult:
        now = _utc(now or datetime.now(timezone.utc))
        assessment = self.assessments.get(assessment_id)
        if assessment is None:
            raise KeyError(assessment_id)
        previous = assessment.state
        if assessment.terminal:
            return ReconciliationResult(assessment_id, previous, previous, False, "terminal assessment preserved")
        work = self._work_for(assessment)
        if work is None:
            if self._execution_due(assessment, now):
                updated = self._timeout_assessment(assessment, now)
                self.assessments.update(updated)
                self._audit_transition(updated, "execution timed out without linked work")
                return ReconciliationResult(assessment_id, previous, updated.state, True,
                                            "execution timed out without linked work", True)
            return ReconciliationResult(assessment_id, previous, previous, False, "no linked work item")

        updated = assessment
        reason = "work state unchanged"
        if work.status is AgentWorkStatus.PENDING:
            if assessment.state in (RemoteAssessmentState.CREATED, RemoteAssessmentState.DISPATCHED):
                updated = replace(assessment, state=RemoteAssessmentState.QUEUED,
                                  queued_at=assessment.queued_at or now)
                reason = "work remains pending"
        elif work.status is AgentWorkStatus.LEASED:
            if assessment.state in (RemoteAssessmentState.CREATED, RemoteAssessmentState.QUEUED):
                updated = replace(assessment, state=RemoteAssessmentState.DISPATCHED,
                                  dispatched_at=assessment.dispatched_at or work.leased_at or now)
                reason = "work is leased for delivery"
        elif work.status is AgentWorkStatus.ACKNOWLEDGED:
            if assessment.state not in (RemoteAssessmentState.CANCEL_REQUESTED, RemoteAssessmentState.RUNNING):
                updated = replace(assessment, state=RemoteAssessmentState.RUNNING,
                                  acknowledged_at=assessment.acknowledged_at or work.acknowledged_at or now,
                                  started_at=assessment.started_at or work.acknowledged_at or now)
                reason = "agent acknowledged work"
        elif work.status is AgentWorkStatus.COMPLETED:
            reason = "work completed; awaiting accepted result" if assessment.result is None else "result already accepted"
        elif work.status is AgentWorkStatus.FAILED:
            if assessment.result is None and not work.acknowledged_at:
                updated = replace(assessment, state=RemoteAssessmentState.DELIVERY_FAILED,
                                  failed_at=assessment.failed_at or now, failure_code="WORK_MAX_ATTEMPTS",
                                  failure_reason=work.last_error or "maximum delivery attempts exhausted",
                                  error=assessment.error or work.last_error)
                reason = "delivery attempts exhausted before acknowledgment"
        elif work.status is AgentWorkStatus.EXPIRED:
            if assessment.result is None:
                updated = replace(assessment, state=RemoteAssessmentState.EXPIRED,
                                  failed_at=assessment.failed_at or now, failure_code="WORK_EXPIRED",
                                  failure_reason=work.last_error or "work expired before execution",
                                  error=assessment.error or work.last_error)
                reason = "work expired before execution"

        timed_out = False
        if self._execution_due(updated, now):
            # Stop redelivery before recording a terminal assessment.  A crash
            # between these writes leaves terminal work and a nonterminal
            # assessment, which the next reconciliation pass can finish.
            self._finish_timed_out_work(work, now)
            latest = self.assessments.get(assessment_id)
            if latest.terminal:
                return ReconciliationResult(assessment_id, previous, latest.state, False,
                                            "terminal assessment preserved")
            updated = self._timeout_assessment(updated, now)
            timed_out = True
            reason = "execution timed out; linked work terminalized"

        changed = updated != assessment
        if changed:
            self.assessments.update(updated)
            self._audit_transition(updated, reason)
        return ReconciliationResult(assessment_id, previous, updated.state, changed, reason, timed_out)

    def reconcile_all(self, *, now: Optional[datetime] = None) -> Tuple[ReconciliationResult, ...]:
        return tuple(self.reconcile(item.assessment_id, now=now) for item in self.assessments.list_non_terminal())

    def evaluate_timeouts(self, *, now: Optional[datetime] = None) -> Tuple[ReconciliationResult, ...]:
        """Explicit timeout evaluation; no worker or automatic redelivery is started."""
        return self.reconcile_all(now=now)

    def _work_for(self, assessment):
        items = self.work.list_for_endpoint(assessment.endpoint_id)
        matches = [item for item in items if item.assessment_id == assessment.assessment_id
                   and str(item.correlation_id) == str(assessment.correlation_id)]
        return sorted(matches, key=lambda item: item.created_at)[-1] if matches else None

    def _execution_due(self, assessment, now):
        return (self.execution_timeout is not None
                and assessment.state in (RemoteAssessmentState.RUNNING, RemoteAssessmentState.CANCEL_REQUESTED)
                and assessment.started_at is not None
                and now - assessment.started_at >= self.execution_timeout)

    @staticmethod
    def _timeout_assessment(assessment, now):
        return replace(assessment, state=RemoteAssessmentState.FAILED, failed_at=now,
                       execution_timeout_detected_at=now, failure_code="EXECUTION_TIMEOUT",
                       failure_reason="remote execution exceeded the configured timeout",
                       error="remote execution timed out")

    def _finish_timed_out_work(self, work, now):
        """Make linked work terminal using existing ownership checked writes."""
        for _ in range(3):
            latest = self.work.get(work.work_id)
            if latest is None:
                raise WorkLeaseError("linked work disappeared during timeout handling")
            if latest.status in (AgentWorkStatus.COMPLETED, AgentWorkStatus.FAILED,
                                 AgentWorkStatus.EXPIRED, AgentWorkStatus.CANCELLED):
                return
            try:
                if latest.status in (AgentWorkStatus.PENDING, AgentWorkStatus.LEASED):
                    self.work.cancel(latest.work_id, latest.endpoint_id, now=now)
                elif latest.status is AgentWorkStatus.ACKNOWLEDGED:
                    self.work.complete(latest.endpoint_id, latest.assessment_id, latest.correlation_id,
                                       now=now, failed=True, error="remote execution timed out")
                else:
                    raise WorkLeaseError("linked work has an unsupported state")
                return
            except WorkLeaseError:
                # ACK, completion, or lease expiry may have won the race;
                # inspect current persisted state before deciding again.
                continue
        raise WorkLeaseError("linked work could not be terminalized")

    def _audit_transition(self, assessment, reason):
        if self.audit_sink is None:
            return
        event_type = {
            RemoteAssessmentState.QUEUED: SecurityAuditEventType.ASSESSMENT_QUEUED,
            RemoteAssessmentState.RUNNING: SecurityAuditEventType.ASSESSMENT_ACKNOWLEDGED,
            RemoteAssessmentState.COMPLETED: SecurityAuditEventType.ASSESSMENT_COMPLETED,
            RemoteAssessmentState.FAILED: SecurityAuditEventType.ASSESSMENT_FAILED,
            RemoteAssessmentState.DELIVERY_FAILED: SecurityAuditEventType.ASSESSMENT_DELIVERY_FAILED,
            RemoteAssessmentState.EXPIRED: SecurityAuditEventType.ASSESSMENT_EXPIRED,
        }.get(assessment.state)
        if event_type is not None:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=self.principal,
                outcome=SecurityAuditOutcome.FAILED if assessment.state in (
                    RemoteAssessmentState.FAILED, RemoteAssessmentState.DELIVERY_FAILED,
                    RemoteAssessmentState.EXPIRED) else SecurityAuditOutcome.SUCCESS,
                reason_code=assessment.failure_code, endpoint_id=str(assessment.endpoint_id),
                assessment_id=assessment.assessment_id, correlation_id=str(assessment.correlation_id),
                organization_id=str(assessment.organization_id) if assessment.organization_id else None,
                metadata={"reason": reason},
            ))


def _utc(value):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)
