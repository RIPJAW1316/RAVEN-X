"""Authenticated control-plane handlers for agent reports and remote results."""

from dataclasses import replace
from datetime import datetime, timezone

from ...protocol.agent import (
    AgentCapabilityReport, AgentHeartbeat, AgentMessageType, AgentStatusReport,
    AssessmentAcknowledgment, AssessmentProgress, AssessmentResultPayload,
)
from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.agent_work import AgentWorkStatus
from ...domain.security import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal
from .assessment_dispatch import DuplicateTerminalResultError, RemoteAssessmentState
from .sessions import AgentSession, AgentSessionRegistry, AgentSessionState


class ControlPlaneAgentHandlers:
    def __init__(self, sessions: AgentSessionRegistry, assessments, work_repository=None, audit_sink=None, endpoint_repository=None, presence_service=None):
        self.sessions = sessions
        self.assessments = assessments
        self.work_repository = work_repository
        self.audit_sink = audit_sink
        self.endpoint_repository = endpoint_repository
        self.presence_service = presence_service

    def register_routes(self, router) -> None:
        router.register(AgentMessageType.HEARTBEAT, AgentHeartbeat, self.heartbeat)
        router.register(AgentMessageType.CAPABILITIES, AgentCapabilityReport, self.capabilities)
        router.register(AgentMessageType.STATUS, AgentStatusReport, self.status)
        router.register(AgentMessageType.ASSESSMENT_ACK, AssessmentAcknowledgment, self.acknowledge)
        router.register(AgentMessageType.ASSESSMENT_PROGRESS, AssessmentProgress, self.progress)
        router.register(AgentMessageType.ASSESSMENT_RESULT, AssessmentResultPayload, self.result)

    def heartbeat(self, context, payload, envelope=None):
        if payload.endpoint_id != context.endpoint_id:
            raise ValueError("heartbeat endpoint mismatch")
        # The control-plane receipt clock is authoritative for presence.  The
        # agent timestamp remains observational protocol data only.
        now = datetime.now(timezone.utc)
        if self.presence_service is not None:
            self.presence_service.record_heartbeat(context.endpoint_id, receipt_at=now, observed_at=payload.observed_at)
        session_time = payload.observed_at
        existing = self.sessions.get(context.endpoint_id)
        if existing is None:
            self.sessions.register(AgentSession(context.endpoint_id, str(payload.protocol_version), payload.agent_version, AgentSessionState.READY, session_time))
        else:
            self.sessions.update(replace(existing, protocol_version=str(payload.protocol_version), agent_version=payload.agent_version, state=AgentSessionState.READY, last_seen=session_time))

    def capabilities(self, context, payload, envelope=None):
        if payload.endpoint_id != context.endpoint_id:
            raise ValueError("capability endpoint mismatch")
        session = self.sessions.get(context.endpoint_id)
        if session is None:
            self.sessions.register(AgentSession(context.endpoint_id, "1.0", "unknown", AgentSessionState.CONNECTED, payload.discovered_at, payload.capabilities))
        else:
            self.sessions.update(replace(session, capabilities=payload.capabilities, last_seen=payload.discovered_at))

    def status(self, context, payload, envelope=None):
        if payload.endpoint_id != context.endpoint_id:
            raise ValueError("status endpoint mismatch")
        session = self.sessions.get(context.endpoint_id)
        if session is not None:
            self.sessions.update(replace(session, protocol_version=str(payload.protocol_version), agent_version=payload.agent_version, runtime_state=payload.runtime_state.value, last_seen=datetime.now(timezone.utc), state=AgentSessionState.READY if payload.runtime_state.value == "running" else AgentSessionState.DEGRADED))

    def acknowledge(self, context, payload, envelope):
        receipt_at = datetime.now(timezone.utc)
        assessment = self.assessments.get(payload.assessment_id)
        if assessment is None or assessment.endpoint_id != context.endpoint_id or envelope.correlation_id != assessment.correlation_id:
            raise ValueError("assessment acknowledgment ownership mismatch")
        self._validate_tenant(context, assessment)
        if assessment.terminal or assessment.state is RemoteAssessmentState.CANCEL_REQUESTED:
            raise ValueError("assessment acknowledgment is no longer accepted")
        if self.work_repository is None:
            raise ValueError("durable work delivery is not configured")
        acknowledged = self.work_repository.acknowledge(payload.work_id, context.endpoint_id, payload.lease_token,
                                         assessment_id=payload.assessment_id, correlation_id=envelope.correlation_id,
                                         now=receipt_at)
        current = self.assessments.get(payload.assessment_id)
        if current is None or current.state in (RemoteAssessmentState.CANCELLED, RemoteAssessmentState.CANCEL_REQUESTED):
            raise ValueError("assessment was cancelled while acknowledgment was being processed")
        self.assessments.update(replace(current, state=RemoteAssessmentState.RUNNING,
                                        acknowledged_at=receipt_at, started_at=receipt_at))
        self._audit(SecurityAuditEventType.ASSESSMENT_ACKNOWLEDGED, context, envelope, payload.assessment_id)

    def progress(self, context, payload, envelope):
        receipt_at = datetime.now(timezone.utc)
        assessment = self.assessments.get(payload.assessment_id)
        if assessment is None or assessment.endpoint_id != context.endpoint_id or envelope.correlation_id != assessment.correlation_id:
            raise ValueError("assessment progress ownership mismatch")
        self._validate_tenant(context, assessment)
        if assessment.state in (RemoteAssessmentState.COMPLETED, RemoteAssessmentState.FAILED,
                                RemoteAssessmentState.DELIVERY_FAILED, RemoteAssessmentState.EXPIRED):
            raise ValueError("terminal assessment cannot receive progress")
        work_item = None
        if self.work_repository is not None:
            work_item = self.work_repository.mark_progress(context.endpoint_id, payload.assessment_id, envelope.correlation_id, now=receipt_at)
            if work_item is not None and work_item.status is AgentWorkStatus.CANCELLED:
                raise ValueError("cancelled work cannot receive progress")
        current = self.assessments.get(payload.assessment_id)
        if current is None or current.state is RemoteAssessmentState.CANCELLED:
            raise ValueError("cancelled assessment cannot receive progress")
        assessment = current
        state = assessment.state if assessment.state is RemoteAssessmentState.CANCEL_REQUESTED else (RemoteAssessmentState.RUNNING if payload.status == "running" else assessment.state)
        self.assessments.update(replace(assessment, state=state, progress=payload,
                                        started_at=assessment.started_at or receipt_at))

    def result(self, context, payload, envelope):
        receipt_at = datetime.now(timezone.utc)
        assessment = self.assessments.get(payload.assessment_id)
        if (assessment is None or assessment.endpoint_id != context.endpoint_id
                or EndpointId(payload.endpoint_id) != context.endpoint_id
                or envelope.correlation_id != assessment.correlation_id):
            raise ValueError("assessment result ownership mismatch")
        self._validate_tenant(context, assessment)
        if assessment.state in (RemoteAssessmentState.COMPLETED, RemoteAssessmentState.FAILED,
                                RemoteAssessmentState.DELIVERY_FAILED, RemoteAssessmentState.EXPIRED):
            raise DuplicateTerminalResultError(payload.assessment_id)
        if assessment.state is RemoteAssessmentState.CANCELLED:
            raise ValueError("cancelled assessment cannot receive a result")
        if (self.work_repository is not None and hasattr(self.work_repository, "complete_with_assessment")
                and hasattr(self.assessments, "_database_manager")):
            self.work_repository.complete_with_assessment(
                self.assessments, context.endpoint_id, payload.assessment_id, envelope.correlation_id,
                now=receipt_at, payload=payload,
            )
            state = RemoteAssessmentState.COMPLETED if payload.status.value == "completed" else RemoteAssessmentState.FAILED
            self._audit(SecurityAuditEventType.ASSESSMENT_COMPLETED if state is RemoteAssessmentState.COMPLETED else SecurityAuditEventType.ASSESSMENT_FAILED,
                        context, envelope, payload.assessment_id,
                        outcome=SecurityAuditOutcome.SUCCESS if state is RemoteAssessmentState.COMPLETED else SecurityAuditOutcome.FAILED)
            return
        if self.work_repository is not None:
            work_item = self.work_repository.complete(
                context.endpoint_id, payload.assessment_id, envelope.correlation_id,
                now=receipt_at,
                failed=payload.status.value != "completed", error=payload.error)
            if work_item is not None and work_item.status is AgentWorkStatus.CANCELLED:
                raise ValueError("cancelled work cannot receive a result")
        current = self.assessments.get(payload.assessment_id)
        if current is None or current.state is RemoteAssessmentState.CANCELLED:
            raise ValueError("cancelled assessment cannot receive a result")
        assessment = current
        state = RemoteAssessmentState.COMPLETED if payload.status.value == "completed" else RemoteAssessmentState.FAILED
        finished = receipt_at
        cancellation_metadata = assessment.state is RemoteAssessmentState.CANCEL_REQUESTED
        self.assessments.update(replace(assessment, state=state, result=payload, error=payload.error,
                                        completed_at=finished if state is RemoteAssessmentState.COMPLETED else None,
                                        failed_at=finished if state is RemoteAssessmentState.FAILED else None,
                                        failure_code=(assessment.failure_code if cancellation_metadata else
                                                      "RESULT_EXECUTION_FAILED" if state is RemoteAssessmentState.FAILED else None),
                                        failure_reason=(assessment.failure_reason if cancellation_metadata else
                                                         payload.error if state is RemoteAssessmentState.FAILED else None)))
        self._audit(SecurityAuditEventType.ASSESSMENT_COMPLETED if state is RemoteAssessmentState.COMPLETED else SecurityAuditEventType.ASSESSMENT_FAILED,
                    context, envelope, payload.assessment_id, outcome=SecurityAuditOutcome.SUCCESS if state is RemoteAssessmentState.COMPLETED else SecurityAuditOutcome.FAILED)

    def _audit(self, event_type, context, envelope, assessment_id, *, outcome=SecurityAuditOutcome.SUCCESS):
        if self.audit_sink is not None:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=SecurityPrincipal.endpoint(context.endpoint_id),
                outcome=outcome, endpoint_id=str(context.endpoint_id), assessment_id=assessment_id,
                correlation_id=str(envelope.correlation_id) if envelope.correlation_id else None,
                message_id=str(envelope.message_id), organization_id=str(self._assessment_organization(assessment_id)) if self._assessment_organization(assessment_id) else None,
                metadata={"message_type": envelope.message_type.value},
            ))

    def _assessment_organization(self, assessment_id):
        assessment = self.assessments.get(assessment_id)
        return assessment.organization_id if assessment is not None else None

    def _validate_tenant(self, context, assessment):
        if self.endpoint_repository is None:
            return
        endpoint = self.endpoint_repository.get(context.endpoint_id)
        if endpoint is None or endpoint.organization_id is None or assessment.organization_id != endpoint.organization_id:
            raise ValueError("assessment tenant ownership mismatch")
        if endpoint.status is not EndpointStatus.ACTIVE:
            raise ValueError("endpoint is not approved for assessment work")
        if self.work_repository is not None:
            items = self.work_repository.list_for_endpoint(context.endpoint_id)
            for item in items:
                if item.assessment_id == assessment.assessment_id and item.correlation_id == assessment.correlation_id:
                    if item.organization_id != assessment.organization_id:
                        raise ValueError("work tenant ownership mismatch")
