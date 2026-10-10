"""Control-plane remote assessment request and ephemeral tracking."""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Tuple
from uuid import uuid4

from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.agent_work import AgentWorkItem, AgentWorkStatus, WorkId
from ...protocol.agent import AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, CorrelationId, ProtocolVersion
from ...domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent,
    SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal,
)
from .sessions import AgentSessionRegistry, AgentSessionState


class EndpointUnavailableError(RuntimeError):
    def __init__(self, endpoint_id: str, assessment: Optional["RemoteAssessment"] = None):
        super().__init__(f"endpoint {endpoint_id} is unavailable")
        self.assessment = assessment
class EndpointRevokedError(RuntimeError): ...
class UnknownRemoteAssessmentError(KeyError): ...
class DuplicateTerminalResultError(ValueError): ...


class RemoteAssessmentState(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DELIVERY_FAILED = "delivery_failed"
    EXPIRED = "expired"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    ENDPOINT_UNAVAILABLE = "endpoint_unavailable"


@dataclass(frozen=True)
class RemoteAssessment:
    assessment_id: str
    endpoint_id: EndpointId
    correlation_id: CorrelationId
    scanner_ids: Tuple[str, ...]
    requested_at: datetime
    state: RemoteAssessmentState
    progress: object = None
    result: object = None
    error: Optional[str] = None
    queued_at: Optional[datetime] = None
    dispatched_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    cancel_requested_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    failure_code: Optional[str] = None
    failure_reason: Optional[str] = None
    execution_timeout_detected_at: Optional[datetime] = None
    organization_id: Optional[object] = None
    schedule_id: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if not isinstance(self.correlation_id, CorrelationId):
            object.__setattr__(self, "correlation_id", CorrelationId(self.correlation_id))
        if self.organization_id is not None:
            module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
            object.__setattr__(self, "organization_id", module.OrganizationId.parse(self.organization_id))
        object.__setattr__(self, "state", RemoteAssessmentState(self.state))
        if not self.assessment_id or not self.scanner_ids:
            raise ValueError("assessment_id and scanner_ids are required")
        for value, name in ((self.requested_at, "requested_at"), (self.queued_at, "queued_at"),
                            (self.dispatched_at, "dispatched_at"), (self.acknowledged_at, "acknowledged_at"),
                            (self.started_at, "started_at"), (self.completed_at, "completed_at"),
                            (self.failed_at, "failed_at"), (self.cancel_requested_at, "cancel_requested_at"),
                            (self.cancelled_at, "cancelled_at"), (self.expires_at, "expires_at"),
                            (self.execution_timeout_detected_at, "execution_timeout_detected_at")):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"{name} must be timezone-aware")

    @property
    def terminal(self) -> bool:
        return self.state in _TERMINAL_ASSESSMENT_STATES

    @property
    def created_at(self) -> datetime:
        """Stable naming alias for persistence/API consumers."""
        return self.requested_at

    @property
    def status(self) -> RemoteAssessmentState:
        return self.state

    @property
    def deadline(self) -> Optional[datetime]:
        return self.expires_at

    def to_dict(self):
        return {
            "assessment_id": self.assessment_id,
            "endpoint_id": str(self.endpoint_id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "correlation_id": str(self.correlation_id),
            "scanner_ids": list(self.scanner_ids),
            "requested_at": self.requested_at.isoformat(),
            "state": self.state.value,
            "progress": self.progress.to_dict() if hasattr(self.progress, "to_dict") else self.progress,
            "result": self.result.to_dict() if hasattr(self.result, "to_dict") else self.result,
            "error": self.error,
            "schedule_id": self.schedule_id,
        }


class RemoteAssessmentRegistry:
    def __init__(self):
        self._assessments = {}

    def add(self, assessment: RemoteAssessment) -> None:
        if assessment.assessment_id in self._assessments:
            raise ValueError("assessment already exists")
        if any(item.correlation_id == assessment.correlation_id for item in self._assessments.values()):
            raise ValueError("assessment correlation already exists")
        self._assessments[assessment.assessment_id] = assessment

    def get(self, assessment_id: str) -> Optional[RemoteAssessment]:
        return self._assessments.get(assessment_id)

    def update(self, assessment: RemoteAssessment) -> RemoteAssessment:
        existing = self._assessments.get(assessment.assessment_id)
        if existing is None:
            raise UnknownRemoteAssessmentError(assessment.assessment_id)
        if existing.terminal and assessment != existing:
            raise DuplicateTerminalResultError(assessment.assessment_id)
        if existing.organization_id != assessment.organization_id:
            raise ValueError("assessment organization ownership is immutable")
        self._assessments[assessment.assessment_id] = assessment
        return assessment

    def list(self) -> Tuple[RemoteAssessment, ...]:
        return tuple(self._assessments.values())

    def exists(self, assessment_id: str) -> bool:
        return assessment_id in self._assessments

    def list_non_terminal(self) -> Tuple[RemoteAssessment, ...]:
        return tuple(item for item in self._assessments.values() if not item.terminal)

    def get_for_organization(self, assessment_id, organization_id):
        assessment = self.get(assessment_id)
        return assessment if assessment is not None and assessment.organization_id == _organization_id(organization_id) else None

    def list_for_organization(self, organization_id):
        organization_id = _organization_id(organization_id)
        return tuple(item for item in self.list() if item.organization_id == organization_id)

    def exists_for_organization(self, assessment_id, organization_id):
        return self.get_for_organization(assessment_id, organization_id) is not None

    def list_for_endpoint_and_organization(self, endpoint_id, organization_id):
        endpoint_id = endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(endpoint_id); organization_id = _organization_id(organization_id)
        return tuple(item for item in self.list_for_organization(organization_id) if item.endpoint_id == endpoint_id)

    def list_for_schedule(self, schedule_id):
        return tuple(item for item in self.list() if item.schedule_id == str(schedule_id))


_TERMINAL_ASSESSMENT_STATES = frozenset({
    RemoteAssessmentState.COMPLETED, RemoteAssessmentState.FAILED,
    RemoteAssessmentState.DELIVERY_FAILED, RemoteAssessmentState.EXPIRED,
    RemoteAssessmentState.CANCELLED, RemoteAssessmentState.ENDPOINT_UNAVAILABLE,
})


class RemoteAssessmentDispatcher:
    def __init__(self, endpoint_registry, session_registry: AgentSessionRegistry, transport, assessments: RemoteAssessmentRegistry,
                 *, work_repository=None, work_ttl=None, authorization_service=None, audit_sink=None,
                 principal: Optional[SecurityPrincipal] = None):
        self._endpoint_registry = endpoint_registry
        self._sessions = session_registry
        self._transport = transport
        self._assessments = assessments
        self._work_repository = work_repository
        self._work_ttl = work_ttl
        self._authorization = authorization_service
        self._audit_sink = audit_sink
        self._principal = principal or SecurityPrincipal.system()

    def dispatch(self, endpoint_id: EndpointId, scanner_ids: Tuple[str, ...], *, requested_at: Optional[datetime] = None,
                 principal=None, organization_context=None, schedule_id=None) -> RemoteAssessment:
        if not isinstance(endpoint_id, EndpointId):
            endpoint_id = EndpointId(endpoint_id)
        endpoint = self._endpoint_registry.get(endpoint_id)
        if endpoint is None:
            raise KeyError(f"endpoint {endpoint_id} is not registered")
        if endpoint.status is EndpointStatus.REVOKED:
            raise EndpointRevokedError(str(endpoint_id))
        if endpoint.status is not EndpointStatus.ACTIVE:
            raise EndpointUnavailableError(str(endpoint_id))
        if self._authorization is not None:
            auth_request = AuthorizationRequest(
                principal or self._principal, AuthorizationAction.ASSESSMENT_CREATE,
                AuthorizationResource("endpoint", str(endpoint_id), {"endpoint_id": str(endpoint_id),
                                                                    "organization_id": str(endpoint.organization_id) if endpoint.organization_id else None}),
                organization_context=organization_context,
            )
            decision = self._authorization.authorize(auth_request) if hasattr(self._authorization, "authorize") else None
            if decision is not None:
                if not decision.allowed:
                    raise PermissionError(decision.reason_code)
            else:
                self._authorization.require(auth_request)
        timestamp = requested_at or datetime.now(timezone.utc)
        session = self._sessions.get(endpoint_id)
        unavailable = endpoint.status is EndpointStatus.OFFLINE or session is None or session.state in (AgentSessionState.DISCONNECTED, AgentSessionState.DEGRADED)
        if unavailable and self._work_repository is None:
            unavailable = RemoteAssessment(str(uuid4()), endpoint_id, CorrelationId(), tuple(scanner_ids), timestamp, RemoteAssessmentState.ENDPOINT_UNAVAILABLE,
                                           organization_id=endpoint.organization_id, schedule_id=str(schedule_id) if schedule_id else None)
            self._assessments.add(unavailable)
            raise EndpointUnavailableError(str(endpoint_id), unavailable)
        assessment = RemoteAssessment(str(uuid4()), endpoint_id, CorrelationId(), tuple(scanner_ids), timestamp, RemoteAssessmentState.CREATED,
                                      organization_id=endpoint.organization_id, schedule_id=str(schedule_id) if schedule_id else None)
        self._assessments.add(assessment)
        self._audit(SecurityAuditEventType.ASSESSMENT_CREATED, assessment)
        payload = AssessmentDispatch(assessment.assessment_id, endpoint_id, tuple(scanner_ids), timestamp)
        protocol_version = ProtocolVersion.parse(session.protocol_version) if session is not None else ProtocolVersion.current()
        envelope = AgentMessageEnvelope(
            AgentMessageType.ASSESSMENT_DISPATCH, payload.to_dict(), protocol_version=protocol_version,
            endpoint_id=endpoint_id, timestamp=timestamp, correlation_id=assessment.correlation_id,
        )
        queued_state = RemoteAssessmentState.QUEUED if self._work_repository is not None else RemoteAssessmentState.DISPATCHED
        queued = replace(assessment, state=queued_state,
                         queued_at=timestamp if self._work_repository is not None else None,
                         dispatched_at=timestamp if self._work_repository is None else None,
                         expires_at=timestamp + self._work_ttl if self._work_ttl else None)
        self._assessments.update(queued)
        if self._work_repository is not None:
            self._audit(SecurityAuditEventType.ASSESSMENT_QUEUED, queued)
        if self._work_repository is not None:
            work = AgentWorkItem(
                work_id=WorkId.new(), endpoint_id=endpoint_id, assessment_id=assessment.assessment_id,
                message_id=envelope.message_id, correlation_id=assessment.correlation_id,
                message_type=envelope.message_type.value, protocol_version=str(envelope.protocol_version),
                envelope=envelope.to_dict(), status=AgentWorkStatus.PENDING,
                created_at=timestamp, available_at=timestamp,
                expires_at=queued.expires_at,
                organization_id=queued.organization_id,
            )
            try:
                self._work_repository.add(work)
            except Exception as error:
                self._assessments.update(replace(queued, state=RemoteAssessmentState.DELIVERY_FAILED,
                                                  failed_at=timestamp, failure_code="DISPATCH_PERSISTENCE_FAILED",
                                                  failure_reason="assessment work could not be queued",
                                                  error="assessment work could not be queued"))
                self._audit(SecurityAuditEventType.ASSESSMENT_DELIVERY_FAILED, replace(queued, state=RemoteAssessmentState.DELIVERY_FAILED), reason_code="DISPATCH_PERSISTENCE_FAILED")
                raise
            return self._assessments.get(assessment.assessment_id)
        try:
            self._transport.send_control_to_agent(envelope)
        except Exception as error:
            self._assessments.update(replace(queued, state=RemoteAssessmentState.FAILED, failed_at=timestamp,
                                              failure_code="DISPATCH_TRANSPORT_FAILED", error=str(error)))
            raise
        return self._assessments.get(assessment.assessment_id)

    def _audit(self, event_type, assessment, *, reason_code=None):
        if self._audit_sink is not None:
            self._audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=self._principal,
                outcome=SecurityAuditOutcome.FAILED if reason_code else SecurityAuditOutcome.SUCCESS,
                reason_code=reason_code, endpoint_id=str(assessment.endpoint_id), assessment_id=assessment.assessment_id,
                correlation_id=str(assessment.correlation_id), organization_id=str(assessment.organization_id) if assessment.organization_id else None,
                metadata={"scanner_ids": list(assessment.scanner_ids)},
            ))


def _organization_id(value):
    module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
    return module.OrganizationId.parse(value)
