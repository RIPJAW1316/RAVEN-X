"""In-process authenticated agent-message acceptance pipeline."""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
import inspect

from ...domain.endpoint import AgentInfo, EndpointId, EndpointStatus
from ...domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent,
    SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal,
)
from ...domain.enrollment import EnrollmentRequest
from ...protocol.agent import (
    AgentCapabilityReport, AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, AgentRuntimeState,
    AgentStatusReport, AssessmentAcknowledgment, AssessmentDispatch, AssessmentProgress, AssessmentResultPayload, MessageDirection,
    ProtocolError, ProtocolValidationPolicy, ReplayDetectedError, default_message_registry, message_direction,
    validate_envelope,
)
from ..enrollment import AgentOrganizationSuspendedError, EnrollmentError, EnrollmentService
from ..ports.agent_authorization import (
    AgentMessageAuthorizer, AuthenticatedEndpointContext, AuthorizationDecision, NullAuditEventSink,
)
from ..ports.control_plane_authorization import ConservativeControlPlaneAuthorizer
from ..ports.agent_transport import PresentedCredential


class MessageAcceptanceError(ProtocolError):
    """Structured internal rejection; raw secrets are never included."""


class CredentialEndpointAuthenticator:
    def __init__(self, enrollment_service: EnrollmentService):
        self._service = enrollment_service

    def authenticate(self, envelope, presented: PresentedCredential, now: datetime) -> AuthenticatedEndpointContext:
        if envelope.endpoint_id is None:
            raise MessageAcceptanceError("missing_endpoint_id", "endpoint identity is required")
        try:
            if presented.credential_id is not None:
                credential = self._service.verify_presented_credential(
                    presented.credential_id, envelope.endpoint_id, presented.secret, now=now
                )
            else:
                credential = self._service.verify_credential(envelope.endpoint_id, presented.secret, now=now)
        except AgentOrganizationSuspendedError as error:
            raise MessageAcceptanceError("endpoint_not_active", "endpoint organization is not active") from error
        except EnrollmentError as error:
            raise MessageAcceptanceError("invalid_credential", "credential authentication failed") from error
        if credential.endpoint_id != envelope.endpoint_id:
            raise MessageAcceptanceError("endpoint_mismatch", "credential and message endpoint differ")
        if envelope.message_type in (AgentMessageType.ASSESSMENT_ACK, AgentMessageType.ASSESSMENT_PROGRESS,
                                     AgentMessageType.ASSESSMENT_RESULT):
            endpoint = self._service.get_endpoint(envelope.endpoint_id)
            if endpoint is None or endpoint.status is not EndpointStatus.ACTIVE:
                raise MessageAcceptanceError("endpoint_not_active", "endpoint is not approved for assessment work")
        return AuthenticatedEndpointContext(envelope.endpoint_id, credential.credential_id, now, presented.method)


class DefaultAgentMessageAuthorizer:
    _allowed = frozenset({
        AgentMessageType.HEARTBEAT, AgentMessageType.CAPABILITIES, AgentMessageType.STATUS,
        AgentMessageType.ASSESSMENT_ACK, AgentMessageType.ASSESSMENT_PROGRESS, AgentMessageType.ASSESSMENT_RESULT,
    })

    def authorize(self, context: AuthenticatedEndpointContext, envelope: AgentMessageEnvelope) -> AuthorizationDecision:
        if message_direction(envelope.message_type) is not MessageDirection.AGENT_TO_CONTROL:
            return AuthorizationDecision(False, "message direction is not allowed for inbound agent traffic", "direction_not_allowed")
        if envelope.message_type not in self._allowed:
            return AuthorizationDecision(False, "message type is not allowed for an authenticated agent", "unauthorized_message")
        return AuthorizationDecision(True)


class TypedMessageRouter:
    def __init__(self):
        self._handlers: Dict[AgentMessageType, Tuple[type, Callable[..., Any]]] = {}

    def register(self, message_type: AgentMessageType, payload_type: type, handler: Callable[..., Any]) -> None:
        message_type = AgentMessageType(message_type)
        if message_type in self._handlers:
            raise ValueError(f"handler for {message_type.value} is already registered")
        self._handlers[message_type] = (payload_type, handler)

    def has_handler(self, message_type: AgentMessageType) -> bool:
        return AgentMessageType(message_type) in self._handlers

    def route(self, envelope: AgentMessageEnvelope, context: AuthenticatedEndpointContext) -> Any:
        entry = self._handlers.get(envelope.message_type)
        if entry is None:
            raise MessageAcceptanceError("unknown_message_type", "no handler is registered for this message type")
        payload_type, handler = entry
        payload = self.decode(envelope)
        return self._invoke(handler, context, payload, envelope)

    def decode(self, envelope: AgentMessageEnvelope) -> Any:
        entry = self._handlers.get(envelope.message_type)
        if entry is None:
            raise MessageAcceptanceError("unknown_message_type", "no handler is registered for this message type")
        payload_type, _ = entry
        payload = decode_payload(envelope.message_type, envelope.payload)
        if not isinstance(payload, payload_type):
            raise MessageAcceptanceError("malformed_message", "payload type does not match message type")
        return payload

    def invoke(self, envelope: AgentMessageEnvelope, context: AuthenticatedEndpointContext, payload: Any) -> Any:
        entry = self._handlers.get(envelope.message_type)
        if entry is None:
            raise MessageAcceptanceError("unknown_message_type", "no handler is registered for this message type")
        return self._invoke(entry[1], context, payload, envelope)

    @staticmethod
    def _invoke(handler, context, payload, envelope):
        parameters = inspect.signature(handler).parameters
        if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters.values()) or len(parameters) >= 3:
            return handler(context, payload, envelope)
        return handler(context, payload)


class AgentMessageProcessor:
    def __init__(self, authenticator, replay_guard, *, authorizer: Optional[AgentMessageAuthorizer] = None,
                 router: Optional[TypedMessageRouter] = None, policy: Optional[ProtocolValidationPolicy] = None,
                 audit_sink=None, control_plane_authorizer=None, audit_repository=None):
        self._authenticator = authenticator
        self._replay_guard = replay_guard
        self._authorizer = authorizer or DefaultAgentMessageAuthorizer()
        self._router = router or TypedMessageRouter()
        self._policy = policy or ProtocolValidationPolicy()
        self._audit = audit_sink or NullAuditEventSink()
        self._control_authorizer = control_plane_authorizer or ConservativeControlPlaneAuthorizer()
        self._audit_repository = audit_repository

    @property
    def replay_guard(self):
        """Shared message-id claim store; credential renewal uses the same namespace."""
        return self._replay_guard

    def process(self, envelope: AgentMessageEnvelope, presented: PresentedCredential, *, now: Optional[datetime] = None):
        now = _utc(now or datetime.now(timezone.utc))
        try:
            validate_envelope(envelope, now=now, policy=self._policy)
            context = self._authenticator.authenticate(envelope, presented, now)
            self._append_audit(SecurityAuditEvent(
                event_type=SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_SUCCEEDED.value,
                principal=SecurityPrincipal.endpoint(context.endpoint_id),
                outcome=SecurityAuditOutcome.SUCCESS, endpoint_id=str(context.endpoint_id),
                message_id=str(envelope.message_id), correlation_id=str(envelope.correlation_id) if envelope.correlation_id else None,
                metadata={"message_type": envelope.message_type.value},
            ))
            decision = self._authorizer.authorize(context, envelope)
            if not decision.allowed:
                self._audit.emit("message_authorization_rejected", endpoint_id=context.endpoint_id)
                raise MessageAcceptanceError(decision.code, decision.reason)
            broad_decision = self._control_authorizer.authorize(_authorization_request(envelope, context))
            if not broad_decision.allowed:
                self._audit.emit("message_authorization_rejected", endpoint_id=context.endpoint_id)
                raise MessageAcceptanceError(broad_decision.reason_code, broad_decision.reason)
            if not self._router.has_handler(envelope.message_type):
                raise MessageAcceptanceError("unknown_message_type", "no handler is registered for this message type")
            payload = self._router.decode(envelope)
            if not _claim(self._replay_guard, envelope, context.endpoint_id, now, now + self._policy.replay_retention):
                self._audit.emit("replay_rejected", endpoint_id=context.endpoint_id)
                raise MessageAcceptanceError("replayed_message", "message has already been accepted")
            return self._router.invoke(envelope, context, payload)
        except MessageAcceptanceError as error:
            self._audit_rejection(envelope, error)
            raise
        except ProtocolError as error:
            raise MessageAcceptanceError(error.code, error.message, error.correlation_id, error.details) from error
        except Exception as error:
            raise MessageAcceptanceError("malformed_message", "message could not be accepted") from error

    def _append_audit(self, event):
        if self._audit_repository is not None:
            self._audit_repository.append(event)

    def _audit_rejection(self, envelope, error):
        code = getattr(error, "code", "malformed_message")
        endpoint_id = str(envelope.endpoint_id) if envelope.endpoint_id else None
        principal = SecurityPrincipal.endpoint(envelope.endpoint_id) if envelope.endpoint_id else SecurityPrincipal.system()
        if code == "replayed_message":
            self._audit.emit("replay_rejected", endpoint_id=envelope.endpoint_id)
            event_type = SecurityAuditEventType.AGENT_MESSAGE_REPLAY_REJECTED.value
        elif code in {"endpoint_action_not_allowed", "endpoint_scope_mismatch", "direction_not_allowed", "unauthorized_message"}:
            self._audit.emit("message_authorization_rejected", endpoint_id=envelope.endpoint_id)
            event_type = SecurityAuditEventType.AGENT_MESSAGE_AUTHORIZATION_DENIED.value
        elif code in {"invalid_credential", "endpoint_mismatch"}:
            event_type = SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_FAILED.value
        else:
            return
        self._append_audit(SecurityAuditEvent(
            event_type=event_type, principal=principal, outcome=SecurityAuditOutcome.DENIED,
            reason_code=code, endpoint_id=endpoint_id, message_id=str(envelope.message_id),
            correlation_id=str(envelope.correlation_id) if envelope.correlation_id else None,
            metadata={"message_type": envelope.message_type.value},
        ))


class EnrollmentMessageProcessor:
    """Separate bootstrap path; enrollment has no normal endpoint credential."""
    def __init__(self, service: EnrollmentService):
        self._service = service

    def process(self, payload, *, now: Optional[datetime] = None):
        now = _utc(now or datetime.now(timezone.utc))
        payload.protocol_version.ensure_supported()
        if payload.enrollment_id is None:
            raise MessageAcceptanceError("malformed_message", "enrollment_id is required for bootstrap acceptance")
        request = EnrollmentRequest(
            hostname=payload.hostname,
            platform=payload.platform,
            agent=AgentInfo(payload.agent_version, str(payload.protocol_version)),
            request_id=payload.request_id or "",
            nonce=payload.nonce or "",
        )
        endpoint, credential, raw = self._service.accept_enrollment(
            payload.enrollment_id, payload.enrollment_token, request, now=now
        )
        from ...protocol.agent import EnrollmentResponsePayload
        return EnrollmentResponsePayload(endpoint.endpoint_id, str(credential.credential_id), raw.value,
                                         payload.protocol_version, str(endpoint.organization_id) if endpoint.organization_id else None,
                                         endpoint.status.value, credential.expires_at.isoformat() if credential.expires_at else None)


def decode_payload(message_type: AgentMessageType, data: Mapping[str, Any]):
    message_type = AgentMessageType(message_type)
    if message_type is AgentMessageType.HEARTBEAT:
        return AgentHeartbeat.from_dict(data)
    if message_type is AgentMessageType.CAPABILITIES:
        return AgentCapabilityReport.from_dict(data)
    if message_type is AgentMessageType.STATUS:
        return AgentStatusReport(data["endpoint_id"], data["agent_version"], data["protocol_version"], AgentRuntimeState(data["runtime_state"]), data.get("scanner_catalog_version"))
    if message_type is AgentMessageType.ASSESSMENT_PROGRESS:
        return AssessmentProgress(data["assessment_id"], data["status"], tuple(data.get("completed_scanners", ())), data["total_scanners"], data.get("current_scanner_id"), datetime.fromisoformat(data["timestamp"]))
    if message_type is AgentMessageType.ASSESSMENT_ACK:
        return AssessmentAcknowledgment.from_dict(data)
    if message_type is AgentMessageType.ASSESSMENT_RESULT:
        return AssessmentResultPayload(data["assessment_id"], data["endpoint_id"], data["status"], datetime.fromisoformat(data["started_at"]), datetime.fromisoformat(data["finished_at"]) if data.get("finished_at") else None, tuple(data.get("findings", ())), tuple(data.get("scanner_results", ())), data.get("error"))
    if message_type is AgentMessageType.ASSESSMENT_DISPATCH:
        return AssessmentDispatch(data["assessment_id"], data["endpoint_id"], tuple(data["scanner_ids"]), datetime.fromisoformat(data["requested_at"]), datetime.fromisoformat(data["deadline"]) if data.get("deadline") else None, data.get("options", {}))
    raise MessageAcceptanceError("unknown_message_type", "unsupported payload type")


def _claim(guard, envelope, endpoint_id, now, expires_at) -> bool:
    if hasattr(guard, "claim"):
        return bool(guard.claim(envelope.message_id, endpoint_id, now, expires_at))
    if guard.seen(envelope.message_id):
        return False
    guard.record(envelope.message_id)
    return True


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


_MESSAGE_ACTIONS = {
    AgentMessageType.HEARTBEAT: AuthorizationAction.AGENT_HEARTBEAT_SUBMIT,
    AgentMessageType.CAPABILITIES: AuthorizationAction.AGENT_CAPABILITIES_SUBMIT,
    AgentMessageType.STATUS: AuthorizationAction.AGENT_STATUS_SUBMIT,
    AgentMessageType.ASSESSMENT_ACK: AuthorizationAction.ASSESSMENT_ACK_SUBMIT,
    AgentMessageType.ASSESSMENT_PROGRESS: AuthorizationAction.ASSESSMENT_PROGRESS_SUBMIT,
    AgentMessageType.ASSESSMENT_RESULT: AuthorizationAction.ASSESSMENT_RESULT_SUBMIT,
}


def _authorization_request(envelope, context):
    action = _MESSAGE_ACTIONS.get(envelope.message_type)
    payload_endpoint = envelope.payload.get("endpoint_id") if isinstance(envelope.payload, Mapping) else None
    if envelope.message_type in (AgentMessageType.HEARTBEAT, AgentMessageType.CAPABILITIES, AgentMessageType.STATUS):
        resource = AuthorizationResource("endpoint", payload_endpoint or str(context.endpoint_id),
                                        {"endpoint_id": payload_endpoint or str(context.endpoint_id),
                                         "message_type": envelope.message_type.value})
    else:
        resource = AuthorizationResource("assessment", envelope.payload.get("assessment_id"),
                                        {"endpoint_id": payload_endpoint or str(context.endpoint_id),
                                         "message_type": envelope.message_type.value})
    return AuthorizationRequest(SecurityPrincipal.endpoint(context.endpoint_id), action, resource,
                                {"protocol_message": envelope.message_type.value})
