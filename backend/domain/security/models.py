"""Transport-neutral security boundaries and JSON-safe audit facts."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional
from uuid import UUID, uuid4

from ..endpoint import EndpointId


class PrincipalType(str, Enum):
    SYSTEM = "system"
    INTERNAL = "internal"
    ENDPOINT = "endpoint"
    HUMAN = "human"


@dataclass(frozen=True)
class SecurityPrincipal:
    principal_type: PrincipalType
    principal_id: str
    display_metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "principal_type", PrincipalType(self.principal_type))
        if not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("principal_id is required")
        object.__setattr__(self, "display_metadata", redact_metadata(self.display_metadata))

    @classmethod
    def system(cls) -> "SecurityPrincipal":
        return cls(PrincipalType.SYSTEM, "raven-x")

    @classmethod
    def internal(cls, name: str = "internal") -> "SecurityPrincipal":
        return cls(PrincipalType.INTERNAL, name)

    @classmethod
    def endpoint(cls, endpoint_id: EndpointId) -> "SecurityPrincipal":
        return cls(PrincipalType.ENDPOINT, str(endpoint_id))

    @classmethod
    def human(cls, user_id) -> "SecurityPrincipal":
        return cls(PrincipalType.HUMAN, str(user_id))

    def to_dict(self):
        return {"principal_type": self.principal_type.value, "principal_id": self.principal_id,
                "display_metadata": redact_metadata(self.display_metadata)}


class AuthorizationAction(str, Enum):
    ROLE_CREATE = "role.create"
    ROLE_READ = "role.read"
    ROLE_UPDATE = "role.update"
    ROLE_DISABLE = "role.disable"
    ROLE_REVOKE = "role.revoke"
    ROLE_BINDING_CREATE = "role_binding.create"
    ROLE_BINDING_READ = "role_binding.read"
    ROLE_BINDING_UPDATE = "role_binding.update"
    ROLE_BINDING_REVOKE = "role_binding.revoke"
    ORGANIZATION_CREATE = "organization.create"
    ORGANIZATION_READ = "organization.read"
    ORGANIZATION_UPDATE = "organization.update"
    ORGANIZATION_SUSPEND = "organization.suspend"
    ORGANIZATION_REVOKE = "organization.revoke"
    MEMBERSHIP_CREATE = "membership.create"
    MEMBERSHIP_READ = "membership.read"
    MEMBERSHIP_UPDATE = "membership.update"
    MEMBERSHIP_SUSPEND = "membership.suspend"
    MEMBERSHIP_REVOKE = "membership.revoke"
    USER_CREATE = "user.create"
    USER_READ = "user.read"
    USER_UPDATE = "user.update"
    USER_DISABLE = "user.disable"
    USER_REVOKE = "user.revoke"
    SESSION_CREATE = "session.create"
    SESSION_REVOKE = "session.revoke"
    HUMAN_AUTHENTICATE = "authentication.human.authenticate"
    ENDPOINT_READ = "endpoint.read"
    ENDPOINT_CREATE = "endpoint.create"
    ENDPOINT_UPDATE = "endpoint.update"
    ENDPOINT_REVOKE = "endpoint.revoke"
    ENROLLMENT_CREATE = "enrollment.create"
    ENROLLMENT_REVOKE = "enrollment.revoke"
    CREDENTIAL_ROTATE = "credential.rotate"
    CREDENTIAL_RENEW = "credential.renew"
    CREDENTIAL_REVOKE = "credential.revoke"
    ASSESSMENT_CREATE = "assessment.create"
    ASSESSMENT_READ = "assessment.read"
    ASSESSMENT_CANCEL = "assessment.cancel"
    ASSESSMENT_SCHEDULE_CREATE = "assessment_schedule.create"
    ASSESSMENT_SCHEDULE_READ = "assessment_schedule.read"
    ASSESSMENT_SCHEDULE_UPDATE = "assessment_schedule.update"
    ASSESSMENT_SCHEDULE_PAUSE = "assessment_schedule.pause"
    ASSESSMENT_SCHEDULE_REVOKE = "assessment_schedule.revoke"
    ENDPOINT_GROUP_CREATE = "endpoint_group.create"
    ENDPOINT_GROUP_READ = "endpoint_group.read"
    ENDPOINT_GROUP_UPDATE = "endpoint_group.update"
    ENDPOINT_GROUP_MEMBERSHIP_UPDATE = "endpoint_group.membership_update"
    ENDPOINT_GROUP_REVOKE = "endpoint_group.revoke"
    FLEET_SCOPE_CREATE = "fleet_scope.create"
    FLEET_SCOPE_READ = "fleet_scope.read"
    FLEET_SCOPE_UPDATE = "fleet_scope.update"
    FLEET_SCOPE_REVOKE = "fleet_scope.revoke"
    COMPLIANCE_READ = "compliance.read"
    # Reading the security activity history is a separate, more sensitive grant
    # than reading the organization: audit events reveal who did what and when.
    AUDIT_READ = "audit.read"
    AI_USE = "ai.use"
    REPORT_READ = "reports.read"
    AGENT_HEARTBEAT_SUBMIT = "agent.heartbeat.submit"
    AGENT_CAPABILITIES_SUBMIT = "agent.capabilities.submit"
    AGENT_STATUS_SUBMIT = "agent.status.submit"
    ASSESSMENT_ACK_SUBMIT = "assessment.ack.submit"
    ASSESSMENT_PROGRESS_SUBMIT = "assessment.progress.submit"
    ASSESSMENT_RESULT_SUBMIT = "assessment.result.submit"


@dataclass(frozen=True)
class AuthorizationResource:
    resource_type: str
    resource_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.resource_type, str) or not self.resource_type.strip():
            raise ValueError("resource_type is required")
        object.__setattr__(self, "metadata", redact_metadata(self.metadata))

    def to_dict(self):
        return {"resource_type": self.resource_type, "resource_id": self.resource_id,
                "metadata": redact_metadata(self.metadata)}


@dataclass(frozen=True)
class AuthorizationRequest:
    principal: SecurityPrincipal
    action: AuthorizationAction
    resource: AuthorizationResource
    context: Mapping[str, Any] = field(default_factory=dict)
    organization_context: Optional[Mapping[str, Any]] = None

    def __post_init__(self):
        try:
            object.__setattr__(self, "action", AuthorizationAction(self.action))
        except (ValueError, TypeError):
            if not isinstance(self.action, str) or not self.action.strip():
                raise ValueError("authorization action is required")
            object.__setattr__(self, "action", self.action)
        object.__setattr__(self, "context", redact_metadata(self.context))
        if self.organization_context is not None:
            value = self.organization_context.to_dict() if hasattr(self.organization_context, "to_dict") else self.organization_context
            if not isinstance(value, Mapping):
                raise ValueError("organization_context must be JSON-compatible")
            object.__setattr__(self, "organization_context", redact_metadata(value))


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason_code: str = "allowed"
    reason: str = ""


class SecurityAuditOutcome(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILED = "failed"


class SecurityAuditEventType(str, Enum):
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DISABLED = "role.disabled"
    ROLE_REVOKED = "role.revoked"
    ROLE_BINDING_CREATED = "role_binding.created"
    ROLE_BINDING_DISABLED = "role_binding.disabled"
    ROLE_BINDING_REVOKED = "role_binding.revoked"
    AUTHORIZATION_ALLOWED = "authorization.allowed"
    ORGANIZATION_CONTEXT_RESOLVED = "organization.context_resolved"
    ORGANIZATION_CONTEXT_DENIED = "organization.context_denied"
    ORGANIZATION_CREATED = "organization.created"
    ORGANIZATION_UPDATED = "organization.updated"
    ORGANIZATION_SUSPENDED = "organization.suspended"
    ORGANIZATION_REVOKED = "organization.revoked"
    MEMBERSHIP_CREATED = "membership.created"
    MEMBERSHIP_SUSPENDED = "membership.suspended"
    MEMBERSHIP_REVOKED = "membership.revoked"
    USER_CREATED = "user.created"
    USER_DISABLED = "user.disabled"
    USER_REVOKED = "user.revoked"
    HUMAN_AUTHENTICATION_SUCCEEDED = "human.authentication_succeeded"
    HUMAN_AUTHENTICATION_FAILED = "human.authentication_failed"
    HUMAN_AUTHENTICATION_RATE_LIMITED = "human.authentication_rate_limited"
    SESSION_ISSUED = "session.issued"
    SESSION_REVOKED = "session.revoked"
    SESSION_EXPIRED = "session.expired"
    AUTHORIZATION_DENIED = "authorization.denied"
    ENDPOINT_REGISTERED = "endpoint.registered"
    ENDPOINT_UPDATED = "endpoint.updated"
    ENDPOINT_REVOKED = "endpoint.revoked"
    ENDPOINT_PRESENCE_ONLINE = "endpoint.presence_online"
    ENDPOINT_PRESENCE_STALE = "endpoint.presence_stale"
    ENDPOINT_PRESENCE_OFFLINE = "endpoint.presence_offline"
    ENROLLMENT_CREATED = "enrollment.created"
    ENROLLMENT_RENEWED = "enrollment.renewed"
    ENROLLMENT_CONSUMED = "enrollment.consumed"
    ENROLLMENT_CONSUMPTION_FAILED = "enrollment.consumption_failed"
    ENROLLMENT_REVOKED = "enrollment.revoked"
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_ROTATED = "credential.rotated"
    CREDENTIAL_RENEWED = "credential.renewed"
    CREDENTIAL_RENEWAL_CONFIRMED = "credential.renewal_confirmed"
    CREDENTIAL_RENEWAL_CONFLICT = "credential.renewal_conflict"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_LINEAGE_REVOKED = "credential.lineage_revoked"
    CREDENTIAL_AUTHENTICATION_SUCCEEDED = "credential.authentication_succeeded"
    CREDENTIAL_AUTHENTICATION_FAILED = "credential.authentication_failed"
    AGENT_MESSAGE_REPLAY_REJECTED = "agent.message_replay_rejected"
    AGENT_MESSAGE_AUTHORIZATION_DENIED = "agent.message_authorization_denied"
    ASSESSMENT_CREATED = "assessment.created"
    ASSESSMENT_QUEUED = "assessment.queued"
    ASSESSMENT_ACKNOWLEDGED = "assessment.acknowledged"
    ASSESSMENT_COMPLETED = "assessment.completed"
    ASSESSMENT_FAILED = "assessment.failed"
    ASSESSMENT_DELIVERY_FAILED = "assessment.delivery_failed"
    ASSESSMENT_EXPIRED = "assessment.expired"
    ASSESSMENT_CANCEL_REQUESTED = "assessment.cancel_requested"
    ASSESSMENT_CANCELLED = "assessment.cancelled"


@dataclass(frozen=True)
class SecurityAuditEvent:
    event_id: UUID = field(default_factory=uuid4)
    event_type: str = "security.event"
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    principal: SecurityPrincipal = field(default_factory=SecurityPrincipal.system)
    action: Optional[AuthorizationAction] = None
    resource: Optional[AuthorizationResource] = None
    outcome: SecurityAuditOutcome = SecurityAuditOutcome.SUCCESS
    reason_code: Optional[str] = None
    correlation_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    assessment_id: Optional[str] = None
    work_id: Optional[str] = None
    message_id: Optional[str] = None
    user_id: Optional[str] = None
    organization_id: Optional[str] = None
    membership_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "event_id", UUID(str(self.event_id)))
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise ValueError("event_type is required")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        if self.action is not None:
            try:
                object.__setattr__(self, "action", AuthorizationAction(self.action))
            except (ValueError, TypeError):
                if not isinstance(self.action, str) or not self.action.strip():
                    raise ValueError("audit action must be a non-empty string")
                object.__setattr__(self, "action", self.action)
        object.__setattr__(self, "outcome", SecurityAuditOutcome(self.outcome))
        object.__setattr__(self, "metadata", redact_metadata(self.metadata))

    def to_dict(self):
        return {
            "event_id": str(self.event_id), "event_type": self.event_type,
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat(),
            "principal": self.principal.to_dict(), "action": self.action.value if isinstance(self.action, AuthorizationAction) else self.action,
            "resource": self.resource.to_dict() if self.resource else None,
            "outcome": self.outcome.value, "reason_code": self.reason_code,
            "correlation_id": self.correlation_id, "endpoint_id": self.endpoint_id,
            "assessment_id": self.assessment_id, "work_id": self.work_id,
            "message_id": self.message_id, "user_id": self.user_id,
            "organization_id": self.organization_id, "membership_id": self.membership_id,
            "metadata": redact_metadata(self.metadata),
        }


_SENSITIVE_KEYS = {"token", "secret", "credential", "authorization", "password", "verifier", "private_key", "bearer"}


def redact_metadata(value):
    if isinstance(value, Mapping):
        return {str(key): "<redacted>" if any(sensitive in str(key).lower() for sensitive in _SENSITIVE_KEYS)
                else redact_metadata(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_metadata(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
