"""Typed, JSON-safe, transport-neutral agent protocol messages."""

from dataclasses import dataclass, field, is_dataclass, fields
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import re
from threading import RLock
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple, Type
from uuid import UUID, uuid4

from ...domain.assessment import AssessmentResult, AssessmentStatus, Evidence, Finding, FindingSeverity
from ...domain.endpoint import EndpointId, PlatformInfo
from ...domain.enrollment import EnrollmentId
from ...domain.scanner import (
    CapabilityAvailability, CapabilityObservation, ScannerCapability, ScannerExecutionResult,
    ScannerExecutionStatus, TargetCapabilities,
)
from ...domain.reporting import materialize_finding_identity


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str, correlation_id: Optional[str] = None, details: Optional[Mapping[str, Any]] = None):
        self.code, self.correlation_id, self.details = code, correlation_id, dict(details or {})
        super().__init__(message)
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "correlation_id": self.correlation_id, "details": _safe(self.details)}


class UnsupportedProtocolVersion(ProtocolError): ...
class ReplayDetectedError(ProtocolError): ...


@dataclass(frozen=True, order=True)
class ProtocolVersion:
    major: int
    minor: int

    SUPPORTED_MAJOR = 1
    SUPPORTED_MINOR = 0

    def __post_init__(self) -> None:
        if not isinstance(self.major, int) or not isinstance(self.minor, int) or self.major < 0 or self.minor < 0:
            raise ValueError("protocol version numbers must be non-negative integers")

    @classmethod
    def parse(cls, value: str) -> "ProtocolVersion":
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", value):
            raise ValueError("protocol version must have the form major.minor")
        return cls(int(value.split(".")[0]), int(value.split(".")[1]))

    @classmethod
    def current(cls) -> "ProtocolVersion":
        return cls(cls.SUPPORTED_MAJOR, cls.SUPPORTED_MINOR)

    @property
    def supported(self) -> bool:
        return self.major == self.SUPPORTED_MAJOR and self.minor >= 0

    def ensure_supported(self) -> None:
        if not self.supported:
            raise UnsupportedProtocolVersion("unsupported_protocol_version", f"unsupported protocol major version {self.major}")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True)
class MessageId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", UUID(str(self.value)))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class CorrelationId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", UUID(str(self.value)))

    def __str__(self) -> str:
        return str(self.value)


class AgentMessageType(str, Enum):
    HEARTBEAT = "agent.heartbeat"
    CAPABILITIES = "agent.capabilities"
    STATUS = "agent.status"
    ENROLLMENT_REQUEST = "enrollment.request"
    ENROLLMENT_RESPONSE = "enrollment.response"
    ASSESSMENT_DISPATCH = "assessment.dispatch"
    ASSESSMENT_ACK = "assessment.ack"
    ASSESSMENT_PROGRESS = "assessment.progress"
    ASSESSMENT_RESULT = "assessment.result"
    ERROR = "protocol.error"


class MessageDirection(str, Enum):
    AGENT_TO_CONTROL = "agent_to_control"
    CONTROL_TO_AGENT = "control_to_agent"
    BIDIRECTIONAL = "bidirectional"


class ProtocolPayload:
    """Mixin providing deterministic JSON-safe public serialization."""

    def to_dict(self) -> Dict[str, Any]:
        return _safe(self)


def _timestamp(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class AgentMessageEnvelope:
    message_type: AgentMessageType
    payload: Mapping[str, Any]
    protocol_version: ProtocolVersion = field(default_factory=ProtocolVersion.current)
    endpoint_id: Optional[EndpointId] = None
    message_id: MessageId = field(default_factory=MessageId)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[CorrelationId] = None
    nonce: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "message_type", AgentMessageType(self.message_type))
        if isinstance(self.protocol_version, str):
            object.__setattr__(self, "protocol_version", ProtocolVersion.parse(self.protocol_version))
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        object.__setattr__(self, "timestamp", _timestamp(self.timestamp, "timestamp"))
        if self.endpoint_id is not None and not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if self.correlation_id is not None and not isinstance(self.correlation_id, CorrelationId):
            object.__setattr__(self, "correlation_id", CorrelationId(self.correlation_id))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": str(self.message_id), "message_type": self.message_type.value,
            "protocol_version": str(self.protocol_version),
            "endpoint_id": str(self.endpoint_id) if self.endpoint_id else None,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "nonce": self.nonce, "payload": _safe(self.payload),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AgentMessageEnvelope":
        required = ("message_id", "message_type", "protocol_version", "timestamp", "payload")
        if any(key not in data for key in required):
            raise ValueError("message envelope is missing required fields")
        return cls(
            message_type=data["message_type"], payload=data["payload"],
            protocol_version=ProtocolVersion.parse(data["protocol_version"]),
            endpoint_id=EndpointId(data["endpoint_id"]) if data.get("endpoint_id") else None,
            message_id=MessageId(data["message_id"]), timestamp=datetime.fromisoformat(data["timestamp"]),
            correlation_id=CorrelationId(data["correlation_id"]) if data.get("correlation_id") else None,
            nonce=data.get("nonce"),
        )


@dataclass(frozen=True)
class EnrollmentRequestPayload(ProtocolPayload):
    enrollment_token: str
    hostname: str
    platform: PlatformInfo
    agent_version: str
    protocol_version: ProtocolVersion = field(default_factory=ProtocolVersion.current)
    request_id: Optional[str] = None
    nonce: Optional[str] = None
    enrollment_id: Optional[EnrollmentId] = None

    def __post_init__(self) -> None:
        if not self.enrollment_token or not self.hostname.strip() or not self.agent_version.strip():
            raise ValueError("enrollment token, hostname, and agent_version are required")
        if isinstance(self.protocol_version, str):
            object.__setattr__(self, "protocol_version", ProtocolVersion.parse(self.protocol_version))
        if self.enrollment_id is not None and not isinstance(self.enrollment_id, EnrollmentId):
            object.__setattr__(self, "enrollment_id", EnrollmentId(self.enrollment_id))

    def __repr__(self) -> str:
        return f"EnrollmentRequestPayload(hostname={self.hostname!r}, enrollment_token=<redacted>)"

    def to_dict(self, *, include_secret: bool = False) -> Dict[str, Any]:
        return {"enrollment_token": self.enrollment_token if include_secret else "<redacted>", "hostname": self.hostname,
                "platform": _safe(self.platform), "agent_version": self.agent_version,
                "protocol_version": str(self.protocol_version), "request_id": self.request_id, "nonce": self.nonce,
                "enrollment_id": str(self.enrollment_id) if self.enrollment_id else None}

    def to_wire_dict(self) -> Dict[str, Any]:
        return self.to_dict(include_secret=True)

    @classmethod
    def from_wire_dict(cls, data: Mapping[str, Any]) -> "EnrollmentRequestPayload":
        platform = data["platform"]
        return cls(
            data["enrollment_token"], data["hostname"],
            PlatformInfo(platform["name"], platform.get("version"), platform.get("architecture")),
            data["agent_version"], ProtocolVersion.parse(data["protocol_version"]),
            data.get("request_id"), data.get("nonce"), data.get("enrollment_id"),
        )


@dataclass(frozen=True)
class EnrollmentResponsePayload(ProtocolPayload):
    endpoint_id: EndpointId
    credential_id: str
    credential_secret: str
    protocol_version: ProtocolVersion = field(default_factory=ProtocolVersion.current)
    organization_id: Optional[str] = None
    status: Optional[str] = None
    credential_expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.credential_secret:
            raise ValueError("credential_secret is required")
        if isinstance(self.protocol_version, str):
            object.__setattr__(self, "protocol_version", ProtocolVersion.parse(self.protocol_version))

    def __repr__(self) -> str:
        return f"EnrollmentResponsePayload(endpoint_id={self.endpoint_id!s}, credential_secret=<redacted>)"

    def to_dict(self, *, include_secret: bool = False) -> Dict[str, Any]:
        result = {"endpoint_id": str(self.endpoint_id), "credential_id": self.credential_id,
                "credential_secret": self.credential_secret if include_secret else "<redacted>",
                "protocol_version": str(self.protocol_version)}
        if self.organization_id is not None:
            result["organization_id"] = self.organization_id
        if self.status is not None:
            result["status"] = self.status
        if self.credential_expires_at is not None:
            result["credential_expires_at"] = self.credential_expires_at
        return result

    def to_wire_dict(self) -> Dict[str, Any]:
        return self.to_dict(include_secret=True)

    @classmethod
    def from_wire_dict(cls, data: Mapping[str, Any]) -> "EnrollmentResponsePayload":
        return cls(data["endpoint_id"], data["credential_id"], data["credential_secret"],
                   ProtocolVersion.parse(data["protocol_version"]), data.get("organization_id"),
                   data.get("status"), data.get("credential_expires_at"))


@dataclass(frozen=True)
class AgentHeartbeat(ProtocolPayload):
    endpoint_id: EndpointId
    agent_version: str
    protocol_version: ProtocolVersion
    observed_at: datetime
    uptime_seconds: Optional[int] = None
    health: str = "healthy"

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if isinstance(self.protocol_version, str):
            object.__setattr__(self, "protocol_version", ProtocolVersion.parse(self.protocol_version))
        _timestamp(self.observed_at, "observed_at")
        if not self.agent_version.strip() or self.uptime_seconds is not None and self.uptime_seconds < 0:
            raise ValueError("invalid heartbeat metadata")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AgentHeartbeat":
        return cls(EndpointId(data["endpoint_id"]), data["agent_version"],
                   ProtocolVersion.parse(data["protocol_version"]), datetime.fromisoformat(data["observed_at"]),
                   data.get("uptime_seconds"), data.get("health", "healthy"))


@dataclass(frozen=True)
class AgentCapabilityReport(ProtocolPayload):
    endpoint_id: EndpointId
    capabilities: TargetCapabilities
    discovered_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        _timestamp(self.discovered_at, "discovered_at")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AgentCapabilityReport":
        capability_data = data.get("capabilities", data)
        observations = tuple(
            CapabilityObservation(ScannerCapability(item["capability"]), CapabilityAvailability(item["availability"]),
                                   item["source"], item["reason"])
            for item in capability_data.get("observations", ())
        )
        capabilities = TargetCapabilities(frozenset(ScannerCapability(item) for item in capability_data.get("values", ())), observations)
        return cls(EndpointId(data["endpoint_id"]), capabilities, datetime.fromisoformat(data["discovered_at"]))


class AgentRuntimeState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPED = "stopped"


@dataclass(frozen=True)
class AgentStatusReport(ProtocolPayload):
    endpoint_id: EndpointId
    agent_version: str
    protocol_version: ProtocolVersion
    runtime_state: AgentRuntimeState
    scanner_catalog_version: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if isinstance(self.protocol_version, str):
            object.__setattr__(self, "protocol_version", ProtocolVersion.parse(self.protocol_version))
        object.__setattr__(self, "runtime_state", AgentRuntimeState(self.runtime_state))


@dataclass(frozen=True)
class AssessmentDispatch(ProtocolPayload):
    assessment_id: str
    endpoint_id: EndpointId
    scanner_ids: Tuple[str, ...]
    requested_at: datetime
    deadline: Optional[datetime] = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_id, EndpointId):
            object.__setattr__(self, "endpoint_id", EndpointId(self.endpoint_id))
        if not self.assessment_id.strip() or any(not item.strip() for item in self.scanner_ids):
            raise ValueError("assessment_id and scanner_ids must be non-empty")
        _timestamp(self.requested_at, "requested_at")
        if self.deadline is not None:
            _timestamp(self.deadline, "deadline")

    def to_assessment_options(self):
        from ...application.assessment.options import AssessmentOptions
        return AssessmentOptions(tuple(self.scanner_ids))


@dataclass(frozen=True)
class AssessmentProgress(ProtocolPayload):
    assessment_id: str
    status: str
    completed_scanners: Tuple[str, ...]
    total_scanners: int
    current_scanner_id: Optional[str]
    timestamp: datetime
    correlation_id: Optional[CorrelationId] = None

    def __post_init__(self) -> None:
        _timestamp(self.timestamp, "timestamp")
        if self.correlation_id is not None and not isinstance(self.correlation_id, CorrelationId):
            object.__setattr__(self, "correlation_id", CorrelationId(self.correlation_id))
        object.__setattr__(self, "completed_scanners", tuple(self.completed_scanners))
        if self.total_scanners < 0 or len(self.completed_scanners) > self.total_scanners:
            raise ValueError("invalid assessment progress counts")


@dataclass(frozen=True)
class AssessmentAcknowledgment(ProtocolPayload):
    """Assessment-specific delivery acceptance; never authorizes execution itself."""
    assessment_id: str
    work_id: str
    lease_token: str
    accepted_at: datetime

    def __post_init__(self) -> None:
        if not self.assessment_id.strip() or not self.work_id.strip() or not self.lease_token:
            raise ValueError("assessment_id, work_id, and lease_token are required")
        _timestamp(self.accepted_at, "accepted_at")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AssessmentAcknowledgment":
        return cls(data["assessment_id"], data["work_id"], data["lease_token"], datetime.fromisoformat(data["accepted_at"]))

    def __repr__(self) -> str:
        return f"AssessmentAcknowledgment(assessment_id={self.assessment_id!r}, work_id={self.work_id!r}, lease_token=<redacted>)"


@dataclass(frozen=True)
class AssessmentResultPayload(ProtocolPayload):
    assessment_id: str
    endpoint_id: str
    status: AssessmentStatus
    started_at: datetime
    finished_at: Optional[datetime]
    findings: Tuple[Mapping[str, Any], ...] = ()
    scanner_results: Tuple[Mapping[str, Any], ...] = ()
    error: Optional[str] = None

    @classmethod
    def from_assessment_result(cls, result: AssessmentResult) -> "AssessmentResultPayload":
        return cls(result.assessment_id, result.target.target_id, result.status, _coerce_timestamp(result.started_at),
                   _coerce_timestamp(result.finished_at) if result.finished_at else None,
                   tuple(_finding_dict(item, result.assessment_id, result.target.target_id, index)
                         for index, item in enumerate(result.findings)),
                   tuple(_scanner_result_dict(item) for item in result.scanner_results), result.error)

    def __post_init__(self) -> None:
        if not self.endpoint_id or not self.assessment_id:
            raise ValueError("assessment and endpoint identity are required")
        object.__setattr__(self, "status", AssessmentStatus(self.status))
        _timestamp(self.started_at, "started_at")
        if self.finished_at is not None:
            _timestamp(self.finished_at, "finished_at")
        object.__setattr__(self, "findings", tuple(
            materialize_finding_identity(item, assessment_id=self.assessment_id,
                                         endpoint_id=self.endpoint_id, index=index)
            if isinstance(item, Mapping) else item
            for index, item in enumerate(self.findings)))


class MessageReplayGuard(Protocol):
    def seen(self, message_id: MessageId) -> bool: ...
    def record(self, message_id: MessageId) -> None: ...


class InMemoryReplayGuard:
    def __init__(self):
        self._seen = {}
        self._lock = RLock()

    def seen(self, message_id: MessageId) -> bool:
        with self._lock:
            return str(message_id) in self._seen

    def record(self, message_id: MessageId) -> None:
        with self._lock:
            if self.seen(message_id):
                raise ReplayDetectedError("replay_detected", "message_id has already been observed")
            self._seen[str(message_id)] = None

    def claim(self, message_id: MessageId, endpoint_id, now: datetime, expires_at: datetime) -> bool:
        with self._lock:
            self.purge_expired(now)
            key = str(message_id)
            if key in self._seen:
                return False
            self._seen[key] = _timestamp(expires_at, "expires_at")
            return True

    def purge_expired(self, before: datetime) -> int:
        cutoff = _timestamp(before, "before")
        with self._lock:
            expired = [key for key, expires in self._seen.items() if expires is not None and expires <= cutoff]
            for key in expired:
                del self._seen[key]
            return len(expired)


@dataclass(frozen=True)
class ProtocolValidationPolicy:
    max_clock_skew: timedelta = timedelta(minutes=5)
    max_payload_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_clock_skew < timedelta(0) or self.max_payload_bytes <= 0:
            raise ValueError("invalid protocol validation policy")


def validate_envelope(envelope: AgentMessageEnvelope, *, now: Optional[datetime] = None,
                      policy: ProtocolValidationPolicy = ProtocolValidationPolicy()) -> None:
    if not isinstance(envelope.message_id, MessageId):
        raise ProtocolError("invalid_message_id", "message_id is invalid")
    if not isinstance(envelope.payload, Mapping):
        raise ProtocolError("invalid_payload", "payload must be a mapping")
    if envelope.message_type not in (AgentMessageType.ENROLLMENT_REQUEST, AgentMessageType.ENROLLMENT_RESPONSE) and envelope.endpoint_id is None:
        raise ProtocolError("missing_endpoint_id", "authenticated protocol messages require endpoint_id")
    if envelope.message_type in (AgentMessageType.ASSESSMENT_ACK, AgentMessageType.ASSESSMENT_PROGRESS, AgentMessageType.ASSESSMENT_RESULT) and envelope.correlation_id is None:
        raise ProtocolError("missing_correlation_id", "assessment workflow messages require correlation_id")
    envelope.protocol_version.ensure_supported()
    current = _timestamp(now or datetime.now(timezone.utc), "now")
    delta = abs((current - envelope.timestamp).total_seconds())
    if delta > policy.max_clock_skew.total_seconds():
        raise ProtocolError("stale_or_future_message", "message timestamp is outside the allowed clock skew")
    size = len(json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if size > policy.max_payload_bytes:
        raise ProtocolError("payload_too_large", "message exceeds the configured payload size")


def message_direction(message_type: AgentMessageType) -> MessageDirection:
    message_type = AgentMessageType(message_type)
    if message_type in (AgentMessageType.HEARTBEAT, AgentMessageType.CAPABILITIES, AgentMessageType.STATUS,
                        AgentMessageType.ENROLLMENT_REQUEST, AgentMessageType.ASSESSMENT_PROGRESS,
                        AgentMessageType.ASSESSMENT_ACK, AgentMessageType.ASSESSMENT_RESULT, AgentMessageType.ERROR):
        return MessageDirection.AGENT_TO_CONTROL
    if message_type in (AgentMessageType.ENROLLMENT_RESPONSE, AgentMessageType.ASSESSMENT_DISPATCH):
        return MessageDirection.CONTROL_TO_AGENT
    return MessageDirection.BIDIRECTIONAL


class MessageRegistry:
    def __init__(self):
        self._types: Dict[AgentMessageType, Type[Any]] = {}

    def register(self, message_type: AgentMessageType, payload_type: Type[Any]) -> None:
        message_type = AgentMessageType(message_type)
        if message_type in self._types:
            raise ValueError(f"message type {message_type.value} is already registered")
        self._types[message_type] = payload_type

    def get(self, message_type: AgentMessageType) -> Optional[Type[Any]]:
        return self._types.get(AgentMessageType(message_type))

    def list(self) -> Tuple[AgentMessageType, ...]:
        return tuple(self._types)


def default_message_registry() -> MessageRegistry:
    registry = MessageRegistry()
    for message_type, payload_type in (
        (AgentMessageType.HEARTBEAT, AgentHeartbeat), (AgentMessageType.CAPABILITIES, AgentCapabilityReport),
        (AgentMessageType.STATUS, AgentStatusReport), (AgentMessageType.ENROLLMENT_REQUEST, EnrollmentRequestPayload),
        (AgentMessageType.ENROLLMENT_RESPONSE, EnrollmentResponsePayload), (AgentMessageType.ASSESSMENT_DISPATCH, AssessmentDispatch),
        (AgentMessageType.ASSESSMENT_ACK, AssessmentAcknowledgment),
        (AgentMessageType.ASSESSMENT_PROGRESS, AssessmentProgress), (AgentMessageType.ASSESSMENT_RESULT, AssessmentResultPayload),
        (AgentMessageType.ERROR, ProtocolError),
    ):
        registry.register(message_type, payload_type)
    return registry


# Short names used by protocol documentation; the explicit Payload suffixes
# remain the canonical DTO names.
EnrollmentRequest = EnrollmentRequestPayload
EnrollmentResponse = EnrollmentResponsePayload
AgentStatus = AgentStatusReport


def _finding_dict(value: Finding, assessment_id: str = "", endpoint_id: str = "", index: int = 0) -> Dict[str, Any]:
    result = {"finding_id": value.finding_id, "severity": value.severity.value, "category": value.category,
            "title": value.title, "details": value.details, "component": value.component,
            "remediation": value.remediation, "evidence": [_safe(item) for item in value.evidence],
            "metadata": _safe(value.metadata), "legacy_metadata": _safe(value.legacy_metadata)}
    return materialize_finding_identity(result, assessment_id=assessment_id, endpoint_id=endpoint_id, index=index)


def _coerce_timestamp(value: datetime) -> datetime:
    """Legacy local orchestration used naive UTC timestamps; normalize at the protocol boundary."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _scanner_result_dict(value: Any) -> Dict[str, Any]:
    if not isinstance(value, ScannerExecutionResult):
        return _safe(value)
    return {"scanner_id": value.scanner_id, "status": value.status.value, "started_at": value.started_at.isoformat(),
            "completed_at": value.completed_at.isoformat() if value.completed_at else None,
            "findings": [_finding_dict(item) for item in value.findings], "error": value.error,
            "native_metrics": _safe(value.native_metrics), "scanner_version": value.scanner_version,
            "execution_evidence": value.execution_evidence.to_dict() if value.execution_evidence else None,
            "error_category": value.error_category}


def _safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (ProtocolVersion, MessageId, CorrelationId)):
        return str(value)
    if isinstance(value, EndpointId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, PlatformInfo):
        return {"name": value.name, "version": value.version, "architecture": value.architecture}
    if isinstance(value, ScannerCapability):
        return value.value
    if isinstance(value, TargetCapabilities):
        return {"values": sorted(item.value for item in value.values), "observations": [_safe(item) for item in value.observations]}
    if isinstance(value, Mapping):
        return {str(key): _safe(item) for key, item in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_safe(item) for item in value]
    if is_dataclass(value):
        return {item.name: _safe(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"value of type {type(value).__name__} is not JSON-safe")
