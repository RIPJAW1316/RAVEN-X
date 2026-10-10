"""First local Raven-X endpoint-agent runtime; networking remains deferred."""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Protocol, Tuple

from ..application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from ..application.scanner.local_capabilities import LocalTargetCapabilityProvider
from ..application.scanner.registry import ScannerRegistry
from ..application.enrollment.service import EnrollmentService
from ..application.ports.agent_transport import AgentMessageSender
from ..domain.assessment import AssessmentTarget, AssessmentStatus
from ..domain.endpoint import EndpointId
from ..domain.enrollment import CredentialId
from ..protocol.agent import (
    AgentCapabilityReport, AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, AgentRuntimeState,
    AgentStatusReport, AssessmentAcknowledgment, AssessmentDispatch, AssessmentProgress, AssessmentResultPayload, MessageDirection,
    ProtocolError, ProtocolVersion, ProtocolValidationPolicy,
    message_direction, validate_envelope,
)


class AgentLifecycleState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    BUSY = "busy"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    UNENROLLED = "unenrolled"


class AgentStartupError(RuntimeError):
    pass


class AgentIdentityStore(Protocol):
    def load(self) -> Optional[EndpointId]: ...
    def store(self, endpoint_id: EndpointId) -> None: ...
    def exists(self) -> bool: ...


class AgentCredentialStore(Protocol):
    def load(self) -> Optional["AgentCredential"]: ...
    def store(self, credential: "AgentCredential") -> None: ...
    def clear(self) -> None: ...


@dataclass(frozen=True)
class AgentConfig:
    agent_version: str = "1.0.0"
    protocol_version: ProtocolVersion = ProtocolVersion.current()
    heartbeat_interval_seconds: float = 60.0
    hostname: str = "local-agent"
    platform: str = "Windows"
    platform_version: Optional[str] = None
    architecture: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.agent_version.strip() or not self.hostname.strip() or not self.platform.strip():
            raise ValueError("agent_version, hostname, and platform are required")
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat interval must be positive")
        if isinstance(self.protocol_version, str):
            object.__setattr__(self, "protocol_version", ProtocolVersion.parse(self.protocol_version))


@dataclass(frozen=True)
class AgentCredential:
    credential_id: CredentialId
    secret: str

    def __post_init__(self) -> None:
        if not self.secret:
            raise ValueError("credential secret must not be empty")
        if not isinstance(self.credential_id, CredentialId):
            object.__setattr__(self, "credential_id", CredentialId(self.credential_id))

    def __repr__(self) -> str:
        return f"AgentCredential(credential_id={self.credential_id!s}, secret=<redacted>)"


class InMemoryAgentIdentityStore:
    def __init__(self, endpoint_id: Optional[EndpointId] = None):
        self._endpoint_id = endpoint_id

    def load(self) -> Optional[EndpointId]:
        return self._endpoint_id

    def store(self, endpoint_id: EndpointId) -> None:
        self._endpoint_id = endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(endpoint_id)

    def exists(self) -> bool:
        return self._endpoint_id is not None

    def clear(self) -> None:
        self._endpoint_id = None


class InMemoryAgentCredentialStore:
    def __init__(self, credential: Optional[AgentCredential] = None):
        self._credential = credential

    def load(self) -> Optional[AgentCredential]:
        return self._credential

    def store(self, credential: AgentCredential) -> None:
        self._credential = credential

    def clear(self) -> None:
        self._credential = None


class AgentEnrollmentInstaller:
    def __init__(self, identity_store: InMemoryAgentIdentityStore, credential_store: InMemoryAgentCredentialStore):
        self._identity_store, self._credential_store = identity_store, credential_store

    def install(self, response) -> None:
        self._identity_store.store(response.endpoint_id)
        self._credential_store.store(AgentCredential(response.credential_id, response.credential_secret))


class RavenXAgent:
    def __init__(self, *, config: AgentConfig, identity_store, credential_store,
                 capability_provider, scanner_registry, assessment_orchestrator,
                 sender: AgentMessageSender):
        self.config = config
        self.identity_store = identity_store
        self.credential_store = credential_store
        self.capability_provider = capability_provider
        self.scanner_registry = scanner_registry
        self.assessment_orchestrator = assessment_orchestrator
        self.sender = sender
        self.state = AgentLifecycleState.STOPPED
        self._capabilities = None
        self._started_at: Optional[datetime] = None

    @property
    def endpoint_id(self) -> Optional[EndpointId]:
        return self.identity_store.load()

    @property
    def target(self) -> Optional[AssessmentTarget]:
        if self.endpoint_id is None:
            return None
        return AssessmentTarget(
            target_id=str(self.endpoint_id), hostname=self.config.hostname, platform=self.config.platform,
            platform_version=self.config.platform_version,
            metadata={"architecture": self.config.architecture, "agent_version": self.config.agent_version},
        )

    @property
    def capabilities(self):
        return self._capabilities

    def start(self, *, now: Optional[datetime] = None) -> AgentLifecycleState:
        self.state = AgentLifecycleState.STARTING
        self._started_at = _utc(now or datetime.now(timezone.utc))
        if not self.config.protocol_version.supported:
            self.state = AgentLifecycleState.DEGRADED
            raise AgentStartupError("configured protocol version is unsupported")
        if self.identity_store.load() is None or self.credential_store.load() is None:
            self.state = AgentLifecycleState.UNENROLLED
            return self.state
        try:
            self._capabilities = self.capability_provider.capabilities_for(self.target)
        except Exception as error:
            self.state = AgentLifecycleState.DEGRADED
            raise AgentStartupError("capability discovery failed") from error
        self.state = AgentLifecycleState.READY
        return self.state

    def stop(self) -> None:
        self.state = AgentLifecycleState.STOPPED

    def heartbeat(self, *, now: Optional[datetime] = None) -> AgentMessageEnvelope:
        self._require_started_identity()
        observed = _utc(now or datetime.now(timezone.utc))
        payload = AgentHeartbeat(
            self.endpoint_id, self.config.agent_version, self.config.protocol_version, observed,
            max(0, int((observed - self._started_at).total_seconds())) if self._started_at else None,
            "healthy" if self.state in (AgentLifecycleState.READY, AgentLifecycleState.BUSY) else "degraded",
        )
        return self._envelope(AgentMessageType.HEARTBEAT, payload.to_dict(), observed)

    def capability_report(self, *, now: Optional[datetime] = None) -> AgentMessageEnvelope:
        self._require_started_identity()
        if self._capabilities is None:
            raise AgentStartupError("capabilities are not available")
        observed = _utc(now or datetime.now(timezone.utc))
        payload = AgentCapabilityReport(self.endpoint_id, self._capabilities, observed)
        return self._envelope(AgentMessageType.CAPABILITIES, payload.to_dict(), observed)

    def status(self, *, now: Optional[datetime] = None) -> AgentMessageEnvelope:
        self._require_started_identity()
        observed = _utc(now or datetime.now(timezone.utc))
        runtime_state = {
            AgentLifecycleState.READY: AgentRuntimeState.RUNNING,
            AgentLifecycleState.BUSY: AgentRuntimeState.RUNNING,
            AgentLifecycleState.DEGRADED: AgentRuntimeState.DEGRADED,
            AgentLifecycleState.STARTING: AgentRuntimeState.STARTING,
            AgentLifecycleState.STOPPED: AgentRuntimeState.STOPPED,
            AgentLifecycleState.UNENROLLED: AgentRuntimeState.STOPPED,
        }[self.state]
        payload = AgentStatusReport(
            self.endpoint_id, self.config.agent_version, self.config.protocol_version,
            runtime_state,
            scanner_catalog_version="1.0",
        )
        return self._envelope(AgentMessageType.STATUS, payload.to_dict(), observed)

    def emit_startup_messages(self, *, now: Optional[datetime] = None) -> Tuple[AgentMessageEnvelope, ...]:
        messages = (self.heartbeat(now=now), self.capability_report(now=now), self.status(now=now))
        for message in messages:
            self.sender.send(message)
        return messages

    def handle_dispatch(self, envelope: AgentMessageEnvelope, *, now: Optional[datetime] = None,
                        work_id: Optional[str] = None, lease_token: Optional[str] = None) -> AssessmentResultPayload:
        now = _utc(now or datetime.now(timezone.utc))
        self._require_started_identity()
        if self.state is AgentLifecycleState.BUSY:
            raise AgentStartupError("agent is busy with another assessment")
        try:
            validate_envelope(envelope, now=now, policy=ProtocolValidationPolicy())
        except ProtocolError as error:
            raise AgentStartupError(error.message) from error
        if envelope.message_type is not AgentMessageType.ASSESSMENT_DISPATCH:
            raise AgentStartupError("agent accepts only assessment.dispatch messages")
        if message_direction(envelope.message_type) is not MessageDirection.CONTROL_TO_AGENT:
            raise AgentStartupError("assessment dispatch direction is invalid")
        if envelope.endpoint_id != self.endpoint_id:
            raise AgentStartupError("assessment dispatch targets another endpoint")
        if envelope.correlation_id is None:
            raise AgentStartupError("assessment dispatch requires correlation_id")
        dispatch = AssessmentDispatch(
            envelope.payload["assessment_id"], envelope.payload["endpoint_id"], tuple(envelope.payload["scanner_ids"]),
            datetime.fromisoformat(envelope.payload["requested_at"]),
            datetime.fromisoformat(envelope.payload["deadline"]) if envelope.payload.get("deadline") else None,
            envelope.payload.get("options", {}),
        )
        if dispatch.endpoint_id != self.endpoint_id:
            raise AgentStartupError("assessment dispatch targets another endpoint")
        if (work_id is None) != (lease_token is None):
            raise AgentStartupError("work_id and lease_token must be supplied together")
        if work_id is not None:
            self._emit_ack(dispatch, work_id, lease_token, now, envelope.correlation_id)
        self.state = AgentLifecycleState.BUSY
        total = len(dispatch.scanner_ids)
        self._emit_progress(dispatch, 0, (), "running", now, envelope.correlation_id)
        try:
            try:
                result = self.assessment_orchestrator.run(self.target, dispatch.scanner_ids)
            except Exception:
                from ..domain.assessment import AssessmentResult
                result = AssessmentResult(
                    assessment_id=dispatch.assessment_id, target=self.target, status=AssessmentStatus.FAILED,
                    started_at=now, finished_at=now, error="local assessment execution failed",
                )
            status = "completed" if result.status is AssessmentStatus.COMPLETED else "failed"
            scanner_results = tuple(result.scanner_results or ())
            if scanner_results:
                completed = []
                for scanner_result in scanner_results:
                    completed.append(scanner_result.scanner_id)
                    self._emit_progress(dispatch, len(completed), tuple(completed), status, now, envelope.correlation_id)
            else:
                self._emit_progress(dispatch, total, dispatch.scanner_ids, status, now, envelope.correlation_id)
            # The local orchestrator owns execution, while the dispatch owns the
            # distributed assessment identity. Bind the returned local result to
            # the control-plane assessment before crossing the protocol boundary.
            if result.assessment_id != dispatch.assessment_id:
                result = replace(result, assessment_id=dispatch.assessment_id)
            result_payload = AssessmentResultPayload.from_assessment_result(result)
            result_message = self._envelope(
                AgentMessageType.ASSESSMENT_RESULT, result_payload.to_dict(), result_payload.finished_at or now, envelope.correlation_id
            )
            self.sender.send(result_message)
            return result_payload
        finally:
            self.state = AgentLifecycleState.READY

    def receive(self, envelope: AgentMessageEnvelope) -> AssessmentResultPayload:
        """Transport receiver boundary; control plane never calls dispatch directly."""
        return self.handle_dispatch(envelope)

    def receive_leased_work(self, leased_work) -> AssessmentResultPayload:
        """Accept delivery metadata without coupling the runtime to HTTP."""
        return self.handle_dispatch(leased_work.envelope, work_id=leased_work.work_id,
                                    lease_token=leased_work.lease_token)

    def _emit_progress(self, dispatch, completed_count, completed, status, now, correlation_id):
        payload = AssessmentProgress(dispatch.assessment_id, status, tuple(completed), len(dispatch.scanner_ids), None, now, correlation_id)
        self.sender.send(self._envelope(AgentMessageType.ASSESSMENT_PROGRESS, payload.to_dict(), now, correlation_id))

    def _emit_ack(self, dispatch, work_id, lease_token, now, correlation_id):
        payload = AssessmentAcknowledgment(dispatch.assessment_id, str(work_id), lease_token, now)
        self.sender.send(self._envelope(AgentMessageType.ASSESSMENT_ACK, payload.to_dict(), now, correlation_id))

    def _envelope(self, message_type, payload, timestamp, correlation_id=None):
        return AgentMessageEnvelope(
            message_type=message_type, payload=payload, protocol_version=self.config.protocol_version,
            endpoint_id=self.endpoint_id, timestamp=_utc(timestamp), correlation_id=correlation_id,
        )

    def _require_started_identity(self):
        if self.endpoint_id is None or self.state in (AgentLifecycleState.STOPPED, AgentLifecycleState.UNENROLLED):
            raise AgentStartupError("agent is not enrolled and ready")


def build_local_agent(*, config: Optional[AgentConfig] = None, identity_store=None, credential_store=None,
                      capability_provider=None, scanner_registry=None, assessment_orchestrator=None, sender=None):
    config = config or AgentConfig()
    identity_store = identity_store or InMemoryAgentIdentityStore()
    credential_store = credential_store or InMemoryAgentCredentialStore()
    capability_provider = capability_provider or LocalTargetCapabilityProvider()
    if scanner_registry is None:
        # The historical in-process default remains available, but importing the
        # agent runtime must not import the personal GUI scanner on service start.
        from ..application.scanner.legacy_adapters import legacy_scanner_adapters
        scanner_registry = ScannerRegistry(legacy_scanner_adapters())
    assessment_orchestrator = assessment_orchestrator or LocalAssessmentOrchestrator(scanner_registry, capability_provider)
    if sender is None:
        raise ValueError("sender must be supplied explicitly; no transport is created implicitly")
    return RavenXAgent(config=config, identity_store=identity_store, credential_store=credential_store,
                      capability_provider=capability_provider, scanner_registry=scanner_registry,
                      assessment_orchestrator=assessment_orchestrator, sender=sender)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)
