"""Foreground Windows agent host with bounded, stoppable network polling."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import platform
import random
import socket
from threading import Event
import time

from ..application.scanner.local_capabilities import LocalTargetCapabilityProvider
from ..application.scanner.registry import ScannerRegistry
from ..application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from ..infrastructure.transport.http.client import HttpAgentTransport, HttpTransportConfig, HttpTransportError
from ..protocol.agent import ProtocolVersion
from .outbox import DurableResultSender, DurableResultSender as _DefaultDurableResultSender
from .renewal import CredentialRenewalCoordinator
from .runtime import AgentConfig, AgentLifecycleState, AgentStartupError, build_local_agent
from .windows_scanners import windows_read_only_scanners
from .windows_store import AgentStateError, WindowsAgentStateStore


AGENT_VERSION = "1.0.0-rc11"
DEFAULT_RENEWAL_THRESHOLD_SECONDS = 7 * 24 * 3600.0


def ca_certificate_digest(path: Path) -> str:
    data = Path(path).read_bytes()
    if not data or len(data) > 256 * 1024:
        raise AgentStateError("CA certificate is empty or too large")
    return hashlib.sha256(data).hexdigest()


def local_agent_config(*, protocol_version: str = "1.0", heartbeat_seconds: float = 60.0) -> AgentConfig:
    if platform.system() != "Windows":
        raise AgentStateError("the endpoint runtime requires Windows")
    return AgentConfig(
        agent_version=AGENT_VERSION,
        protocol_version=ProtocolVersion.parse(protocol_version),
        heartbeat_interval_seconds=heartbeat_seconds,
        hostname=socket.gethostname(), platform="Windows",
        platform_version=platform.version(), architecture=platform.machine(),
    )


@dataclass(frozen=True)
class HostIntervals:
    poll_seconds: float = 10.0
    heartbeat_seconds: float = 60.0
    maximum_backoff_seconds: float = 60.0
    renewal_threshold_seconds: float = DEFAULT_RENEWAL_THRESHOLD_SECONDS
    renewal_retry_seconds: float = 60.0

    def __post_init__(self):
        if min(self.poll_seconds, self.heartbeat_seconds, self.maximum_backoff_seconds,
               self.renewal_threshold_seconds, self.renewal_retry_seconds) <= 0:
            raise ValueError("agent intervals must be positive")


class WindowsAgentHost:
    """Keep one enrolled endpoint alive; execute only dispatched allowlisted checks."""

    def __init__(self, *, store: WindowsAgentStateStore, server_url: str, ca_cert: Path,
                 intervals: HostIntervals | None = None, transport=None, clock=time.monotonic,
                 jitter=random.uniform, stop_event: Event | None = None,
                 now_fn=None, renewal=None):
        self.store = store
        self.intervals = intervals or HostIntervals()
        self._clock = clock
        self._jitter = jitter
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self.stop_event = stop_event or Event()
        record = store.load_record()
        if record is None:
            raise AgentStateError("endpoint is not enrolled")
        load_pending = getattr(store, "load_pending_renewal", None)
        pending = load_pending() if load_pending is not None else None
        credential_valid = record.credential_expires_at > self._now()
        if not credential_valid and pending is None:
            raise AgentStateError("endpoint credential has expired; enroll again")
        if record.server_url != server_url.rstrip("/"):
            raise AgentStateError("server URL differs from enrolled control plane")
        if record.ca_sha256 != ca_certificate_digest(ca_cert):
            raise AgentStateError("CA certificate differs from enrolled trust anchor")
        self._owns_transport = transport is None
        self.transport = transport or HttpAgentTransport(
            HttpTransportConfig(server_url, verify=str(ca_cert)), store.credential_store,
            endpoint_id=record.endpoint_id,
        )
        store_files = getattr(store, "_files", None)
        if store_files is not None and DurableResultSender is _DefaultDurableResultSender:
            self.sender = DurableResultSender(self.transport, store.directory, files=store_files)
        else:
            self.sender = DurableResultSender(self.transport, store.directory)
        if renewal is None and hasattr(store, "renewal_lock") and hasattr(self.transport, "renew_credential"):
            renewal = CredentialRenewalCoordinator(
                store, self.transport, now_fn=self._now, clock=clock, jitter=jitter,
                threshold=timedelta(seconds=self.intervals.renewal_threshold_seconds),
                retry_interval=timedelta(seconds=self.intervals.renewal_retry_seconds),
            )
        self.renewal = renewal
        capabilities = LocalTargetCapabilityProvider()
        registry = ScannerRegistry(windows_read_only_scanners())
        self.agent = build_local_agent(
            config=local_agent_config(protocol_version=record.protocol_version,
                                      heartbeat_seconds=self.intervals.heartbeat_seconds),
            identity_store=store.identity_store,
            credential_store=store.credential_store,
            capability_provider=capabilities, scanner_registry=registry,
            assessment_orchestrator=LocalAssessmentOrchestrator(registry, capabilities.capabilities_for),
            sender=self.sender,
        )
        self._agent_started = False
        if credential_valid:
            # With an expired stored credential the agent starts only after the
            # prepared successor has been recovered in tick().
            self._start_agent()
        self._startup_sent = False
        self._next_heartbeat = 0.0

    def tick(self) -> str:
        """One bounded pass: advance renewal, drain durable results, report presence, and poll work."""
        if self.renewal is not None:
            self.renewal.advance()
        self._check_expiry()
        if not self._agent_started:
            self._start_agent()
        self.sender.flush()
        if not self._startup_sent:
            self.agent.emit_startup_messages(now=self._now())
            self._startup_sent = True
            self._next_heartbeat = self._clock() + self.intervals.heartbeat_seconds
        elif self._clock() >= self._next_heartbeat:
            self.sender.send(self.agent.heartbeat(now=self._now()))
            self._next_heartbeat = self._clock() + self.intervals.heartbeat_seconds
        try:
            work = self.transport.poll_work()
        except HttpTransportError as error:
            if error.code == "approval_required":
                return "pending_approval"
            raise
        if work is None:
            return "idle"
        self.agent.receive_leased_work(work)
        return "assessed"

    def run(self, *, once: bool = False) -> None:
        backoff = self.intervals.poll_seconds
        try:
            while not self.stop_event.is_set():
                try:
                    self.tick()
                    backoff = self.intervals.poll_seconds
                    if once:
                        return
                    self.stop_event.wait(self.intervals.poll_seconds)
                except HttpTransportError as error:
                    if error.code in {"authentication_failed", "missing_credential", "payload_too_large"}:
                        raise
                    if once:
                        raise
                    delay = min(backoff, self.intervals.maximum_backoff_seconds)
                    self.stop_event.wait(self._jitter(delay * 0.8, delay))
                    backoff = min(backoff * 2, self.intervals.maximum_backoff_seconds)
        finally:
            self.agent.stop()
            if self._owns_transport:
                self.transport.close()

    def _start_agent(self) -> None:
        if self.agent.start(now=self._now()) is not AgentLifecycleState.READY:
            raise AgentStartupError("endpoint failed to start")
        self._agent_started = True

    def _check_expiry(self):
        record = self.store.load_record()
        if record is None or record.credential_expires_at <= self._now():
            raise AgentStateError("endpoint credential has expired; enroll again")
