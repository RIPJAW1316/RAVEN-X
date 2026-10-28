"""WS-01 end-to-end renewal regressions: SQLite + HTTP ingress + agent state machine.

The control plane and the agent share a fake clock, and a fault-injecting
network sits between them. Server restarts rebuild every service on the same
SQLite file; agent restarts rebuild the store and coordinator on the same
protected directory.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from threading import Barrier, Event, Thread
from types import SimpleNamespace
from uuid import uuid4
import secrets
import sys

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

import backend.agent.host as host_module
from backend.agent.host import HostIntervals, WindowsAgentHost, ca_certificate_digest
from backend.agent.renewal import CredentialRenewalCoordinator, ReEnrollmentRequiredError, RenewalOutcome
from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners
from backend.agent.windows_store import AgentStateError, PendingRenewal, WindowsAgentStateStore
from backend.application.agent.processor import AgentMessageProcessor, CredentialEndpointAuthenticator, TypedMessageRouter
from backend.application.control_plane import AgentSessionRegistry, ControlPlaneAgentHandlers, RemoteAssessmentDispatcher
from backend.application.endpoint.registry import EndpointRegistry
from backend.application.enrollment import EnrollmentService
from backend.core.database.database import DatabaseManager
from backend.core.database.models import EndpointCredentialRecord, EndpointCredentialRenewalRecord
from backend.domain.endpoint import EndpointStatus, PlatformInfo
from backend.domain.enrollment import CredentialId, EnrollmentRequest
from backend.domain.organization import Organization, OrganizationId, OrganizationStatus
from backend.infrastructure.operational.rate_limiter import InMemoryRateLimiter
from backend.infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository
from backend.infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository
from backend.infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository
from backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from backend.infrastructure.persistence.sqlalchemy_replay_guard import SQLAlchemyReplayGuard
from backend.infrastructure.persistence.sqlalchemy_security_audit_repository import SQLAlchemySecurityAuditRepository
from backend.infrastructure.transport.http import (
    HttpAgentTransport, HttpControlPlaneTransport, HttpTransportConfig, RenewalReceipt, create_agent_http_app,
)
from backend.protocol.agent import AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, ProtocolVersion


T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
MINUTE = timedelta(minutes=1)
SERVER_URL = "https://control.example"


class FakeClock:
    def __init__(self, start):
        self.value = start

    def now(self):
        return self.value

    def advance(self, delta):
        self.value += delta


class _Protector:
    """Deterministic stand-in for machine DPAPI (the real one is exercised in unit tests)."""

    def protect(self, plaintext):
        return b"dpapi-test:" + plaintext

    def unprotect(self, ciphertext):
        if not ciphertext.startswith(b"dpapi-test:"):
            raise AgentStateError("protected agent state could not be decrypted")
        return ciphertext[len(b"dpapi-test:"):]


class _Files:
    """Atomic file operations without Windows ACL mutation (elevated ACLs are a physical gate)."""

    def verify_directory(self, path):
        assert Path(path).is_dir()

    def verify_protected_file(self, path):
        assert Path(path).is_file()

    def atomic_write_protected(self, path, data):
        target = Path(path)
        temporary = target.with_name(target.name + "." + uuid4().hex + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(target)

    def atomic_create_protected(self, path, data):
        with Path(path).open("xb") as handle:
            handle.write(data)


class _Server:
    """One control-plane process; ``restart`` builds a new one on the same database."""

    def __init__(self, config_path: Path, clock: FakeClock, *, verifier_key=None):
        self.config_path, self.clock = config_path, clock
        self.manager = DatabaseManager(str(config_path))
        self.manager.initialize_sync_engine()
        self.manager.create_tables()
        self.endpoints = SQLAlchemyEndpointRepository(self.manager)
        self.enrollments = SQLAlchemyEnrollmentRepository(self.manager)
        self.organizations = SQLAlchemyOrganizationRepository(self.manager)
        self.audit = SQLAlchemySecurityAuditRepository(self.manager)
        self.assessments = SQLAlchemyRemoteAssessmentRepository(self.manager)
        self.work = SQLAlchemyAgentWorkRepository(self.manager, endpoint_repository=self.endpoints,
                                                  assessment_repository=self.assessments)
        self.replay_guard = SQLAlchemyReplayGuard(self.manager)
        self.sessions = AgentSessionRegistry()
        handlers = ControlPlaneAgentHandlers(self.sessions, self.assessments, self.work, self.audit,
                                             endpoint_repository=self.endpoints)
        router = TypedMessageRouter()
        handlers.register_routes(router)
        self.verifier_key = verifier_key or secrets.token_bytes(32)
        self.service = EnrollmentService(self.enrollments, audit_sink=self.audit,
                                         organization_repository=self.organizations,
                                         verifier_key=self.verifier_key)
        processor = AgentMessageProcessor(CredentialEndpointAuthenticator(self.service), self.replay_guard,
                                          router=router, audit_repository=self.audit)
        self.app = create_agent_http_app(processor, self.service, work_repository=self.work,
                                         replay_guard=self.replay_guard, clock=clock.now,
                                         credential_rate_limiter=InMemoryRateLimiter(10_000, 60))
        self.client = TestClient(self.app)

    @classmethod
    def create(cls, tmp_path, clock):
        config = tmp_path / "ws01.yaml"
        config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % (tmp_path / "ws01.db").as_posix(),
                          encoding="utf-8")
        return cls(config, clock)

    def restart(self):
        self.client.close()
        self.manager.close()
        return _Server(self.config_path, self.clock, verifier_key=self.verifier_key)

    def enroll(self, *, ttl=timedelta(days=5), hostname="omen-agent"):
        issued_at = self.clock.now() - timedelta(days=1)
        organization = Organization(OrganizationId.new(), "Tenant", created_at=issued_at - timedelta(days=1),
                                    updated_at=issued_at - timedelta(days=1))
        self.organizations.add(organization)
        authorization, token = self.service.create_enrollment_authorization(
            organization_id=organization.organization_id, now=issued_at)
        endpoint, credential, secret = self.service.accept_enrollment(
            authorization.enrollment_id, token.value, EnrollmentRequest(hostname, PlatformInfo("Windows")),
            now=issued_at, credential_ttl=ttl)
        endpoint = self.endpoints.transition_status_for_organization(
            endpoint.endpoint_id, organization.organization_id, (EndpointStatus.NEW,), EndpointStatus.ACTIVE,
            issued_at + timedelta(seconds=1))
        return SimpleNamespace(organization=organization, endpoint=endpoint, credential=credential,
                               secret=secret.value)

    def set_organization(self, organization_id, status):
        current = self.organizations.get(organization_id)
        self.organizations.update(current.transition_to(status, self.clock.now()))

    def work_status(self, endpoint_id, secret):
        return self.client.post("/api/v1/agent/work", headers={
            "Authorization": f"Bearer {secret}", "X-Raven-Endpoint-Id": str(endpoint_id)}).status_code

    def heartbeat_status(self, endpoint_id, secret):
        now = self.clock.now()
        payload = AgentHeartbeat(endpoint_id, "1.0.0", ProtocolVersion.current(), now).to_dict()
        envelope = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, payload, endpoint_id=endpoint_id, timestamp=now)
        return self.client.post("/api/v1/agent/messages", json=envelope.to_dict(),
                                headers={"Authorization": f"Bearer {secret}"}).status_code

    def confirm_status(self, endpoint_id, credential_id, secret):
        return self.client.post("/api/v1/agent/renew/confirm", json={
            "message_id": str(uuid4()), "timestamp": self.clock.now().isoformat(), "nonce": uuid4().hex,
            "protocol_version": "1.0", "credential_id": str(credential_id),
        }, headers={"Authorization": f"Bearer {secret}", "X-Raven-Endpoint-Id": str(endpoint_id)}).status_code

    def renewal_rows(self, endpoint_id):
        with self.manager.get_db() as session:
            return [(row.predecessor_credential_id, row.successor_credential_id, row.confirmed_at is not None)
                    for row in session.query(EndpointCredentialRenewalRecord).filter_by(endpoint_id=str(endpoint_id))]

    def active_credentials(self, endpoint_id):
        with self.manager.get_db() as session:
            return sorted(row.credential_id for row in session.query(EndpointCredentialRecord).filter_by(
                endpoint_id=str(endpoint_id), status="active"))

    def close(self):
        self.client.close()
        self.manager.close()


def _fingerprint(secret):
    return hashlib.sha256(secret.encode("ascii")).hexdigest()[:16]


class _Network:
    """Routes agent requests to the current server; faults are consumed in order per path."""

    def __init__(self, server):
        self.server = server
        self.faults = []
        self.log = []
        self.captured = []

    def fail_next(self, path, mode):
        self.faults.append((path, mode))

    def _take(self, path):
        for index, (fault_path, mode) in enumerate(self.faults):
            if path.endswith(fault_path):
                del self.faults[index]
                return mode
        return None

    def forward(self, request, client=None):
        response = (client or self.server.client).request(
            request.method, request.url.raw_path.decode("ascii"), content=request.content,
            headers=dict(request.headers))
        return httpx.Response(response.status_code, headers=dict(response.headers), content=response.content)

    def handler(self, request):
        path = request.url.path
        bearer = request.headers.get("authorization", "").partition(" ")[2]
        mode = self._take(path)
        if mode == "unreachable":
            self.log.append((path, None, _fingerprint(bearer)))
            raise httpx.ConnectError("simulated outage: request never reached the server")
        if mode == "crash":
            raise RuntimeError("simulated agent process crash")
        if mode == "hold":
            # The agent gives up on this request, but it is still in flight to the server.
            self.held = Thread(target=lambda: self.held_result.append(self.forward(request, TestClient(self.server.app))))
            self.held_result = []
            self.held.start()
            raise httpx.ReadTimeout("simulated client timeout while the request is in flight")
        response = self.forward(request)
        self.log.append((path, response.status_code, _fingerprint(bearer)))
        if mode == "lose_response":
            self.captured.append(response.json())
            raise httpx.ReadTimeout("simulated lost response after the server committed")
        return response


def _agent(tmp_path, network, enrolled, clock, *, name="agent", ca_sha256="c" * 64):
    directory = tmp_path / name
    directory.mkdir(exist_ok=True)
    store = WindowsAgentStateStore(directory, protector=_Protector(), files=_Files())
    if store.load_record() is None:
        grant = SimpleNamespace(endpoint_id=enrolled.endpoint.endpoint_id,
                                credential_id=str(enrolled.credential.credential_id),
                                credential_secret=enrolled.secret,
                                organization_id=str(enrolled.organization.organization_id),
                                protocol_version="1.0", credential_expires_at=enrolled.credential.expires_at)
        store.save_enrollment(grant, server_url=SERVER_URL, ca_sha256=ca_sha256)
    transport = HttpAgentTransport(HttpTransportConfig(SERVER_URL), store.credential_store,
                                   endpoint_id=enrolled.endpoint.endpoint_id,
                                   client=httpx.Client(transport=httpx.MockTransport(network.handler)))
    coordinator = CredentialRenewalCoordinator(store, transport, now_fn=clock.now, clock=lambda: 0.0,
                                               retry_interval=timedelta(0))
    return SimpleNamespace(store=store, transport=transport, coordinator=coordinator, directory=directory)


@pytest.fixture
def world(tmp_path):
    clock = FakeClock(T0 + timedelta(days=1))
    server = _Server.create(tmp_path, clock)
    enrolled = server.enroll()
    network = _Network(server)
    agent = _agent(tmp_path, network, enrolled, clock)
    state = SimpleNamespace(clock=clock, server=server, enrolled=enrolled, network=network, agent=agent,
                            tmp_path=tmp_path)
    yield state
    state.server.close()


def _restart_server(world):
    world.server = world.server.restart()
    world.network.server = world.server


def _assert_converged(world, pending):
    """Agent and control plane agree on exactly one authorized credential: the prepared successor."""
    record = world.agent.store.load_record()
    endpoint_id = world.enrolled.endpoint.endpoint_id
    assert record.credential_id == pending.successor_credential_id
    assert record.credential_secret == pending.successor_credential_secret
    assert world.agent.store.load_pending_renewal() is None
    assert world.server.active_credentials(endpoint_id) == [str(pending.successor_credential_id)]
    assert [row[:2] for row in world.server.renewal_rows(endpoint_id)] == [
        (str(world.enrolled.credential.credential_id), str(pending.successor_credential_id))]
    assert world.server.work_status(endpoint_id, pending.successor_credential_secret) == 200
    assert world.server.work_status(endpoint_id, world.enrolled.secret) == 401


def _commit_with_lost_response(world):
    world.network.fail_next("/renew", "lose_response")
    assert world.agent.coordinator.advance() is RenewalOutcome.DEFERRED
    pending = world.agent.store.load_pending_renewal()
    assert pending is not None
    assert world.agent.store.load_record().credential_id == world.enrolled.credential.credential_id
    rows = world.server.renewal_rows(world.enrolled.endpoint.endpoint_id)
    assert rows == [(str(world.enrolled.credential.credential_id), str(pending.successor_credential_id), False)]
    return pending


def test_a_lost_response_followed_by_an_immediate_retry_is_idempotent(world):
    pending = _commit_with_lost_response(world)
    before = len(world.network.log)

    assert world.agent.coordinator.advance() is RenewalOutcome.RENEWED
    assert [entry[:2] for entry in world.network.log[before:]] == [
        ("/api/v1/agent/renew", 200), ("/api/v1/agent/renew/confirm", 200)]
    _assert_converged(world, pending)


@pytest.mark.parametrize("outage", [timedelta(minutes=20), timedelta(hours=12)], ids=["20-minutes", "overnight"])
def test_a_lost_response_followed_by_an_outage_beyond_the_overlap_recovers_with_the_prepared_successor(world, outage):
    pending = _commit_with_lost_response(world)
    committed_at = world.clock.now()
    world.clock.advance(outage)
    before = len(world.network.log)

    assert world.agent.coordinator.advance() is RenewalOutcome.RECOVERED
    assert [entry[:2] for entry in world.network.log[before:]] == [
        ("/api/v1/agent/renew", 401), ("/api/v1/agent/renew/confirm", 200)]
    renewal = world.server.enrollments.get_renewal_for_predecessor(world.enrolled.credential.credential_id)
    assert renewal.predecessor_valid_until == committed_at + 15 * MINUTE
    _assert_converged(world, pending)


@pytest.mark.parametrize("power_off", [timedelta(minutes=2), timedelta(hours=3)], ids=["inside-overlap", "beyond-overlap"])
def test_power_loss_after_server_commit_but_before_local_replacement_recovers_after_reboot(world, monkeypatch, power_off):
    class PowerLoss(Exception):
        pass

    def lose_power(*_args, **_kwargs):
        raise PowerLoss("power lost before credential.bin was replaced")

    monkeypatch.setattr(world.agent.store, "promote_renewal", lose_power)
    with pytest.raises(PowerLoss):
        world.agent.coordinator.advance()
    monkeypatch.undo()
    pending = world.agent.store.load_pending_renewal()
    assert world.agent.store.load_record().credential_id == world.enrolled.credential.credential_id
    world.clock.advance(power_off)

    world.agent = _agent(world.tmp_path, world.network, world.enrolled, world.clock)
    expected = RenewalOutcome.RENEWED if power_off < 15 * MINUTE else RenewalOutcome.RECOVERED
    assert world.agent.coordinator.advance() is expected
    _assert_converged(world, pending)


def test_concurrent_requests_with_distinct_message_ids_converge_and_a_rival_successor_conflicts(world):
    endpoint_id = world.enrolled.endpoint.endpoint_id
    successor_id, successor_secret = str(CredentialId.new()), secrets.token_urlsafe(32)

    def post(successor, barrier=None):
        client = TestClient(world.server.app)
        if barrier is not None:
            barrier.wait(timeout=10)
        return client.post("/api/v1/agent/renew", json={
            "message_id": str(uuid4()), "timestamp": world.clock.now().isoformat(), "nonce": uuid4().hex,
            "protocol_version": "1.0", "credential_id": str(world.enrolled.credential.credential_id),
            "successor_credential_id": successor[0], "successor_credential_secret": successor[1],
        }, headers={"Authorization": f"Bearer {world.enrolled.secret}", "X-Raven-Endpoint-Id": str(endpoint_id)})

    barrier = Barrier(4)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: post((successor_id, successor_secret), barrier), range(4)))
    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    bodies = [response.json() for response in responses]
    assert {body["credential_id"] for body in bodies} == {successor_id}
    assert len({body["predecessor_valid_until"] for body in bodies}) == 1
    assert all("secret" not in key for body in bodies for key in body)
    assert all(successor_secret not in response.text for response in responses)

    rival = post((str(CredentialId.new()), secrets.token_urlsafe(32)))
    assert rival.status_code == 409 and rival.json() == {"error": "renewal_conflict"}
    assert world.server.active_credentials(endpoint_id) == [successor_id]
    assert world.server.renewal_rows(endpoint_id) == [(str(world.enrolled.credential.credential_id), successor_id, False)]


def test_a_delayed_response_arriving_after_the_retry_response_cannot_change_agent_state(world):
    pending = _commit_with_lost_response(world)
    delayed = world.network.captured[-1]
    assert world.agent.coordinator.advance() is RenewalOutcome.RENEWED
    promoted = world.agent.store.load_record()

    receipt = RenewalReceipt.from_dict(delayed, now=world.clock.now())
    assert receipt.credential_id == str(pending.successor_credential_id)
    assert world.agent.store.promote_renewal(pending, credential_expires_at=receipt.credential_expires_at) == promoted
    unrelated = PendingRenewal(pending.endpoint_id, pending.organization_id, pending.predecessor_credential_id,
                               CredentialId.new(), secrets.token_urlsafe(32), world.clock.now())
    with pytest.raises(AgentStateError):
        world.agent.store.promote_renewal(unrelated, credential_expires_at=receipt.credential_expires_at)
    assert world.agent.store.load_record() == promoted
    _assert_converged(world, pending)


def test_an_in_flight_request_landing_after_the_successor_was_persisted_changes_nothing(world):
    gate, entered = Event(), Event()
    original = world.server.service.renew_credential

    def delayed_renewal(*args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert gate.wait(timeout=20)
        return original(*args, **kwargs)

    world.server.service.renew_credential = delayed_renewal
    world.network.fail_next("/renew", "hold")
    assert world.agent.coordinator.advance() is RenewalOutcome.DEFERRED
    assert entered.wait(timeout=10)
    pending = world.agent.store.load_pending_renewal()

    # The retry wins while the first request is still in flight; confirmation is lost.
    world.network.fail_next("/renew/confirm", "unreachable")
    assert world.agent.coordinator.advance() is RenewalOutcome.RENEWED
    assert world.agent.store.load_record().credential_id == pending.successor_credential_id
    gate.set()
    world.network.held.join(timeout=20)
    late = world.network.held_result[0]
    assert late.status_code == 200 and late.json()["credential_id"] == str(pending.successor_credential_id)
    _assert_converged(world, pending)


def test_a_crash_after_local_persistence_but_before_confirmation_is_confirmed_by_the_next_request(world):
    world.network.fail_next("/renew/confirm", "crash")
    with pytest.raises(RuntimeError, match="crash"):
        world.agent.coordinator.advance()
    record = world.agent.store.load_record()
    rows = world.server.renewal_rows(world.enrolled.endpoint.endpoint_id)
    assert rows[0][1] == str(record.credential_id) and rows[0][2] is False
    assert world.agent.store.load_pending_renewal() is None

    world.agent = _agent(world.tmp_path, world.network, world.enrolled, world.clock)
    assert world.agent.coordinator.advance() is RenewalOutcome.NOT_DUE
    assert world.server.work_status(world.enrolled.endpoint.endpoint_id, record.credential_secret) == 200
    assert world.server.renewal_rows(world.enrolled.endpoint.endpoint_id)[0][2] is True
    assert world.server.work_status(world.enrolled.endpoint.endpoint_id, world.enrolled.secret) == 401


def test_server_restarts_between_preparation_issuance_and_confirmation(world):
    world.network.fail_next("/renew", "unreachable")
    assert world.agent.coordinator.advance() is RenewalOutcome.DEFERRED
    pending = world.agent.store.load_pending_renewal()
    assert world.server.renewal_rows(world.enrolled.endpoint.endpoint_id) == []

    _restart_server(world)
    world.network.fail_next("/renew", "lose_response")
    assert world.agent.coordinator.advance() is RenewalOutcome.DEFERRED
    assert world.agent.store.load_pending_renewal() == pending

    _restart_server(world)
    world.clock.advance(16 * MINUTE)
    assert world.agent.coordinator.advance() is RenewalOutcome.RECOVERED

    _restart_server(world)
    _assert_converged(world, pending)


def test_endpoint_revocation_during_renewal_requires_re_enrollment_and_preserves_local_evidence(world):
    pending = _commit_with_lost_response(world)
    endpoint = world.enrolled.endpoint
    world.server.endpoints.transition_status_for_organization(
        endpoint.endpoint_id, world.enrolled.organization.organization_id, (EndpointStatus.ACTIVE,),
        EndpointStatus.REVOKED, world.clock.now())

    with pytest.raises(ReEnrollmentRequiredError):
        world.agent.coordinator.advance()
    assert world.agent.store.load_record().credential_id == world.enrolled.credential.credential_id
    assert world.agent.store.load_pending_renewal() == pending
    for secret in (world.enrolled.secret, pending.successor_credential_secret):
        assert world.server.work_status(endpoint.endpoint_id, secret) == 401


def test_organization_suspension_and_revocation_during_renewal_and_ordinary_traffic(world):
    pending = _commit_with_lost_response(world)
    endpoint_id = world.enrolled.endpoint.endpoint_id
    organization_id = world.enrolled.organization.organization_id
    old_secret, new_secret = world.enrolled.secret, pending.successor_credential_secret

    world.server.set_organization(organization_id, OrganizationStatus.SUSPENDED)
    for secret in (old_secret, new_secret):
        assert world.server.work_status(endpoint_id, secret) == 403
        assert world.server.heartbeat_status(endpoint_id, secret) == 403
    assert world.server.confirm_status(endpoint_id, pending.successor_credential_id, new_secret) == 403
    assert world.agent.coordinator.advance() is RenewalOutcome.DEFERRED
    assert world.agent.store.load_pending_renewal() == pending
    assert world.server.renewal_rows(endpoint_id)[0][2] is False
    assert world.server.work_status(endpoint_id, "not-the-secret") == 401

    world.server.set_organization(organization_id, OrganizationStatus.ACTIVE)
    assert world.agent.coordinator.advance() is RenewalOutcome.RENEWED
    assert world.server.heartbeat_status(endpoint_id, new_secret) == 200

    world.server.set_organization(organization_id, OrganizationStatus.REVOKED)
    for secret in (old_secret, new_secret):
        assert world.server.work_status(endpoint_id, secret) == 401
        assert world.server.heartbeat_status(endpoint_id, secret) == 401
    assert world.server.confirm_status(endpoint_id, pending.successor_credential_id, new_secret) == 401
    # Once the successor is due for its own renewal, the revoked tenant cannot renew it either.
    world.clock.advance(timedelta(days=24))
    with pytest.raises(ReEnrollmentRequiredError):
        world.agent.coordinator.advance()


def test_an_outage_across_natural_expiry_recovers_a_committed_successor_and_never_presents_an_expired_credential(world):
    pending = _commit_with_lost_response(world)
    expired_at = world.enrolled.credential.expires_at
    world.clock.value = expired_at + timedelta(days=1)
    before = len(world.network.log)

    assert world.agent.coordinator.advance() is RenewalOutcome.RECOVERED
    after = world.network.log[before:]
    assert [entry[:2] for entry in after] == [("/api/v1/agent/renew/confirm", 200)]
    assert all(entry[2] != _fingerprint(world.enrolled.secret) for entry in after)
    _assert_converged(world, pending)


def test_an_outage_across_natural_expiry_without_a_committed_successor_requires_re_enrollment(world):
    world.network.fail_next("/renew", "unreachable")
    assert world.agent.coordinator.advance() is RenewalOutcome.DEFERRED
    pending = world.agent.store.load_pending_renewal()
    world.clock.value = world.enrolled.credential.expires_at + timedelta(hours=1)
    before = len(world.network.log)

    with pytest.raises(ReEnrollmentRequiredError):
        world.agent.coordinator.advance()
    after = world.network.log[before:]
    assert [entry[:2] for entry in after] == [("/api/v1/agent/renew/confirm", 401)]
    assert all(entry[2] != _fingerprint(world.enrolled.secret) for entry in after)
    assert world.server.renewal_rows(world.enrolled.endpoint.endpoint_id) == []
    assert world.agent.store.load_pending_renewal() == pending
    assert world.server.work_status(world.enrolled.endpoint.endpoint_id, world.enrolled.secret) == 401


def test_the_database_rejects_a_second_successor_for_one_predecessor(world):
    _commit_with_lost_response(world)
    endpoint_id = str(world.enrolled.endpoint.endpoint_id)
    with pytest.raises(IntegrityError):
        with world.server.manager.get_db() as session:
            session.execute(insert(EndpointCredentialRenewalRecord).values(
                successor_credential_id=str(uuid4()),
                predecessor_credential_id=str(world.enrolled.credential.credential_id),
                endpoint_id=endpoint_id, issued_at=world.clock.now().replace(tzinfo=None),
                predecessor_valid_until=world.clock.now().replace(tzinfo=None)))


def test_renewal_audit_events_are_tenant_attributed_and_secret_free(world):
    pending = _commit_with_lost_response(world)
    assert world.agent.coordinator.advance() is RenewalOutcome.RENEWED

    events = world.server.audit.list(endpoint_id=str(world.enrolled.endpoint.endpoint_id))
    types = {item.event_type for item in events}
    assert {"credential.renewed", "credential.renewal_confirmed"} <= types
    assert all(item.organization_id == str(world.enrolled.organization.organization_id) for item in events)
    serialized = str([item.to_dict() for item in world.server.audit.list()])
    assert world.enrolled.secret not in serialized
    assert pending.successor_credential_secret not in serialized


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows agent host requires Windows")
def test_host_renews_then_executes_assessment_work_with_the_renewed_credential(tmp_path, monkeypatch):
    # Real time: the runtime validates dispatch freshness against the wall clock.
    clock = FakeClock(datetime.now(timezone.utc))
    server = _Server.create(tmp_path, clock)
    enrolled = server.enroll(ttl=timedelta(days=5))
    network = _Network(server)
    ca_cert = tmp_path / "ca.pem"
    ca_cert.write_text("CA", encoding="utf-8")
    agent = _agent(tmp_path, network, enrolled, clock, ca_sha256=ca_certificate_digest(ca_cert))
    manifest = next(item.manifest for item in windows_read_only_scanners() if item.manifest.scanner_id == "windows.uac")
    scanner = WindowsReadOnlyScanner(manifest, registry_reader=lambda name: {
        "ConsentPromptBehaviorAdmin": 5, "PromptOnSecureDesktop": 1}[name])
    monkeypatch.setattr(host_module, "windows_read_only_scanners", lambda: (scanner,))
    host = WindowsAgentHost(store=agent.store, server_url=SERVER_URL, ca_cert=ca_cert, transport=agent.transport,
                            intervals=HostIntervals(renewal_retry_seconds=1.0))
    try:
        clock.value = datetime.now(timezone.utc)
        assert host.tick() == "idle"
        renewed = agent.store.load_record()
        assert renewed.credential_id != enrolled.credential.credential_id
        assert server.work_status(enrolled.endpoint.endpoint_id, enrolled.secret) == 401

        dispatcher = RemoteAssessmentDispatcher(EndpointRegistry(server.endpoints), server.sessions,
                                                HttpControlPlaneTransport(), server.assessments,
                                                work_repository=server.work)
        assessment = dispatcher.dispatch(enrolled.endpoint.endpoint_id, ("windows.uac",))
        clock.value = datetime.now(timezone.utc)
        assert host.tick() == "assessed"
        assert server.assessments.get(assessment.assessment_id).state.value == "completed"
    finally:
        host.agent.stop()
        server.close()


def test_confirmed_successor_is_rejected_after_predecessor_compromise_revocation(world):
    pending = world.agent.store.prepare_renewal(now=world.clock.now())
    assert world.agent.coordinator.advance() is RenewalOutcome.RENEWED
    endpoint_id = world.enrolled.endpoint.endpoint_id
    world.server.service.revoke_compromised_credential(
        world.enrolled.credential.credential_id, now=world.clock.now(), reason="stolen predecessor")

    assert world.server.work_status(endpoint_id, pending.successor_credential_secret) == 401
    assert world.server.heartbeat_status(endpoint_id, pending.successor_credential_secret) == 401
    assert world.server.confirm_status(endpoint_id, pending.successor_credential_id,
                                       pending.successor_credential_secret) == 401
    body = {
        "message_id": str(uuid4()), "timestamp": world.clock.now().isoformat(), "nonce": uuid4().hex,
        "protocol_version": "1.0", "credential_id": str(pending.successor_credential_id),
        "successor_credential_id": str(uuid4()), "successor_credential_secret": secrets.token_urlsafe(32),
    }
    renew = world.server.client.post("/api/v1/agent/renew", json=body, headers={
        "Authorization": f"Bearer {pending.successor_credential_secret}",
        "X-Raven-Endpoint-Id": str(endpoint_id),
    })
    assert renew.status_code == 401
    other = world.server.enroll(hostname="win-02")
    assert world.server.work_status(other.endpoint.endpoint_id, other.secret) == 200


def test_lost_receipt_blocks_pre_renewal_binary_rollback(world):
    from backend.application.ops.rollback import evaluate_server_rollback
    pending = _commit_with_lost_response(world)
    decision = evaluate_server_rollback(world.server.enrollments, target_schema=1,
                                        engine=world.server.manager.engine)
    assert not decision.allowed
    assert decision.code == "pending_renewal_lineage"
    assert world.agent.store.load_record().credential_id == world.enrolled.credential.credential_id
    assert world.agent.store.load_pending_renewal().successor_credential_id == pending.successor_credential_id
