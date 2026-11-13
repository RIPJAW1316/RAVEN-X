"""Real loopback TLS and read-only Windows-agent golden path.

All server state, certificates and database files live under pytest's tmp_path.
The in-memory agent credential stores are explicit test fixtures; the installed
Windows agent uses its protected Windows state store instead.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import platform
import json
from pathlib import Path
import secrets
import socket
import ssl
import sys
from threading import Thread
import time
from uuid import uuid4

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

from backend.agent.runtime import AgentConfig, AgentCredential, InMemoryAgentCredentialStore, InMemoryAgentIdentityStore, RavenXAgent
from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners
from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.application.agent.processor import AgentMessageProcessor, CredentialEndpointAuthenticator, TypedMessageRouter, decode_payload
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.assessment.tenant_service import TenantAssessmentService
from backend.application.control_plane import AgentSessionRegistry, ControlPlaneAgentHandlers, RemoteAssessmentDispatcher
from backend.application.endpoint import TenantEndpointService
from backend.application.endpoint.registry import EndpointRegistry
from backend.application.enrollment import EnrollmentService, TenantEnrollmentService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import OrganizationContextResolver, OrganizationMembershipService, OrganizationService
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.application.reporting.fleet_report import TenantFleetReportService
from backend.application.reporting.detail import TenantAssessmentDetailService
from backend.application.scanner.local_capabilities import LocalTargetCapabilityProvider, StaticTargetCapabilityProvider
from backend.application.scanner.registry import ScannerRegistry
from backend.core.database.database import DatabaseManager
from backend.core.database.models import EndpointCredentialRecord
from backend.cli import generate_local_tls
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.domain.security import SecurityPrincipal
from backend.domain.scanner import ScannerCapability, TargetCapabilities
from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository
from backend.infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository
from backend.infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository
from backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from backend.infrastructure.persistence.sqlalchemy_replay_guard import SQLAlchemyReplayGuard
from backend.infrastructure.transport.http import HttpAgentTransport, HttpControlPlaneTransport, HttpTransportConfig
from backend.infrastructure.transport.http.client import HttpAgentEnrollmentClient, HttpTransportError
from backend.infrastructure.transport.http.server import create_agent_http_router


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="real Windows read-only scanner test")


def _certificates(tmp_path):
    """Exercise the deployment CLI's TLS generator with test-only storage."""
    material = generate_local_tls(
        tmp_path / "tls", ["127.0.0.1"],
        protect=lambda path: path.mkdir(parents=True, exist_ok=True),
    )
    return tuple(Path(material[name]) for name in ("ca.pem", "server.pem", "server-key.pem"))


@contextmanager
def _https_server(app, cert_path, key_path):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
        ssl_certfile=str(cert_path), ssl_keyfile=str(key_path),
        lifespan="off", proxy_headers=False, access_log=False, log_level="critical", log_config=None))
    thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started, "loopback TLS server failed to start"
        yield f"https://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive(), "loopback TLS server failed to stop"


def _isolated_app(tmp_path, *, with_foreign_scope=False):
    db_path = tmp_path / "golden-path.db"
    config_path = tmp_path / "golden-path.yaml"
    config_path.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % db_path.as_posix(), encoding="utf-8")
    db = DatabaseManager(str(config_path))
    db.initialize_sync_engine()
    db.create_tables()
    endpoint_repository = SQLAlchemyEndpointRepository(db)
    enrollment_repository = SQLAlchemyEnrollmentRepository(db)
    assessment_repository = SQLAlchemyRemoteAssessmentRepository(db)
    work_repository = SQLAlchemyAgentWorkRepository(db, endpoint_repository=endpoint_repository,
                                                     assessment_repository=assessment_repository)
    sessions = AgentSessionRegistry()
    handlers = ControlPlaneAgentHandlers(sessions, assessment_repository, work_repository,
                                          endpoint_repository=endpoint_repository)
    agent_router = TypedMessageRouter()
    handlers.register_routes(agent_router)

    users = InMemoryUserRepository()
    owner = HumanIdentityService(users).create_initial_user(
        "golden-owner@example.com", "Golden owner", "GOLDEN_PASSWORD_SENTINEL")
    organizations = InMemoryOrganizationRepository()
    organization = OrganizationService(organizations).create("Golden tenant")
    agent_enrollment = EnrollmentService(enrollment_repository, organization_repository=organizations)
    processor = AgentMessageProcessor(CredentialEndpointAuthenticator(agent_enrollment),
                                      SQLAlchemyReplayGuard(db), router=agent_router)
    memberships = InMemoryOrganizationMembershipRepository()
    membership = OrganizationMembershipService(memberships, organizations, users).create(
        owner.user_id, organization.organization_id)
    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(organization.organization_id, "Golden operator", [
        "enrollment.create", "enrollment.revoke", "endpoint.read", "endpoint.update", "endpoint.revoke",
        "assessment.create", "assessment.read", "reports.read",
    ])
    RoleBindingService(bindings, roles, memberships).create(organization.organization_id,
                                                             membership.membership_id, role.role_id)
    foreign = None
    if with_foreign_scope:
        foreign = OrganizationService(organizations).create("Independent foreign tenant")
        other_membership = OrganizationMembershipService(memberships, organizations, users).create(
            owner.user_id, foreign.organization_id)
        other_role = RoleService(roles).create(foreign.organization_id, "Foreign reader", ["assessment.read"])
        RoleBindingService(bindings, roles, memberships).create(foreign.organization_id,
                                                               other_membership.membership_id, other_role.role_id)
    authorizer = OrganizationRbacAuthorizer(membership_repository=memberships,
        role_binding_repository=bindings, role_repository=roles, organization_repository=organizations,
        endpoint_repository=endpoint_repository)
    context_resolver = OrganizationContextResolver(users, memberships, organizations)
    class _NoPresence:
        def list_for_organization(self, organization_id):
            return ()
    report_service = TenantFleetReportService(endpoint_repository, _NoPresence(),
                                               assessment_repository, authorizer)
    dispatcher = RemoteAssessmentDispatcher(EndpointRegistry(endpoint_repository), sessions,
        HttpControlPlaneTransport(), assessment_repository, work_repository=work_repository,
        authorization_service=authorizer)
    tenant_assessments = TenantAssessmentService(endpoint_repository, assessment_repository,
                                                  dispatcher, authorizer)
    app = FastAPI()
    app.include_router(create_agent_http_router(processor, agent_enrollment,
                       work_repository=work_repository), prefix="/api/v1/agent")
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        HumanAuthenticationService(users), HumanSessionAuthenticator(users), users,
        context_resolver,
        TenantEndpointService(endpoint_repository, authorizer), tenant_assessments,
        organizations, memberships,
        enrollment_service=TenantEnrollmentService(enrollment_repository, authorizer),
        assessment_detail_service=TenantAssessmentDetailService(endpoint_repository, assessment_repository, authorizer),
    )), prefix="/api/v1")
    app.state.foreign_organization_id = str(foreign.organization_id) if foreign is not None else None
    return app, db, organization, owner, context_resolver, report_service


def test_verified_https_windows_read_only_golden_path(tmp_path):
    ca_path, cert_path, key_path = _certificates(tmp_path)
    trust = ssl.create_default_context(cafile=str(ca_path))
    trust.verify_flags |= ssl.VERIFY_X509_STRICT
    app, db, organization, owner, context_resolver, report_service = _isolated_app(tmp_path)
    with _https_server(app, cert_path, key_path) as base_url:
        config = HttpTransportConfig(base_url, verify=trust, timeout_seconds=30)
        with httpx.Client(verify=trust, trust_env=False, timeout=30) as human:
            login = human.post(base_url + "/api/v1/auth/login", json={
                "email": "golden-owner@example.com", "password": "GOLDEN_PASSWORD_SENTINEL"})
            assert login.status_code == 200
            session = login.json()["session_token"]
            human_headers = {"Authorization": f"Bearer {session}"}
            tenant_base = f"{base_url}/api/v1/organizations/{organization.organization_id}"
            issued = human.post(tenant_base + "/enrollment-tokens", headers=human_headers,
                                json={"ttl_minutes": 10, "label": "loopback Windows"})
            assert issued.status_code == 201
            token = issued.json()
            assert issued.headers["cache-control"] == "no-store"

            enrollment_client = HttpAgentEnrollmentClient(config)
            try:
                grant = enrollment_client.enroll(
                    enrollment_id=token["enrollment_id"], bootstrap_token=token["enrollment_token"],
                    hostname=socket.gethostname(), platform_name="Windows", platform_version=platform.version(),
                    architecture=platform.machine(), agent_version="1.0.0", protocol_version="1.0",
                    request_id=str(uuid4()), nonce=str(uuid4()))
                assert grant.organization_id == str(organization.organization_id)
                assert grant.status == "new"
                with pytest.raises(HttpTransportError) as replay:
                    enrollment_client.enroll(
                        enrollment_id=token["enrollment_id"], bootstrap_token=token["enrollment_token"],
                        hostname=socket.gethostname(), platform_name="Windows", platform_version=platform.version(),
                        architecture=platform.machine(), agent_version="1.0.0", protocol_version="1.0")
                assert replay.value.status_code == 401
            finally:
                enrollment_client.close()

            credentials = InMemoryAgentCredentialStore(AgentCredential(CredentialId(grant.credential_id),
                                                                        grant.credential_secret))
            transport = HttpAgentTransport(config, credentials, endpoint_id=grant.endpoint_id)
            registry = ScannerRegistry(windows_read_only_scanners())
            capability_provider = LocalTargetCapabilityProvider()
            agent = RavenXAgent(
                config=AgentConfig(hostname=socket.gethostname(), platform="Windows",
                                   platform_version=platform.version(), architecture=platform.machine()),
                identity_store=InMemoryAgentIdentityStore(grant.endpoint_id), credential_store=credentials,
                capability_provider=capability_provider, scanner_registry=registry,
                assessment_orchestrator=LocalAssessmentOrchestrator(registry, capability_provider.capabilities_for),
                sender=transport,
            )
            try:
                assert agent.start().value == "ready"
                agent.emit_startup_messages()
                with pytest.raises(HttpTransportError) as pending:
                    transport.poll_work()
                assert pending.value.status_code == 403

                heartbeat = agent.heartbeat()
                transport.send(heartbeat)
                with pytest.raises(HttpTransportError) as repeated_heartbeat:
                    transport.send(heartbeat)
                assert repeated_heartbeat.value.status_code == 409
                forged = heartbeat.to_dict()
                forged["endpoint_id"] = str(EndpointId.new())
                forged["payload"] = {**forged["payload"], "endpoint_id": forged["endpoint_id"]}
                impersonation = human.post(base_url + "/api/v1/agent/messages", json=forged,
                    headers={"Authorization": f"Bearer {grant.credential_secret}"})
                assert impersonation.status_code == 401
                wrong_secret = human.post(base_url + "/api/v1/agent/messages", json=heartbeat.to_dict(),
                    headers={"Authorization": "Bearer invalid-credential"})
                assert wrong_secret.status_code == 401

                endpoint_url = tenant_base + f"/endpoints/{grant.endpoint_id}"
                approved = human.post(endpoint_url + "/approve", headers=human_headers)
                assert approved.status_code == 200 and approved.json()["status"] == "active"

                # Place the enrolled credential inside the server renewal window, then
                # propose an agent-prepared successor over verified loopback HTTPS.
                with db.get_db() as session:
                    row = session.get(EndpointCredentialRecord, grant.credential_id)
                    row.expires_at = (datetime.now(timezone.utc) + timedelta(days=5)).replace(tzinfo=None)
                successor_id = str(CredentialId.new())
                successor_secret = secrets.token_urlsafe(32)
                receipt = transport.renew_credential(
                    credential=AgentCredential(CredentialId(grant.credential_id), grant.credential_secret),
                    successor_credential_id=successor_id,
                    successor_credential_secret=successor_secret,
                    protocol_version="1.0",
                )
                assert receipt.endpoint_id == grant.endpoint_id
                assert receipt.organization_id == str(organization.organization_id)
                assert receipt.credential_id == successor_id
                assert receipt.replaces_credential_id == grant.credential_id
                credentials.store(AgentCredential(CredentialId(successor_id), successor_secret))
                transport.confirm_renewal(
                    credential=AgentCredential(CredentialId(successor_id), successor_secret),
                    replaces_credential_id=grant.credential_id,
                    protocol_version="1.0",
                )
                old_cred_attempt = human.post(
                    base_url + "/api/v1/agent/work",
                    headers={
                        "Authorization": f"Bearer {grant.credential_secret}",
                        "X-Raven-Endpoint-Id": str(grant.endpoint_id),
                    },
                )
                assert old_cred_attempt.status_code == 401

                requested = human.post(tenant_base + "/assessments", headers=human_headers,
                    json={"endpoint_id": str(grant.endpoint_id),
                          "scanner_ids": ["windows.uac", "windows.bitlocker"]})
                assert requested.status_code == 200
                assessment_id = requested.json()["assessment_id"]
                leased = transport.poll_work()
                assert leased is not None and leased.envelope.payload["assessment_id"] == assessment_id
                result = agent.receive_leased_work(leased)
                assert result.assessment_id == assessment_id
                reported = human.get(tenant_base + f"/assessments/{assessment_id}", headers=human_headers)
                assert reported.status_code == 200
                report = reported.json()
                assert report["state"] == "completed"
                scanner_results = {item["scanner_id"]: item for item in report["result"]["scanner_results"]}
                assert set(scanner_results) == {"windows.uac", "windows.bitlocker"}
                assert scanner_results["windows.uac"]["status"] in {"success", "failed"}
                bitlocker = scanner_results["windows.bitlocker"]
                assert bitlocker["status"] in {"success", "failed", "incompatible"}
                if bitlocker["status"] == "failed":
                    assert bitlocker["error_category"] == "READ_FAILED"
                    assert bitlocker["findings"] == []
                    assert bitlocker["execution_evidence"]["completeness"] == "unknown"
                context = context_resolver.resolve(SecurityPrincipal.human(owner.user_id), organization.organization_id)
                fleet_report = report_service.build(SecurityPrincipal.human(owner.user_id), context,
                                                    endpoint_id=grant.endpoint_id, assessment_ids=(assessment_id,))
                expected_status = ("scanned" if all(item["status"] == "success" for item in scanner_results.values())
                                   else "partial")
                assert fleet_report["endpoints"][0]["scan_status"] == expected_status
                assert fleet_report["endpoints"][0]["partial_evidence"] == (expected_status == "partial")

                revoked = human.post(endpoint_url + "/revoke", headers=human_headers)
                assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
                with pytest.raises(HttpTransportError) as denied:
                    transport.poll_work()
                assert denied.value.status_code == 401
            finally:
                agent.stop()
                transport.close()
    db.close()


def test_partial_uac_finding_survives_authenticated_https_persistence_and_detail_api(tmp_path):
    """Synthetic registry observations; real orchestration, TLS, auth and SQLite."""
    ca_path, cert_path, key_path = _certificates(tmp_path)
    trust = ssl.create_default_context(cafile=str(ca_path))
    trust.verify_flags |= ssl.VERIFY_X509_STRICT
    app, db, organization, owner, resolver, report_service = _isolated_app(tmp_path, with_foreign_scope=True)
    canary = "PHASE1AB_SECRET_CANARY"
    try:
        with _https_server(app, cert_path, key_path) as base_url:
            config = HttpTransportConfig(base_url, verify=trust, timeout_seconds=30)
            with httpx.Client(verify=trust, trust_env=False, timeout=30) as human:
                login = human.post(base_url + "/api/v1/auth/login", json={
                    "email": "golden-owner@example.com", "password": "GOLDEN_PASSWORD_SENTINEL"})
                assert login.status_code == 200
                headers = {"Authorization": "Bearer " + login.json()["session_token"]}
                tenant = f"{base_url}/api/v1/organizations/{organization.organization_id}"
                issued = human.post(tenant + "/enrollment-tokens", headers=headers,
                                    json={"ttl_minutes": 10, "label": "synthetic partial collector"})
                assert issued.status_code == 201
                token = issued.json()
                enrollment = HttpAgentEnrollmentClient(config)
                try:
                    grant = enrollment.enroll(enrollment_id=token["enrollment_id"],
                        bootstrap_token=token["enrollment_token"], hostname="SYNTHETIC-PARTIAL-UAC",
                        platform_name="Windows", platform_version="synthetic", architecture="AMD64",
                        agent_version="1.0.0", protocol_version="1.0", request_id=str(uuid4()), nonce=str(uuid4()))
                finally:
                    enrollment.close()
                assert grant.status == "new"
                assert human.post(tenant + f"/endpoints/{grant.endpoint_id}/approve", headers=headers).status_code == 200

                def registry_read(name):
                    if name == "PromptOnSecureDesktop":
                        raise PermissionError(canary)
                    return {"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 2}[name]

                manifest = next(x.manifest for x in windows_read_only_scanners() if x.manifest.scanner_id == "windows.uac")
                scanner = WindowsReadOnlyScanner(manifest, registry_reader=registry_read)
                registry = ScannerRegistry((scanner,))
                capabilities = StaticTargetCapabilityProvider(TargetCapabilities(frozenset({ScannerCapability("windows.registry.read")})))
                credentials = InMemoryAgentCredentialStore(AgentCredential(CredentialId(grant.credential_id), grant.credential_secret))

                class RecordingTransport(HttpAgentTransport):
                    def __init__(self):
                        super().__init__(config, credentials, endpoint_id=grant.endpoint_id)
                        self.results = []

                    def send(self, envelope):
                        if envelope.message_type is AgentMessageType.ASSESSMENT_RESULT:
                            self.results.append(envelope)
                        return super().send(envelope)

                transport = RecordingTransport()
                agent = RavenXAgent(config=AgentConfig(hostname="SYNTHETIC-PARTIAL-UAC", platform="Windows"),
                    identity_store=InMemoryAgentIdentityStore(grant.endpoint_id), credential_store=credentials,
                    capability_provider=capabilities, scanner_registry=registry,
                    assessment_orchestrator=LocalAssessmentOrchestrator(registry, capabilities.capabilities_for), sender=transport)
                try:
                    assert agent.start().value == "ready"
                    agent.emit_startup_messages()
                    requested = human.post(tenant + "/assessments", headers=headers,
                        json={"endpoint_id": str(grant.endpoint_id), "scanner_ids": ["windows.uac"]})
                    assert requested.status_code == 200
                    assessment_id = requested.json()["assessment_id"]
                    work = transport.poll_work()
                    assert work is not None
                    result = agent.receive_leased_work(work)
                    assert len(result.findings) == 1
                    assert len(transport.results) == 1
                    envelope = AgentMessageEnvelope.from_dict(json.loads(json.dumps(transport.results[0].to_dict())))
                    decoded = decode_payload(envelope.message_type, envelope.payload)
                    assert decoded.findings[0]["title"] == "UAC Disabled"
                    assert decoded.findings[0]["severity"] == "high"
                    assert decoded.scanner_results[0]["status"] == "failed"
                    assert decoded.scanner_results[0]["execution_evidence"]["completeness"] == "partial"
                    assert decoded.scanner_results[0]["execution_evidence"]["rules_completed"] == []
                    assert canary not in json.dumps(envelope.to_dict())

                    # A credential is still mandatory even when the payload contains a finding.
                    denied = human.post(base_url + "/api/v1/agent/messages", json=envelope.to_dict(),
                                        headers={"Authorization": "Bearer invalid-fixture-credential"})
                    assert denied.status_code == 401
                    with pytest.raises(HttpTransportError) as replay:
                        transport.send(envelope)
                    assert replay.value.status_code == 409

                    details_url = tenant + f"/assessments/{assessment_id}/details"
                    response = human.get(details_url, headers=headers)
                    assert response.status_code == 200
                    data = response.json()
                    assert data["total_findings"] == 1
                    finding = data["findings"][0]
                    assert finding["title"] == "UAC Disabled" and finding["severity"] == "high"
                    assert data["scanner_results"] == [{"scanner_id": "windows.uac", "status": "failed",
                                                       "finding_count": 1, "error": "READ_FAILED"}]
                    finding_url = tenant + f"/assessments/{assessment_id}/findings/{finding['occurrence_id']}"
                    assert human.get(finding_url, headers=headers).json()["occurrence_id"] == finding["occurrence_id"]
                    assert human.get(details_url).status_code == 401
                    foreign = f"{base_url}/api/v1/organizations/{app.state.foreign_organization_id}"
                    assert human.get(foreign + f"/assessments/{assessment_id}/details", headers=headers).status_code == 404
                    assert human.get(foreign + f"/assessments/{assessment_id}/findings/{finding['occurrence_id']}", headers=headers).status_code == 404
                    assert canary not in response.text

                    # Read the actual persisted result through a new database manager.
                    reopened = DatabaseManager(str(db.config_path))
                    reopened.initialize_sync_engine()
                    try:
                        stored = SQLAlchemyRemoteAssessmentRepository(reopened).get(assessment_id)
                        assert len(stored.result.findings) == 1
                        assert stored.result.findings[0]["occurrence_id"] == finding["occurrence_id"]
                        assert stored.result.scanner_results[0]["status"] == "failed"
                    finally:
                        reopened.close()
                    context = resolver.resolve(SecurityPrincipal.human(owner.user_id), organization.organization_id)
                    fleet = report_service.build(SecurityPrincipal.human(owner.user_id), context,
                        endpoint_id=grant.endpoint_id, assessment_ids=(assessment_id,))
                    assert fleet["endpoints"][0]["scan_status"] == "partial"
                    assert fleet["endpoints"][0]["partial_evidence"] is True
                finally:
                    agent.stop()
                    transport.close()
    finally:
        db.close()
