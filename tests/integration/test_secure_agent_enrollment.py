from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.application.endpoint import TenantEndpointService
from backend.application.agent.processor import CredentialEndpointAuthenticator, MessageAcceptanceError
from backend.application.enrollment import EnrollmentAlreadyUsedError, EnrollmentService, TenantEnrollmentService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import OrganizationContextResolver, OrganizationMembershipService, OrganizationService
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.core.database.database import DatabaseManager
from backend.core.database.models import EndpointCredentialRecord, EndpointRecord, EnrollmentRecord
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.organization import Organization, OrganizationId
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository
from backend.infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository
from backend.infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository
from backend.infrastructure.transport.http.server import create_agent_http_app
from backend.domain.enrollment import EnrollmentRequest
from backend.application.ports.agent_transport import PresentedCredential
from backend.protocol.agent import AgentMessageType
from backend.infrastructure.operational.rate_limiter import InMemoryRateLimiter


def _database(tmp_path):
    path = tmp_path / "enrollment.db"
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def _agent_body():
    return {"hostname": "actual-win-agent", "platform": {"name": "Windows", "version": "11", "architecture": "x64"},
            "agent_version": "1.0.0", "protocol_version": "1.0", "request_id": "request-1", "nonce": "nonce-1"}


def test_http_bootstrap_is_single_use_tenant_bound_and_requires_approval(tmp_path):
    now = datetime.now(timezone.utc)
    manager = _database(tmp_path)
    repository = SQLAlchemyEnrollmentRepository(manager)
    service = EnrollmentService(repository)
    organization_id = OrganizationId.new()
    SQLAlchemyOrganizationRepository(manager).add(Organization(organization_id, "Bootstrap tenant"))
    authorization, token = service.create_enrollment_authorization(organization_id=organization_id, now=now)
    client = TestClient(create_agent_http_app(None, service))
    url = "/api/v1/agent/enroll"
    headers = {"Authorization": f"Bearer {token.value}", "X-Raven-Enrollment-Id": str(authorization.enrollment_id)}

    assert client.post(url, json=_agent_body(), headers={**headers, "Authorization": "Bearer wrong"}).status_code == 401
    assert repository.get_authorization(authorization.enrollment_id).status.value == "pending"
    assert client.post(url, json={**_agent_body(), "organization_id": str(OrganizationId.new())}, headers=headers).status_code == 401
    created = client.post(url, json=_agent_body(), headers=headers)
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    payload = created.json()
    assert payload["organization_id"] == str(organization_id)
    assert payload["status"] == "new"
    assert datetime.fromisoformat(payload["credential_expires_at"]) <= now + timedelta(days=31)
    assert token.value not in created.text

    replay = client.post(url, json=_agent_body(), headers=headers)
    assert replay.status_code == 401
    assert replay.json() == {"error": "enrollment_rejected"}
    with manager.get_db() as session:
        assert session.query(EndpointRecord).count() == 1
        assert session.query(EndpointCredentialRecord).count() == 1
        assert session.get(EnrollmentRecord, str(authorization.enrollment_id)).status == "consumed"

    work_headers = {"Authorization": f"Bearer {payload['credential_secret']}", "X-Raven-Endpoint-Id": payload["endpoint_id"]}
    assert client.post("/api/v1/agent/work", headers=work_headers).status_code == 403
    limited_agent = TestClient(create_agent_http_app(None, service,
        credential_rate_limiter=InMemoryRateLimiter(1, 60)))
    assert limited_agent.post("/api/v1/agent/work", headers=work_headers).status_code == 403
    assert limited_agent.post("/api/v1/agent/work", headers=work_headers).status_code == 429
    endpoints = SQLAlchemyEndpointRepository(manager)
    # The HTTP handler timestamps enrollment after the request starts. Anchor
    # lifecycle transitions to the stored creation time even on slow runners.
    enrolled_at = endpoints.get_for_organization(payload["endpoint_id"], organization_id).created_at
    endpoints.transition_status_for_organization(payload["endpoint_id"], organization_id,
                                                  (EndpointStatus.NEW,), EndpointStatus.ACTIVE, enrolled_at + timedelta(seconds=1))
    assert client.post("/api/v1/agent/work", headers=work_headers).status_code == 200
    endpoints.transition_status_for_organization(payload["endpoint_id"], organization_id,
                                                  (EndpointStatus.ACTIVE,), EndpointStatus.DEGRADED, enrolled_at + timedelta(seconds=2))
    assert client.post("/api/v1/agent/work", headers=work_headers).status_code == 403
    endpoints.transition_status_for_organization(payload["endpoint_id"], organization_id,
                                                  (EndpointStatus.DEGRADED,), EndpointStatus.OFFLINE, enrolled_at + timedelta(seconds=3))
    assert client.post("/api/v1/agent/work", headers=work_headers).status_code == 403
    endpoints.transition_status_for_organization(payload["endpoint_id"], organization_id,
                                                  (EndpointStatus.OFFLINE,), EndpointStatus.REVOKED, enrolled_at + timedelta(seconds=4))
    assert client.post("/api/v1/agent/work", headers=work_headers).status_code == 401
    manager.close()


def test_http_bootstrap_rejects_unowned_expired_revoked_large_and_throttled_requests(tmp_path):
    manager = _database(tmp_path)
    repository = SQLAlchemyEnrollmentRepository(manager)
    service = EnrollmentService(repository)
    now = datetime.now(timezone.utc)
    unowned, unowned_token = service.create_enrollment_authorization()
    expired, expired_token = service.create_enrollment_authorization(
        organization_id=OrganizationId.new(), now=now - timedelta(hours=2), ttl=timedelta(minutes=1))
    revoked, revoked_token = service.create_enrollment_authorization(organization_id=OrganizationId.new())
    service.revoke_authorization(revoked.enrollment_id)
    client = TestClient(create_agent_http_app(None, service, enrollment_rate_limiter=InMemoryRateLimiter(100, 60)))
    url = "/api/v1/agent/enroll"

    def post(item, token, body=None):
        return client.post(url, json=body or _agent_body(), headers={
            "Authorization": f"Bearer {token.value}", "X-Raven-Enrollment-Id": str(item.enrollment_id)})

    for item, token in ((unowned, unowned_token), (expired, expired_token), (revoked, revoked_token)):
        response = post(item, token)
        assert response.status_code == 401
        assert response.json() == {"error": "enrollment_rejected"}
        assert token.value not in response.text
    oversized = client.post(url, content=b"x" * 17000, headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {unowned_token.value}",
        "X-Raven-Enrollment-Id": str(unowned.enrollment_id)})
    assert oversized.status_code == 413
    throttled_client = TestClient(create_agent_http_app(None, service, enrollment_rate_limiter=InMemoryRateLimiter(1, 60)))
    headers = {"Authorization": "Bearer wrong", "X-Raven-Enrollment-Id": str(unowned.enrollment_id)}
    assert throttled_client.post(url, json=_agent_body(), headers=headers).status_code == 401
    limited = throttled_client.post(url, json=_agent_body(), headers=headers)
    assert limited.status_code == 429 and int(limited.headers["retry-after"]) > 0
    manager.close()


def test_human_enrollment_routes_scope_tokens_and_approval_to_verified_tenant():
    users = InMemoryUserRepository()
    identities = HumanIdentityService(users)
    owner = identities.create_initial_user("owner@example.com", "Owner", "OWNER_PASSWORD_SENTINEL")
    viewer = identities.create_user("viewer@example.com", "Viewer", "VIEWER_PASSWORD_SENTINEL", principal=SecurityPrincipal.system())
    organizations = InMemoryOrganizationRepository()
    organization = OrganizationService(organizations).create("Owner tenant")
    other = OrganizationService(organizations).create("Other tenant")
    memberships = InMemoryOrganizationMembershipRepository()
    owner_membership = OrganizationMembershipService(memberships, organizations, users).create(owner.user_id, organization.organization_id)
    OrganizationMembershipService(memberships, organizations, users).create(viewer.user_id, organization.organization_id)
    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(organization.organization_id, "Enrollment administrator",
                                     ["enrollment.create", "enrollment.revoke", "endpoint.read", "endpoint.update", "endpoint.revoke"])
    RoleBindingService(bindings, roles, memberships).create(organization.organization_id, owner_membership.membership_id, role.role_id)
    endpoints = InMemoryEndpointRepository()
    endpoint = Endpoint(EndpointId.new(), "waiting-win-agent", PlatformInfo("Windows"), organization_id=organization.organization_id)
    endpoints.add(endpoint)
    audit = InMemorySecurityAuditRepository()
    authorizer = OrganizationRbacAuthorizer(membership_repository=memberships, role_binding_repository=bindings,
                                           role_repository=roles, organization_repository=organizations,
                                           endpoint_repository=endpoints, audit_sink=audit)
    repository = InMemoryEnrollmentRepository()
    enrollment = TenantEnrollmentService(repository, authorizer, audit_sink=audit)
    other_auth, _ = EnrollmentService(repository).create_enrollment_authorization(organization_id=other.organization_id)
    authentication = HumanAuthenticationService(users)
    app = FastAPI()
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        authentication, HumanSessionAuthenticator(users), users,
        OrganizationContextResolver(users, memberships, organizations, audit_sink=audit),
        TenantEndpointService(endpoints, authorizer, audit_sink=audit), None,
        enrollment_service=enrollment,
    )), prefix="/api/v1")
    client = TestClient(app)
    owner_token = client.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": "OWNER_PASSWORD_SENTINEL"}).json()["session_token"]
    viewer_token = client.post("/api/v1/auth/login", json={"email": "viewer@example.com", "password": "VIEWER_PASSWORD_SENTINEL"}).json()["session_token"]
    headers = {"Authorization": f"Bearer {owner_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    base = f"/api/v1/organizations/{organization.organization_id}"
    tokens = base + "/enrollment-tokens"

    assert client.post(tokens, json={"ttl_minutes": 60}, headers=viewer_headers).status_code == 403
    assert client.post(tokens, json={"max_uses": 2}, headers=headers).status_code == 422
    assert client.post(tokens, json={"max_uses": 1.0}, headers=headers).status_code == 422
    assert client.post(tokens, json={"organization_id": str(other.organization_id)}, headers=headers).status_code == 422
    created = client.post(tokens, json={"ttl_minutes": 30, "label": "Desk A"}, headers=headers)
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    issued = created.json()
    assert issued["organization_id"] == str(organization.organization_id)
    assert issued["label"] == "Desk A"
    assert issued["status"] == "pending"
    expired_auth, saved_secret = EnrollmentService(repository).create_enrollment_authorization(
        organization_id=organization.organization_id,
        now=datetime.now(timezone.utc) - timedelta(minutes=2),
        ttl=timedelta(minutes=1),
    )
    assert repository.get_authorization(expired_auth.enrollment_id).status.value == "pending"
    listed = client.get(tokens, headers=headers)
    assert listed.status_code == 200
    assert [(item["enrollment_id"], item["status"]) for item in listed.json()] == [
        (issued["enrollment_id"], "pending"), (str(expired_auth.enrollment_id), "expired")]
    assert repository.get_authorization(expired_auth.enrollment_id).status.value == "pending"
    assert "enrollment_token" not in listed.text and "token_verifier" not in listed.text
    assert issued["enrollment_token"] not in listed.text
    assert client.delete(f"{tokens}/{other_auth.enrollment_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/organizations/{other.organization_id}/enrollment-tokens", headers=headers).status_code == 403
    assert client.post(f"{base}/endpoints/{endpoint.endpoint_id}/approve", headers=viewer_headers).status_code == 403
    assert client.post(f"{base}/endpoints/{endpoint.endpoint_id}/approve", headers=headers).json()["status"] == "active"
    assert client.post(f"{base}/endpoints/{endpoint.endpoint_id}/approve", headers=headers).status_code == 409
    assert client.post(f"{base}/endpoints/{endpoint.endpoint_id}/revoke", headers=headers).json()["status"] == "revoked"
    assert client.delete(f"{tokens}/{issued['enrollment_id']}", headers=headers).json()["status"] == "revoked"
    assert client.delete(f"{tokens}/{issued['enrollment_id']}", headers=headers).json()["status"] == "revoked"
    assert len(audit.list(event_type="enrollment.revoked")) == 1
    created_events = audit.list(event_type="enrollment.created")
    assert len(created_events) == 1
    assert created_events[0].user_id == str(owner.user_id)
    assert created_events[0].organization_id == str(organization.organization_id)
    assert created_events[0].membership_id == str(owner_membership.membership_id)

    assert listed.json()[1]["renewable"] is True
    assert listed.json()[0]["renewable"] is False
    renewal = f"{tokens}/{expired_auth.enrollment_id}/renew"
    assert client.post(renewal, headers=viewer_headers).status_code == 403
    assert client.post(renewal).status_code == 401
    assert client.post(f"{tokens}/{other_auth.enrollment_id}/renew", headers=headers).status_code == 404
    assert client.post(f"{tokens}/{issued['enrollment_id']}/renew", headers=headers).status_code == 409
    renewed = client.post(renewal, headers=headers)
    assert renewed.status_code == 200
    assert renewed.headers["cache-control"] == "no-store"
    assert renewed.json()["enrollment_id"] == str(expired_auth.enrollment_id)
    assert renewed.json()["status"] == "pending"
    assert renewed.json()["renewable"] is False
    assert saved_secret.value not in renewed.text
    assert "token_verifier" not in renewed.json()
    assert "enrollment_token" not in renewed.json()
    assert client.post(renewal, headers=headers).status_code == 409
    event, = audit.list(event_type="enrollment.renewed")
    assert event.user_id == str(owner.user_id)
    assert event.metadata["expires_at"] == renewed.json()["expires_at"]
    endpoint, _, _ = EnrollmentService(repository).accept_enrollment(
        expired_auth.enrollment_id, saved_secret.value, EnrollmentRequest("renewed-win-agent", PlatformInfo("Windows")),
    )
    assert endpoint.organization_id == organization.organization_id
    assert client.post(renewal, headers=headers).status_code == 409
    stale, _ = EnrollmentService(repository).create_enrollment_authorization(
        organization_id=organization.organization_id,
        now=datetime.now(timezone.utc) - timedelta(days=3),
        ttl=timedelta(minutes=1),
    )
    assert client.post(f"{tokens}/{stale.enrollment_id}/renew", headers=headers).status_code == 409
    assert client.delete(f"{tokens}/{stale.enrollment_id}", headers=headers).json()["status"] == "revoked"
    assert client.post(f"{tokens}/{stale.enrollment_id}/renew", headers=headers).status_code == 409


def test_concurrent_sql_redemption_issues_exactly_one_endpoint(tmp_path):
    manager = _database(tmp_path)
    barrier = Barrier(2)

    class RacingRepository(SQLAlchemyEnrollmentRepository):
        def complete_enrollment(self, *args):
            barrier.wait(timeout=10)
            return super().complete_enrollment(*args)

    repository = RacingRepository(manager)
    service = EnrollmentService(repository)
    authorization, token = service.create_enrollment_authorization(organization_id=OrganizationId.new())

    def redeem(_):
        try:
            return service.accept_enrollment(authorization.enrollment_id, token.value,
                                             EnrollmentRequest("race-host", PlatformInfo("Windows")))
        except Exception as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(redeem, range(2)))
    successes = [item for item in outcomes if isinstance(item, tuple)]
    assert len(successes) == 1, outcomes
    assert sum(isinstance(item, EnrollmentAlreadyUsedError) for item in outcomes) == 1, outcomes
    with manager.get_db() as session:
        assert session.query(EndpointRecord).count() == 1
        assert session.query(EndpointCredentialRecord).count() == 1
        assert session.get(EnrollmentRecord, str(authorization.enrollment_id)).status == "consumed"
    manager.close()


def test_pending_agent_can_identify_but_cannot_acknowledge_work():
    repository = InMemoryEnrollmentRepository()
    service = EnrollmentService(repository)
    organization = Organization(OrganizationId.new(), "Pending tenant")
    repository.register_organization(organization)
    authorization, token = service.create_enrollment_authorization(organization_id=organization.organization_id)
    endpoint, credential, raw = service.accept_enrollment(
        authorization.enrollment_id, token.value, EnrollmentRequest("pending-agent", PlatformInfo("Windows")))
    authenticator = CredentialEndpointAuthenticator(service)
    presented = PresentedCredential(raw.value)
    now = datetime.now(timezone.utc)
    heartbeat = SimpleNamespace(endpoint_id=endpoint.endpoint_id, message_type=AgentMessageType.HEARTBEAT)
    acknowledgment = SimpleNamespace(endpoint_id=endpoint.endpoint_id, message_type=AgentMessageType.ASSESSMENT_ACK)
    assert authenticator.authenticate(heartbeat, presented, now).credential_id == credential.credential_id
    with pytest.raises(MessageAcceptanceError, match="approved"):
        authenticator.authenticate(acknowledgment, presented, now)
    repository.endpoints[str(endpoint.endpoint_id)] = endpoint.transition_to(EndpointStatus.ACTIVE, now)
    assert authenticator.authenticate(acknowledgment, presented, now).credential_id == credential.credential_id
    degraded = repository.endpoints[str(endpoint.endpoint_id)].transition_to(EndpointStatus.DEGRADED, now)
    repository.endpoints[str(endpoint.endpoint_id)] = degraded
    with pytest.raises(MessageAcceptanceError, match="approved"):
        authenticator.authenticate(acknowledgment, presented, now)
    assert authenticator.authenticate(heartbeat, presented, now).credential_id == credential.credential_id
