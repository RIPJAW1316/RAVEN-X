"""Security observability through the real HTTP boundary, auth stack and RBAC."""
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.application.audit import TenantAuditQueryService
from backend.application.endpoint import TenantEndpointService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.observability import TenantSecurityObservabilityService
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService, TenantOrganizationAdministrationService)
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.security import SecurityPrincipal
from backend.domain.security_signals import SignalThresholds
from backend.infrastructure.operational import MetricsCollector, SecurityTelemetry
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

PASSWORD = "OBSERVER_PASSWORD_SENTINEL"
OBSERVER = ["audit.read", "organization.read", "endpoint.read"]
BLIND = ["organization.read", "endpoint.read"]


class World:
    def __init__(self, permissions=OBSERVER, thresholds=None):
        self.users = InMemoryUserRepository()
        identity = HumanIdentityService(self.users)
        self.user = identity.create_initial_user("observer@example.com", "Observer", PASSWORD)
        self.outsider = identity.create_user("outsider@example.com", "Outsider", PASSWORD,
                                             principal=SecurityPrincipal.system())

        self.orgs = InMemoryOrganizationRepository()
        self.org_a = OrganizationService(self.orgs).create("A")
        self.org_b = OrganizationService(self.orgs).create("B")
        self.memberships = InMemoryOrganizationMembershipRepository()
        member_service = OrganizationMembershipService(self.memberships, self.orgs, self.users)
        membership = member_service.create(self.user.user_id, self.org_a.organization_id)
        outsider_membership = member_service.create(self.outsider.user_id, self.org_b.organization_id)

        roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
        role_service, binding_service = RoleService(roles), RoleBindingService(bindings, roles, self.memberships)
        role = role_service.create(self.org_a.organization_id, "Observer", permissions)
        binding_service.create(self.org_a.organization_id, membership.membership_id, role.role_id)
        b_role = role_service.create(self.org_b.organization_id, "B", ["organization.read", "audit.read"])
        binding_service.create(self.org_b.organization_id, outsider_membership.membership_id, b_role.role_id)

        endpoints = InMemoryEndpointRepository()
        endpoints.add(Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"),
                               created_at=datetime.now(timezone.utc),
                               organization_id=self.org_a.organization_id))

        self.metrics = MetricsCollector()
        self.telemetry = SecurityTelemetry(metrics=self.metrics)
        self.audit = InMemorySecurityAuditRepository()
        self.authorizer = OrganizationRbacAuthorizer(
            membership_repository=self.memberships, role_binding_repository=bindings,
            role_repository=roles, organization_repository=self.orgs,
            endpoint_repository=endpoints, audit_sink=self.audit, telemetry=self.telemetry)

        self.app = FastAPI()
        self.app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
            HumanAuthenticationService(self.users, audit_sink=self.audit, telemetry=self.telemetry),
            HumanSessionAuthenticator(self.users), self.users,
            OrganizationContextResolver(self.users, self.memberships, self.orgs, audit_sink=self.audit),
            TenantEndpointService(endpoints, self.authorizer, audit_sink=self.audit), None,
            self.orgs, self.memberships,
            TenantOrganizationAdministrationService(OrganizationService(self.orgs), member_service,
                                                    self.orgs, self.memberships, self.authorizer),
            audit_query_service=TenantAuditQueryService(self.audit, self.authorizer),
            security_observability_service=TenantSecurityObservabilityService(
                self.telemetry, self.authorizer, thresholds=thresholds, metrics=self.metrics),
        )), prefix="/api/v1")
        self.client = TestClient(self.app)

    def token(self, email="observer@example.com"):
        response = self.client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 200
        return {"Authorization": f"Bearer {response.json()['session_token']}"}

    def metrics_for(self, org=None, headers=None, query=""):
        org = org or self.org_a.organization_id
        return self.client.get(f"/api/v1/organizations/{org}/security/metrics{query}",
                               headers=headers or self.token())


# ------------------------------------------------------------------- shape

def test_snapshot_reports_authorization_authentication_and_signals():
    world = World()
    headers = world.token()
    for _ in range(6):
        world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/endpoints", headers=headers)

    body = world.metrics_for(headers=headers).json()
    assert set(body) >= {"organization_id", "generated_at", "window_minutes",
                         "authorization", "authentication", "operations", "signals"}
    assert body["authorization"]["attempts"] >= 6
    assert body["authorization"]["allowed"] >= 6
    assert body["authorization"]["denied"] == 0
    assert body["authorization"]["denial_rate"] == 0
    assert body["signals"] == []


def test_successful_reads_produce_telemetry_but_no_audit_rows():
    """The whole point: volume goes to metrics, not the audit trail."""
    world = World()
    headers = world.token()
    before = len(world.audit.list())
    for _ in range(15):
        world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/endpoints", headers=headers)

    body = world.metrics_for(headers=headers).json()
    assert body["authorization"]["allowed"] >= 15
    assert len(world.audit.list()) == before


def test_denials_appear_in_both_telemetry_and_the_audit_trail():
    world = World(permissions=BLIND)   # no audit.read
    headers = world.token()
    for _ in range(3):
        world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/security/metrics",
                         headers=headers)
    denied = [e for e in world.audit.list() if e.event_type == "authorization.denied"]
    assert len(denied) == 3
    counts = world.telemetry.authorization_counts(world.org_a.organization_id, window_minutes=15)
    assert counts.denied >= 3


# ----------------------------------------------------------- authorization

def test_unauthenticated_request_is_rejected():
    world = World()
    assert world.client.get(
        f"/api/v1/organizations/{world.org_a.organization_id}/security/metrics").status_code == 401


def test_member_without_audit_read_is_forbidden():
    world = World(permissions=BLIND)
    assert world.metrics_for().status_code == 403


def test_service_absence_reports_unavailable():
    world = World()
    app = FastAPI()
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        HumanAuthenticationService(world.users), HumanSessionAuthenticator(world.users), world.users,
        OrganizationContextResolver(world.users, world.memberships, world.orgs),
        None, None, world.orgs, world.memberships, None,
        security_observability_service=None)), prefix="/api/v1")
    client = TestClient(app)
    token = client.post("/api/v1/auth/login",
                        json={"email": "observer@example.com", "password": PASSWORD}).json()["session_token"]
    response = client.get(f"/api/v1/organizations/{world.org_a.organization_id}/security/metrics",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 503


# --------------------------------------------------------- tenant isolation

def test_one_tenant_telemetry_is_not_visible_to_another():
    world = World()
    observer = world.token()
    for _ in range(12):
        world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/endpoints", headers=observer)

    outsider = world.token("outsider@example.com")
    body = world.client.get(
        f"/api/v1/organizations/{world.org_b.organization_id}/security/metrics",
        headers=outsider).json()
    # Org B has only its own traffic; org A's 12 allowed reads must not appear.
    assert body["authorization"]["allowed"] < 12
    assert body["organization_id"] == str(world.org_b.organization_id)


def test_cross_tenant_request_is_denied_and_does_not_read_the_target():
    world = World()
    response = world.metrics_for(org=world.org_b.organization_id)
    assert response.status_code == 403


def test_probing_a_tenant_does_not_attribute_telemetry_to_it():
    """An outsider's denied traffic must not inflate the victim's numbers."""
    world = World()
    outsider = world.token("outsider@example.com")
    for _ in range(10):
        world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/endpoints",
                         headers=outsider)

    body = world.metrics_for().json()
    assert body["authorization"]["denied"] == 0, "outsider traffic leaked into the victim tenant"


# ------------------------------------------------------------- query bounds

def test_window_minutes_is_validated():
    world = World()
    headers = world.token()
    for query in ("?window_minutes=0", "?window_minutes=-5", "?window_minutes=61",
                  "?window_minutes=abc"):
        assert world.metrics_for(headers=headers, query=query).status_code == 422, query
    assert world.metrics_for(headers=headers, query="?window_minutes=60").status_code == 200


def test_default_window_is_applied():
    world = World()
    assert world.metrics_for().json()["window_minutes"] == 15


# ------------------------------------------------------------------ signals

def test_normal_traffic_produces_no_signals():
    world = World()
    headers = world.token()
    for _ in range(30):
        world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/endpoints", headers=headers)
    assert world.metrics_for(headers=headers).json()["signals"] == []


def test_a_denial_spike_produces_a_signal():
    """Deliberate abuse must surface as an explainable signal."""
    world = World(permissions=OBSERVER,
                  thresholds=SignalThresholds(denial_floor=10, denial_rate=0.5))
    headers = world.token()
    # Drive real denied evaluations through the authorizer rather than poking
    # the counters, so the signal is produced by genuine traffic.
    from backend.application.organization.context import OrganizationContext
    from backend.domain.security import (AuthorizationAction, AuthorizationRequest,
                                         AuthorizationResource)
    membership = world.memberships.list_for_user(world.user.user_id)[0]
    context = OrganizationContext(world.org_a.organization_id,
                                  str(membership.membership_id), world.user.user_id)
    principal = SecurityPrincipal.human(world.user.user_id)
    for _ in range(25):
        decision = world.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.ENDPOINT_REVOKE,
            AuthorizationResource("endpoint", None, {}), organization_context=context))
        assert not decision.allowed

    body = world.metrics_for(headers=headers).json()
    kinds = [s["signal_type"] for s in body["signals"]]
    assert "authorization.denial_spike" in kinds, body["authorization"]
    spike = next(s for s in body["signals"] if s["signal_type"] == "authorization.denial_spike")
    assert spike["evidence"]["denied"] >= 25
    assert spike["reason"]
    assert spike["severity"] in {"warning", "critical"}


def test_signals_carry_explainable_evidence():
    world = World(thresholds=SignalThresholds(boundary_denial_floor=3))
    headers = world.token()
    for _ in range(5):
        world.telemetry.record_authorization(
            organization_id=world.org_a.organization_id, allowed=False,
            action="endpoint.read", reason_code="resource_organization_mismatch")
    body = world.metrics_for(headers=headers).json()
    probing = next(s for s in body["signals"]
                   if s["signal_type"] == "authorization.cross_tenant_probing")
    assert probing["severity"] == "critical"
    assert probing["evidence"]["boundary_denials"] == 5
    assert "detected_at" in probing and probing["window_minutes"] == 15


def test_response_contains_no_user_identifiers_or_secrets():
    world = World()
    headers = world.token()
    world.client.get(f"/api/v1/organizations/{world.org_a.organization_id}/endpoints", headers=headers)
    text = world.metrics_for(headers=headers).text
    assert "observer@example.com" not in text
    assert PASSWORD not in text
    assert str(world.user.user_id) not in text
