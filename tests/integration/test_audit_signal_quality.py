"""End-to-end evidence that the audit trail carries signal rather than noise.

Drives the real HTTP boundary with the real authenticator, RBAC authorizer and
audit sink, then asserts on what actually landed in the trail.
"""
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.application.audit import TenantAuditQueryService
from backend.application.endpoint import TenantEndpointService
from backend.application.fleet.groups import TenantEndpointGroupService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService, TenantOrganizationAdministrationService)
from backend.application.rbac import AuthorizationAuditPolicy, OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_group_scope_repository import InMemoryEndpointGroupRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

PASSWORD = "OPERATOR_PASSWORD_SENTINEL"

FULL_PERMISSIONS = [
    "audit.read", "organization.read", "endpoint.read",
    "endpoint_group.create", "endpoint_group.read", "endpoint_group.update",
    "endpoint_group.membership_update", "endpoint_group.revoke",
]


def build(policy=None, permissions=FULL_PERMISSIONS):
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    user = identity.create_initial_user("operator@example.com", "Operator", PASSWORD)

    organizations = InMemoryOrganizationRepository()
    org = OrganizationService(organizations).create("Tenant")
    memberships = InMemoryOrganizationMembershipRepository()
    membership_service = OrganizationMembershipService(memberships, organizations, users)
    membership = membership_service.create(user.user_id, org.organization_id)

    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(org.organization_id, "Operator", permissions)
    RoleBindingService(bindings, roles, memberships).create(
        org.organization_id, membership.membership_id, role.role_id)

    endpoints = InMemoryEndpointRepository()
    endpoints.add(Endpoint(EndpointId.new(), "host-1", PlatformInfo("Windows"),
                           created_at=datetime.now(timezone.utc), organization_id=org.organization_id))

    audit = InMemorySecurityAuditRepository()
    authorizer = OrganizationRbacAuthorizer(
        membership_repository=memberships, role_binding_repository=bindings, role_repository=roles,
        organization_repository=organizations, endpoint_repository=endpoints,
        audit_sink=audit, audit_policy=policy)

    groups = TenantEndpointGroupService(InMemoryEndpointGroupRepository(), endpoints, authorizer,
                                        audit_sink=audit)

    app = FastAPI()
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        HumanAuthenticationService(users), HumanSessionAuthenticator(users), users,
        OrganizationContextResolver(users, memberships, organizations),
        TenantEndpointService(endpoints, authorizer, audit_sink=audit), None,
        organizations, memberships,
        TenantOrganizationAdministrationService(OrganizationService(organizations),
                                                membership_service, organizations, memberships, authorizer),
        endpoint_group_service=groups,
        audit_query_service=TenantAuditQueryService(audit, authorizer),
    )), prefix="/api/v1")
    return app, org, audit


def login(client):
    response = client.post("/api/v1/auth/login",
                           json={"email": "operator@example.com", "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['session_token']}"}


def types_of(audit):
    return [event.event_type for event in audit.list()]


def test_read_only_navigation_writes_no_audit_records():
    """Browsing the console is not an audit event."""
    app, org, audit = build()
    client = TestClient(app)
    headers = login(client)
    before = len(audit.list())

    for _ in range(10):
        assert client.get(f"/api/v1/organizations/{org.organization_id}/endpoints",
                          headers=headers).status_code == 200
        assert client.get(f"/api/v1/organizations/{org.organization_id}", headers=headers).status_code == 200
        assert client.get(f"/api/v1/organizations/{org.organization_id}/audit-events",
                          headers=headers).status_code == 200

    assert len(audit.list()) == before, (
        "read-only navigation added audit rows: " + str(types_of(audit)[before:]))


def test_a_real_operation_produces_exactly_one_meaningful_event():
    app, org, audit = build()
    client = TestClient(app)
    headers = login(client)
    before = len(audit.list())

    response = client.post(f"/api/v1/organizations/{org.organization_id}/endpoint-groups",
                           headers=headers, json={"name": "Production", "description": "prod"})
    assert response.status_code == 200

    added = types_of(audit)[before:]
    assert "authorization.allowed" not in added
    assert any(item.startswith("endpoint_group") for item in added), added
    assert len(added) == 1, added


def test_signal_ratio_is_dominated_by_operations_not_permission_checks():
    """The measurable outcome: operations outnumber permission-check rows."""
    app, org, audit = build()
    client = TestClient(app)
    headers = login(client)

    for index in range(5):
        assert client.post(f"/api/v1/organizations/{org.organization_id}/endpoint-groups",
                           headers=headers, json={"name": f"Group {index}"}).status_code == 200
        client.get(f"/api/v1/organizations/{org.organization_id}/endpoints", headers=headers)
        client.get(f"/api/v1/organizations/{org.organization_id}/audit-events", headers=headers)

    recorded = types_of(audit)
    permission_checks = [item for item in recorded if item == "authorization.allowed"]
    operations = [item for item in recorded if item.startswith("endpoint_group")]
    assert permission_checks == []
    assert len(operations) == 5
    # Every stored row is something an operator would care about.
    assert all(item != "authorization.allowed" for item in recorded)


def test_denied_operation_is_recorded_and_visible_to_the_tenant():
    """A denial must reach the tenant feed, which requires attribution."""
    app, org, audit = build(permissions=["audit.read", "organization.read"])
    client = TestClient(app)
    headers = login(client)

    denied = client.post(f"/api/v1/organizations/{org.organization_id}/endpoint-groups",
                         headers=headers, json={"name": "Nope"})
    assert denied.status_code == 403

    feed = client.get(f"/api/v1/organizations/{org.organization_id}/audit-events",
                      headers=headers).json()
    kinds = [item["event_type"] for item in feed["items"]]
    assert "authorization.denied" in kinds, kinds

    event = next(item for item in feed["items"] if item["event_type"] == "authorization.denied")
    assert event["severity"] == "critical"
    assert event["outcome"] == "denied"
    assert event["actor"]["principal_type"] == "human"
    assert event["reason_code"] == "permission_not_granted"


def test_denials_surface_without_needing_the_permission_check_toggle():
    app, org, audit = build(permissions=["audit.read", "organization.read"])
    client = TestClient(app)
    headers = login(client)
    client.post(f"/api/v1/organizations/{org.organization_id}/endpoint-groups",
                headers=headers, json={"name": "Nope"})

    default_view = client.get(f"/api/v1/organizations/{org.organization_id}/audit-events",
                              headers=headers).json()
    assert any(item["event_type"] == "authorization.denied" for item in default_view["items"])
    assert default_view["excluded_event_types"] == ["authorization.allowed"]


def test_diagnostic_mode_restores_the_permission_check_trace():
    app, org, audit = build(policy=AuthorizationAuditPolicy(record_successful_authorizations=True))
    client = TestClient(app)
    headers = login(client)
    client.get(f"/api/v1/organizations/{org.organization_id}/endpoints", headers=headers)

    assert "authorization.allowed" in types_of(audit)
    feed = client.get(
        f"/api/v1/organizations/{org.organization_id}/audit-events?include_permission_checks=true",
        headers=headers).json()
    assert any(item["event_type"] == "authorization.allowed" for item in feed["items"])


def test_historical_permission_check_rows_remain_readable():
    """Suppressing new writes must not hide rows already recorded."""
    from backend.domain.security import (AuthorizationAction, AuthorizationResource,
                                         SecurityAuditEvent, SecurityAuditOutcome)
    app, org, audit = build()
    audit.append(SecurityAuditEvent(
        event_type="authorization.allowed", occurred_at=datetime.now(timezone.utc),
        principal=SecurityPrincipal.human("11111111-1111-1111-1111-111111111111"),
        action=AuthorizationAction.ENDPOINT_READ,
        resource=AuthorizationResource("endpoint", "legacy"),
        outcome=SecurityAuditOutcome.SUCCESS, organization_id=str(org.organization_id),
        user_id="11111111-1111-1111-1111-111111111111"))

    client = TestClient(app)
    headers = login(client)
    feed = client.get(
        f"/api/v1/organizations/{org.organization_id}/audit-events?include_permission_checks=true",
        headers=headers).json()
    assert any(item["event_type"] == "authorization.allowed" for item in feed["items"])


def test_audit_read_itself_does_not_grow_the_trail():
    """Polling the activity feed must not feed itself."""
    app, org, audit = build()
    client = TestClient(app)
    headers = login(client)
    client.get(f"/api/v1/organizations/{org.organization_id}/audit-events", headers=headers)
    baseline = len(audit.list())

    for _ in range(15):
        client.get(f"/api/v1/organizations/{org.organization_id}/audit-events", headers=headers)

    assert len(audit.list()) == baseline
