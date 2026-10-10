"""HTTP boundary tests for the audit feed, using the real auth and RBAC stack."""
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.application.audit import TenantAuditQueryService
from backend.application.endpoint import TenantEndpointService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService, TenantOrganizationAdministrationService)
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.domain.security import (AuthorizationAction, AuthorizationResource, SecurityAuditEvent,
                                     SecurityAuditOutcome, SecurityPrincipal)
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

NOW = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
AUDITOR_PASSWORD = "AUDITOR_PASSWORD_SENTINEL"
VIEWER_PASSWORD = "VIEWER_PASSWORD_SENTINEL"


def _event(organization_id, *, event_type, outcome=SecurityAuditOutcome.SUCCESS, occurred_at=NOW,
           metadata=None, principal=None):
    return SecurityAuditEvent(
        event_type=event_type, occurred_at=occurred_at,
        principal=principal or SecurityPrincipal.human("33333333-3333-3333-3333-333333333333"),
        action=AuthorizationAction.ENDPOINT_CREATE,
        resource=AuthorizationResource("endpoint", "endpoint-1"),
        outcome=outcome, organization_id=str(organization_id),
        user_id="33333333-3333-3333-3333-333333333333", metadata=metadata or {},
    )


def setup_app():
    """Two organizations; an auditor in A with audit.read, a viewer in A without it."""
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    auditor = identity.create_initial_user("auditor@example.com", "Auditor", AUDITOR_PASSWORD)
    viewer = identity.create_user("viewer@example.com", "Viewer", VIEWER_PASSWORD,
                                  principal=SecurityPrincipal.system())

    organizations = InMemoryOrganizationRepository()
    org_a = OrganizationService(organizations).create("Org A")
    org_b = OrganizationService(organizations).create("Org B")

    memberships = InMemoryOrganizationMembershipRepository()
    membership_service = OrganizationMembershipService(memberships, organizations, users)
    auditor_membership = membership_service.create(auditor.user_id, org_a.organization_id)
    viewer_membership = membership_service.create(viewer.user_id, org_a.organization_id)
    # The auditor is also a member of B but without audit.read there.
    auditor_b_membership = membership_service.create(auditor.user_id, org_b.organization_id)

    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role_service, binding_service = RoleService(roles), RoleBindingService(bindings, roles, memberships)

    auditor_role = role_service.create(org_a.organization_id, "Auditor",
                                       ["audit.read", "organization.read", "endpoint.read"])
    binding_service.create(org_a.organization_id, auditor_membership.membership_id, auditor_role.role_id)

    viewer_role = role_service.create(org_a.organization_id, "Viewer",
                                      ["organization.read", "endpoint.read"])
    binding_service.create(org_a.organization_id, viewer_membership.membership_id, viewer_role.role_id)

    b_role = role_service.create(org_b.organization_id, "B Viewer", ["organization.read"])
    binding_service.create(org_b.organization_id, auditor_b_membership.membership_id, b_role.role_id)

    endpoints = InMemoryEndpointRepository()
    authorizer = OrganizationRbacAuthorizer(
        membership_repository=memberships, role_binding_repository=bindings, role_repository=roles,
        organization_repository=organizations, endpoint_repository=endpoints)

    audit_repository = InMemorySecurityAuditRepository()
    for index in range(30):
        audit_repository.append(_event(org_a.organization_id, event_type=f"event.a{index:02d}",
                                       occurred_at=NOW + timedelta(minutes=index)))
    audit_repository.append(_event(org_a.organization_id, event_type="authorization.denied",
                                   outcome=SecurityAuditOutcome.DENIED,
                                   occurred_at=NOW + timedelta(hours=2)))
    audit_repository.append(_event(org_a.organization_id, event_type="compliance.snapshot",
                                   metadata={"login": "auditor@example.com", "api_token": "leak-me",
                                             "framework_id": "ravenx.windows.baseline"},
                                   occurred_at=NOW + timedelta(hours=3)))
    audit_repository.append(_event(org_b.organization_id, event_type="secret.b.event",
                                   occurred_at=NOW + timedelta(hours=4)))

    app = FastAPI()
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        HumanAuthenticationService(users), HumanSessionAuthenticator(users), users,
        OrganizationContextResolver(users, memberships, organizations),
        TenantEndpointService(endpoints, authorizer), None,
        organizations, memberships,
        TenantOrganizationAdministrationService(OrganizationService(organizations), membership_service,
                                                organizations, memberships, authorizer),
        audit_query_service=TenantAuditQueryService(audit_repository, authorizer),
    )), prefix="/api/v1")
    return app, org_a, org_b


def _token(client, email, password):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()["session_token"]


def _headers(client, email=("auditor@example.com"), password=AUDITOR_PASSWORD):
    return {"Authorization": f"Bearer {_token(client, email, password)}"}


def test_authorized_user_reads_their_own_organization_events():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    response = client.get(f"/api/v1/organizations/{org_a.organization_id}/audit-events",
                          headers=_headers(client))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "pagination", "excluded_event_types"}
    assert body["pagination"]["total"] == 32
    assert body["pagination"]["limit"] == 25
    assert body["pagination"]["has_next"] is True
    assert len(body["items"]) == 25


def test_unauthenticated_request_is_rejected():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    assert client.get(f"/api/v1/organizations/{org_a.organization_id}/audit-events").status_code == 401
    assert client.get(f"/api/v1/organizations/{org_a.organization_id}/audit-events",
                      headers={"Authorization": "Bearer not-a-real-session"}).status_code == 401


def test_member_without_audit_read_permission_is_forbidden():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    headers = _headers(client, "viewer@example.com", VIEWER_PASSWORD)
    response = client.get(f"/api/v1/organizations/{org_a.organization_id}/audit-events", headers=headers)
    assert response.status_code == 403
    assert "secret" not in response.text.lower() or "event" not in response.text.lower()


def test_cross_tenant_read_is_forbidden_not_empty():
    """Membership in B without audit.read must be a 403, never a leaked page."""
    app, _org_a, org_b = setup_app()
    client = TestClient(app)
    response = client.get(f"/api/v1/organizations/{org_b.organization_id}/audit-events",
                          headers=_headers(client))
    assert response.status_code == 403
    assert "secret.b.event" not in response.text


def test_non_member_organization_is_denied_without_disclosing_existence():
    app, _org_a, _org_b = setup_app()
    client = TestClient(app)
    response = client.get("/api/v1/organizations/11111111-1111-1111-1111-111111111111/audit-events",
                          headers=_headers(client))
    assert response.status_code == 403


def test_events_are_newest_first_and_paginate():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    headers = _headers(client)
    base = f"/api/v1/organizations/{org_a.organization_id}/audit-events"

    first = client.get(f"{base}?limit=5&offset=0", headers=headers).json()
    second = client.get(f"{base}?limit=5&offset=5", headers=headers).json()

    assert first["items"][0]["event_type"] == "compliance.snapshot"
    assert first["items"][1]["event_type"] == "authorization.denied"
    timestamps = [item["occurred_at"] for item in first["items"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert not {item["event_id"] for item in first["items"]} & {item["event_id"] for item in second["items"]}
    assert second["pagination"]["offset"] == 5


def test_filtering_by_type_outcome_and_severity():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    headers = _headers(client)
    base = f"/api/v1/organizations/{org_a.organization_id}/audit-events"

    by_type = client.get(f"{base}?event_type=authorization.denied", headers=headers).json()
    assert by_type["pagination"]["total"] == 1

    by_outcome = client.get(f"{base}?outcome=denied", headers=headers).json()
    assert by_outcome["pagination"]["total"] == 1

    by_severity = client.get(f"{base}?severity=critical", headers=headers).json()
    assert by_severity["pagination"]["total"] == 1
    assert by_severity["items"][0]["severity"] == "critical"


def test_time_range_filtering():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    base = f"/api/v1/organizations/{org_a.organization_id}/audit-events"
    headers = _headers(client)
    cutoff = NOW + timedelta(hours=1)

    # Percent-encoded offset, Z-suffixed, and the raw "+" that a naive client
    # sends (which arrives as a space) must all resolve to the same instant.
    for rendering in (quote(cutoff.isoformat(), safe=""),
                      cutoff.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                      cutoff.isoformat()):
        response = client.get(f"{base}?from={rendering}", headers=headers)
        assert response.status_code == 200, rendering
        assert response.json()["pagination"]["total"] == 2, rendering

    bounded = client.get(f"{base}?from={quote(NOW.isoformat(), safe='')}"
                         f"&to={quote((NOW + timedelta(minutes=5)).isoformat(), safe='')}",
                         headers=headers).json()
    assert bounded["pagination"]["total"] == 6


def test_sensitive_metadata_is_never_serialized():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    response = client.get(f"/api/v1/organizations/{org_a.organization_id}/audit-events?limit=5",
                          headers=_headers(client))
    assert "leak-me" not in response.text
    assert "auditor@example.com" not in response.text
    snapshot = next(item for item in response.json()["items"] if item["event_type"] == "compliance.snapshot")
    assert snapshot["metadata"] == {"framework_id": "ravenx.windows.baseline"}


def test_malformed_query_parameters_are_rejected():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    headers = _headers(client)
    base = f"/api/v1/organizations/{org_a.organization_id}/audit-events"
    for query in ("limit=0", "limit=-5", "limit=5000", "limit=abc", "offset=-1", "offset=xyz",
                  "outcome=bogus", "severity=apocalyptic", "from=not-a-date",
                  "event_type=" + ",".join(f"e{i}" for i in range(11))):
        response = client.get(f"{base}?{query}", headers=headers)
        assert response.status_code == 422, f"{query} should be rejected, got {response.status_code}"


def test_page_size_cannot_be_used_to_dump_the_log():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    base = f"/api/v1/organizations/{org_a.organization_id}/audit-events"
    assert client.get(f"{base}?limit=100", headers=_headers(client)).status_code == 200
    assert client.get(f"{base}?limit=101", headers=_headers(client)).status_code == 422


def test_permission_check_noise_is_suppressed_by_default_and_disclosed():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    headers = _headers(client)
    base = f"/api/v1/organizations/{org_a.organization_id}/audit-events"

    default = client.get(base, headers=headers).json()
    assert default["excluded_event_types"] == ["authorization.allowed"]

    complete = client.get(f"{base}?include_permission_checks=true", headers=headers).json()
    assert complete["excluded_event_types"] == []
    assert complete["pagination"]["total"] >= default["pagination"]["total"]

    assert client.get(f"{base}?include_permission_checks=maybe", headers=headers).status_code == 422


def test_empty_result_is_a_valid_response():
    app, org_a, _org_b = setup_app()
    client = TestClient(app)
    response = client.get(
        f"/api/v1/organizations/{org_a.organization_id}/audit-events?event_type=nothing.matches",
        headers=_headers(client))
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["pagination"]["total"] == 0
    assert response.json()["pagination"]["has_next"] is False


def test_service_absence_reports_unavailable_rather_than_failing_open():
    app_users = InMemoryUserRepository()
    identity = HumanIdentityService(app_users)
    identity.create_initial_user("solo@example.com", "Solo", AUDITOR_PASSWORD)
    organizations = InMemoryOrganizationRepository()
    org = OrganizationService(organizations).create("Solo Org")
    memberships = InMemoryOrganizationMembershipRepository()
    OrganizationMembershipService(memberships, organizations, app_users).create(
        app_users.get_user_by_email("solo@example.com").user_id, org.organization_id)
    app = FastAPI()
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        HumanAuthenticationService(app_users), HumanSessionAuthenticator(app_users), app_users,
        OrganizationContextResolver(app_users, memberships, organizations), None, None,
        organizations, memberships, None, audit_query_service=None)), prefix="/api/v1")
    client = TestClient(app)
    token = _token(client, "solo@example.com", AUDITOR_PASSWORD)
    response = client.get(f"/api/v1/organizations/{org.organization_id}/audit-events",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 503
