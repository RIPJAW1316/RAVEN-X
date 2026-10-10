from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.application.endpoint import TenantEndpointService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService, TenantOrganizationAdministrationService)
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository


class FakeAssessments:
    def __init__(self, endpoint, allowed_principal_id=None):
        self.endpoint = endpoint
        self.allowed_principal_id = str(allowed_principal_id) if allowed_principal_id else None
        self.items = []

    def create_assessment(self, principal, context, endpoint_id, scanner_ids):
        if endpoint_id != self.endpoint.endpoint_id:
            raise KeyError("endpoint not found")
        item = {"assessment_id": "assessment-1", "endpoint_id": str(endpoint_id), "scanner_ids": list(scanner_ids), "organization_id": str(context.organization_id)}
        self.items.append(item)
        return item

    def list_assessments(self, principal, context):
        if self.allowed_principal_id is not None and principal.principal_id != self.allowed_principal_id:
            raise PermissionError("assessment.read denied")
        return [item for item in self.items if item["organization_id"] == str(context.organization_id)]

    def get_assessment(self, principal, context, assessment_id):
        for item in self.items:
            if item["assessment_id"] == assessment_id and item["organization_id"] == str(context.organization_id):
                return item
        raise KeyError("assessment not found")

    def cancel(self, principal, context, assessment_id):
        return {"assessment_id": assessment_id, "outcome": "cancelled"}


def setup_app():
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    user = identity.create_initial_user("human@example.com", "Human", "HUMAN_PASSWORD_SENTINEL")
    member = identity.create_user("member@example.com", "Member", "MEMBER_PASSWORD_SENTINEL", principal=SecurityPrincipal.system())
    organizations = InMemoryOrganizationRepository()
    org_x = OrganizationService(organizations).create("X")
    memberships = InMemoryOrganizationMembershipRepository()
    membership = OrganizationMembershipService(memberships, organizations, users).create(user.user_id, org_x.organization_id)
    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(org_x.organization_id, "Analyst", ["endpoint.read", "assessment.create", "assessment.read", "assessment.cancel", "organization.read", "membership.read", "membership.create", "membership.suspend", "membership.revoke"])
    RoleBindingService(bindings, roles, memberships).create(org_x.organization_id, membership.membership_id, role.role_id)
    endpoints = InMemoryEndpointRepository()
    endpoint = Endpoint(EndpointId.new(), "human-host", PlatformInfo("Windows"), created_at=datetime.now(timezone.utc), organization_id=org_x.organization_id)
    endpoints.add(endpoint)
    authorizer = OrganizationRbacAuthorizer(membership_repository=memberships, role_binding_repository=bindings,
        role_repository=roles, organization_repository=organizations, endpoint_repository=endpoints)
    endpoint_service = TenantEndpointService(endpoints, authorizer)
    auth = HumanAuthenticationService(users)
    sessions = HumanSessionAuthenticator(users)
    assessments = FakeAssessments(endpoint, user.user_id)
    organization_service = OrganizationService(organizations)
    membership_service = OrganizationMembershipService(memberships, organizations, users)
    administration = TenantOrganizationAdministrationService(organization_service, membership_service, organizations, memberships, authorizer)
    app = FastAPI()
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        auth, sessions, users, OrganizationContextResolver(users, memberships, organizations), endpoint_service, assessments,
        organizations, memberships, administration)), prefix="/api/v1")
    return app, auth, user, member, org_x


def test_login_and_tenant_endpoint_boundary():
    app, auth, user, _member, organization = setup_app()
    client = TestClient(app)
    login = client.post("/api/v1/auth/login", json={"email": "human@example.com", "password": "HUMAN_PASSWORD_SENTINEL"})
    assert login.status_code == 200
    token = login.json()["session_token"]
    assert token not in repr(auth.authenticate("human@example.com", "HUMAN_PASSWORD_SENTINEL"))
    response = client.get(f"/api/v1/organizations/{organization.organization_id}/endpoints", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["hostname"] == "human-host"
    assert "HUMAN_PASSWORD_SENTINEL" not in response.text


def test_logout_and_cross_tenant_context_are_safe():
    app, auth, user, _member, organization = setup_app()
    client = TestClient(app)
    token = client.post("/api/v1/auth/login", json={"email": "human@example.com", "password": "HUMAN_PASSWORD_SENTINEL"}).json()["session_token"]
    assert client.get("/api/v1/organizations/not-a-member/endpoints", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/endpoints", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_tenant_assessment_routes_use_explicit_context():
    app, _auth, _user, _member, organization = setup_app()
    client = TestClient(app)
    token = client.post("/api/v1/auth/login", json={"email": "human@example.com", "password": "HUMAN_PASSWORD_SENTINEL"}).json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}
    endpoint_id = client.get(f"/api/v1/organizations/{organization.organization_id}/endpoints", headers=headers).json()[0]["endpoint_id"]
    created = client.post(f"/api/v1/organizations/{organization.organization_id}/assessments", headers=headers,
                          json={"endpoint_id": endpoint_id, "scanner_ids": ["windows.firewall"]})
    assert created.status_code == 200
    assessment_id = created.json()["assessment_id"]
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/assessments", headers=headers).json()[0]["assessment_id"] == assessment_id
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/assessments/{assessment_id}", headers=headers).status_code == 200
    assert client.post(f"/api/v1/organizations/{organization.organization_id}/assessments/{assessment_id}/cancel", headers=headers).status_code == 200


def test_login_errors_do_not_enumerate_users():
    app, *_ = setup_app()
    client = TestClient(app)
    wrong_email = client.post("/api/v1/auth/login", json={"email": "missing@example.com", "password": "wrong"})
    wrong_password = client.post("/api/v1/auth/login", json={"email": "human@example.com", "password": "wrong"})
    assert wrong_email.status_code == wrong_password.status_code == 401
    assert wrong_email.json() == wrong_password.json()


def test_organization_administration_is_scoped_and_new_member_has_no_permissions():
    app, _auth, _user, member, organization = setup_app()
    client = TestClient(app)
    admin_token = client.post("/api/v1/auth/login", json={"email": "human@example.com", "password": "HUMAN_PASSWORD_SENTINEL"}).json()["session_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    assert client.get("/api/v1/auth/organizations", headers=headers).json()[0]["organization_id"] == str(organization.organization_id)
    assert client.get(f"/api/v1/organizations/{organization.organization_id}", headers=headers).status_code == 200
    created = client.post(f"/api/v1/organizations/{organization.organization_id}/memberships", headers=headers, json={"user_id": str(member.user_id)})
    assert created.status_code == 200
    membership_id = created.json()["membership_id"]
    assert client.post(f"/api/v1/organizations/{organization.organization_id}/memberships", headers=headers, json={"user_id": str(member.user_id)}).status_code == 409
    member_token = client.post("/api/v1/auth/login", json={"email": "member@example.com", "password": "MEMBER_PASSWORD_SENTINEL"}).json()["session_token"]
    member_headers = {"Authorization": f"Bearer {member_token}"}
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/endpoints", headers=member_headers).status_code == 403
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/assessments", headers=member_headers).status_code == 403
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/memberships", headers=member_headers).status_code == 403
    assert client.post(f"/api/v1/organizations/{organization.organization_id}/memberships/{membership_id}/revoke", headers=headers).status_code == 200
    assert client.get(f"/api/v1/organizations/{organization.organization_id}/endpoints", headers={"Authorization": f"Bearer {member_token}"}).status_code == 403
