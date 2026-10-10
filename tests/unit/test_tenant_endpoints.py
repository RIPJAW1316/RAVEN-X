from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from backend.application.endpoint import TenantEndpointService
from backend.application.organization import OrganizationContextResolver, OrganizationMembershipService, OrganizationService
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository
from backend.application.identity import HumanIdentityService

NOW = datetime(2026, 8, 23, tzinfo=timezone.utc)


def setup():
    users = InMemoryUserRepository()
    user = HumanIdentityService(users).create_initial_user("tenant@example.com", "Tenant", "long-test-password")
    orgs = InMemoryOrganizationRepository()
    x = OrganizationService(orgs).create("X")
    y = OrganizationService(orgs).create("Y")
    memberships = InMemoryOrganizationMembershipRepository()
    mx = OrganizationMembershipService(memberships, orgs, users).create(user.user_id, x.organization_id)
    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(x.organization_id, "Reader", ["endpoint.read", "endpoint.revoke", "endpoint.create"])
    RoleBindingService(bindings, roles, memberships).create(x.organization_id, mx.membership_id, role.role_id)
    principal = SecurityPrincipal.human(user.user_id)
    context = OrganizationContextResolver(users, memberships, orgs).resolve(principal, x.organization_id)
    repository = InMemoryEndpointRepository()
    endpoint_x = Endpoint(EndpointId.new(), "x-host", PlatformInfo("Windows"), created_at=NOW, organization_id=x.organization_id)
    endpoint_y = Endpoint(EndpointId.new(), "y-host", PlatformInfo("Windows"), created_at=NOW, organization_id=y.organization_id)
    legacy = Endpoint(EndpointId.new(), "legacy", PlatformInfo("Windows"), created_at=NOW)
    repository.add(endpoint_x); repository.add(endpoint_y); repository.add(legacy)
    authorizer = OrganizationRbacAuthorizer(membership_repository=memberships, role_binding_repository=bindings,
        role_repository=roles, organization_repository=orgs, endpoint_repository=repository)
    return principal, context, x, y, repository, authorizer, endpoint_x, endpoint_y, legacy, memberships, bindings, role


def test_human_endpoint_access_is_tenant_scoped_and_legacy_is_hidden():
    principal, context, x, y, repository, authorizer, endpoint_x, endpoint_y, legacy, *_ = setup()
    service = TenantEndpointService(repository, authorizer)
    assert service.get(principal, context, endpoint_x.endpoint_id).endpoint_id == endpoint_x.endpoint_id
    with pytest.raises(KeyError):
        service.get(principal, context, endpoint_y.endpoint_id)
    with pytest.raises(KeyError):
        service.get(principal, context, legacy.endpoint_id)
    assert tuple(service.list(principal, context)) == (endpoint_x,)


def test_ownership_is_required_for_enterprise_registration_and_immutable():
    principal, context, x, _y, repository, authorizer, endpoint_x, *_ = setup()
    service = TenantEndpointService(repository, authorizer)
    unowned = Endpoint(EndpointId.new(), "new", PlatformInfo("Windows"), created_at=NOW)
    with pytest.raises(ValueError):
        service.register(principal, context, unowned)
    with pytest.raises(ValueError):
        service.update(principal, context, replace(endpoint_x, organization_id=None, hostname="bad"))
    created = Endpoint(EndpointId.new(), "created", PlatformInfo("Windows"), created_at=NOW, organization_id=x.organization_id)
    assert service.register(principal, context, created).organization_id == x.organization_id


def test_role_revocation_removes_endpoint_access_immediately():
    principal, context, _x, _y, repository, authorizer, endpoint_x, _endpoint_y, _legacy, _memberships, bindings, role = setup()
    service = TenantEndpointService(repository, authorizer)
    assert service.get(principal, context, endpoint_x.endpoint_id)
    binding = bindings.list_for_role(role.role_id)[0]
    bindings.update(binding.transition_to("revoked", datetime.now(timezone.utc) + timedelta(minutes=1)))
    with pytest.raises(PermissionError):
        service.get(principal, context, endpoint_x.endpoint_id)
