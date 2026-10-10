import pytest
from backend.application.identity import HumanIdentityService
from backend.application.organization import OrganizationContextResolver, OrganizationMembershipService, OrganizationService
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.domain.rbac import Permission, RoleStatus
from backend.domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityPrincipal
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

PASSWORD="correct horse battery staple"
def setup():
    users=InMemoryUserRepository();user=HumanIdentityService(users).create_initial_user("a@example.com","A",PASSWORD)
    orgs=InMemoryOrganizationRepository();x=OrganizationService(orgs).create("X");y=OrganizationService(orgs).create("Y")
    memberships=InMemoryOrganizationMembershipRepository();ms=OrganizationMembershipService(memberships,orgs,users);mx=ms.create(user.user_id,x.organization_id);my=ms.create(user.user_id,y.organization_id)
    roles=InMemoryRoleRepository();bindings=InMemoryRoleBindingRepository();rs=RoleService(roles);bs=RoleBindingService(bindings,roles,memberships)
    rx=rs.create(x.organization_id,"Analyst",["assessment.create","assessment.read"]);ry=rs.create(y.organization_id,"Viewer",["organization.read"])
    bx=bs.create(x.organization_id,mx.membership_id,rx.role_id);by=bs.create(y.organization_id,my.membership_id,ry.role_id)
    principal=SecurityPrincipal.human(user.user_id);resolver=OrganizationContextResolver(users,memberships,orgs)
    return users,orgs,x,y,memberships,mx,my,roles,bindings,rx,ry,bx,by,principal,resolver,rs,bs
def request(principal,context,action,resource_type="assessment",resource_id="a"):
    return AuthorizationRequest(principal,action,AuthorizationResource(resource_type,resource_id),organization_context=context)

def test_explicit_permissions_allow_and_default_deny():
    users,orgs,x,y,memberships,mx,my,roles,bindings,rx,ry,bx,by,principal,resolver,rs,bs=setup()
    cx=resolver.resolve(principal,x.organization_id); authorizer=OrganizationRbacAuthorizer(membership_repository=memberships,role_binding_repository=bindings,role_repository=roles,organization_repository=orgs)
    assert authorizer.authorize(request(principal,cx,AuthorizationAction.ASSESSMENT_CREATE)).allowed
    assert not authorizer.authorize(request(principal,cx,AuthorizationAction.ASSESSMENT_CANCEL)).allowed

def test_roles_do_not_bleed_between_organizations_and_resource_scope_is_checked():
    users,orgs,x,y,memberships,mx,my,roles,bindings,rx,ry,bx,by,principal,resolver,rs,bs=setup(); authorizer=OrganizationRbacAuthorizer(membership_repository=memberships,role_binding_repository=bindings,role_repository=roles,organization_repository=orgs)
    cx=resolver.resolve(principal,x.organization_id);cy=resolver.resolve(principal,y.organization_id)
    assert authorizer.authorize(request(principal,cx,AuthorizationAction.ASSESSMENT_CREATE)).allowed
    assert not authorizer.authorize(request(principal,cy,AuthorizationAction.ASSESSMENT_CREATE)).allowed
    assert authorizer.authorize(request(principal,cy,AuthorizationAction.ORGANIZATION_READ,"organization",str(y.organization_id))).allowed
    assert not authorizer.authorize(request(principal,cx,AuthorizationAction.ORGANIZATION_READ,"organization",str(y.organization_id))).allowed

def test_revoked_membership_role_and_binding_immediately_deny():
    users,orgs,x,y,memberships,mx,my,roles,bindings,rx,ry,bx,by,principal,resolver,rs,bs=setup();authorizer=OrganizationRbacAuthorizer(membership_repository=memberships,role_binding_repository=bindings,role_repository=roles,organization_repository=orgs);cx=resolver.resolve(principal,x.organization_id)
    assert authorizer.authorize(request(principal,cx,AuthorizationAction.ASSESSMENT_CREATE)).allowed
    OrganizationMembershipService(memberships,orgs,users).revoke(mx.membership_id,principal=SecurityPrincipal.system());assert not authorizer.authorize(request(principal,cx,AuthorizationAction.ASSESSMENT_CREATE)).allowed
    # Restore membership in-memory for the independent role/binding checks.
    memberships._items[mx.membership_id]=mx; rs.revoke(rx.role_id,principal=SecurityPrincipal.system());assert not authorizer.authorize(request(principal,cx,AuthorizationAction.ASSESSMENT_CREATE)).allowed

def test_cross_organization_binding_is_rejected_and_unknown_permission_is_rejected():
    users,orgs,x,y,memberships,mx,my,roles,bindings,rx,ry,bx,by,principal,resolver,rs,bs=setup()
    with pytest.raises(ValueError): RoleBindingService(InMemoryRoleBindingRepository(),roles,memberships).create(y.organization_id,mx.membership_id,ry.role_id)
    with pytest.raises(ValueError): Permission("does.not.exist")

def test_multiple_active_roles_union_permissions_and_non_human_policy_is_preserved():
    users,orgs,x,y,memberships,mx,my,roles,bindings,rx,ry,bx,by,principal,resolver,rs,bs=setup(); extra=rs.create(x.organization_id,"Viewer",["organization.read"]);bs.create(x.organization_id,mx.membership_id,extra.role_id);cx=resolver.resolve(principal,x.organization_id);authorizer=OrganizationRbacAuthorizer(membership_repository=memberships,role_binding_repository=bindings,role_repository=roles,organization_repository=orgs)
    assert authorizer.authorize(request(principal,cx,AuthorizationAction.ORGANIZATION_READ,"organization",str(x.organization_id))).allowed
    system=authorizer.authorize(AuthorizationRequest(SecurityPrincipal.system(),AuthorizationAction.ASSESSMENT_CREATE,AuthorizationResource("assessment","x")));assert system.allowed
