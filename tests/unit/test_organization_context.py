from datetime import datetime, timezone
import pytest
from backend.application.identity import HumanIdentityService, HumanAuthenticationService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextError, OrganizationContextReason, OrganizationContextResolver, OrganizationMembershipService, OrganizationService)
from backend.domain.organization import MembershipStatus, OrganizationStatus
from backend.domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType, SecurityPrincipal)
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

PASSWORD="correct horse battery staple"

def setup_context():
    users=InMemoryUserRepository(); user=HumanIdentityService(users).create_initial_user("a@example.com","A",PASSWORD)
    orgs=InMemoryOrganizationRepository(); x=OrganizationService(orgs).create("X"); y=OrganizationService(orgs).create("Y")
    memberships=InMemoryOrganizationMembershipRepository(); service=OrganizationMembershipService(memberships,orgs,users); mx=service.create(user.user_id,x.organization_id); my=service.create(user.user_id,y.organization_id)
    principal=SecurityPrincipal.human(user.user_id); resolver=OrganizationContextResolver(users,memberships,orgs)
    return users,user,orgs,x,y,memberships,mx,my,principal,resolver,service

def test_active_context_is_explicit_and_multi_org_selection_is_independent():
    users,user,orgs,x,y,memberships,mx,my,principal,resolver,service=setup_context()
    cx=resolver.resolve(principal,x.organization_id); cy=resolver.resolve(principal,y.organization_id)
    assert cx.organization_id==x.organization_id and cy.organization_id==y.organization_id and cx.membership_id!=cy.membership_id
    assert resolver.resolve(principal,x.organization_id,membership_id=str(mx.membership_id)).membership_id==str(mx.membership_id)

def test_cross_org_and_wrong_membership_are_rejected_without_fallback():
    users,user,orgs,x,y,memberships,mx,my,principal,resolver,service=setup_context()
    with pytest.raises(OrganizationContextError) as error: resolver.resolve(principal,x.organization_id,membership_id=str(my.membership_id))
    assert error.value.reason_code==OrganizationContextReason.PRINCIPAL_MEMBERSHIP_MISMATCH.value
    other=HumanIdentityService(users).create_user("b@example.com","B",PASSWORD,principal=SecurityPrincipal.system())
    with pytest.raises(OrganizationContextError) as error: resolver.resolve(SecurityPrincipal.human(other.user_id),x.organization_id)
    assert error.value.reason_code==OrganizationContextReason.MEMBERSHIP_NOT_FOUND.value

@pytest.mark.parametrize("change,reason",[("suspend_membership",OrganizationContextReason.MEMBERSHIP_SUSPENDED),("revoke_membership",OrganizationContextReason.MEMBERSHIP_REVOKED),("suspend_org",OrganizationContextReason.ORGANIZATION_SUSPENDED),("revoke_org",OrganizationContextReason.ORGANIZATION_REVOKED)])
def test_lifecycle_changes_immediately_block_context(change,reason):
    users,user,orgs,x,y,memberships,mx,my,principal,resolver,service=setup_context()
    if change=="suspend_membership": service.suspend(mx.membership_id,principal=SecurityPrincipal.system())
    elif change=="revoke_membership": service.revoke(mx.membership_id,principal=SecurityPrincipal.system())
    elif change=="suspend_org": OrganizationService(orgs).suspend(x.organization_id,principal=SecurityPrincipal.system())
    else: OrganizationService(orgs).revoke(x.organization_id,principal=SecurityPrincipal.system())
    with pytest.raises(OrganizationContextError) as error: resolver.resolve(principal,x.organization_id)
    assert error.value.reason_code==reason.value

def test_membership_revocation_does_not_revoke_global_human_session():
    users,user,orgs,x,y,memberships,mx,my,principal,resolver,service=setup_context()
    token,session,_=HumanAuthenticationService(users).authenticate(user.email,PASSWORD)
    service.revoke(mx.membership_id,principal=SecurityPrincipal.system())
    assert HumanSessionAuthenticator(users).validate(token,session.session_id).principal_type is PrincipalType.HUMAN
    with pytest.raises(OrganizationContextError): resolver.resolve(principal,x.organization_id)

def test_user_disable_and_non_human_principal_are_rejected_and_human_auth_is_separate():
    users,user,orgs,x,y,memberships,mx,my,principal,resolver,service=setup_context(); audit=InMemorySecurityAuditRepository(); resolver=OrganizationContextResolver(users,memberships,orgs,audit_sink=audit)
    HumanIdentityService(users).disable_user(user.user_id,principal=SecurityPrincipal.system())
    with pytest.raises(OrganizationContextError) as error: resolver.resolve(principal,x.organization_id)
    assert error.value.reason_code==OrganizationContextReason.USER_INACTIVE.value
    with pytest.raises(OrganizationContextError) as error: resolver.resolve(SecurityPrincipal.system(),x.organization_id)
    assert error.value.reason_code==OrganizationContextReason.NOT_HUMAN_PRINCIPAL.value
    assert any(event.event_type=="organization.context_denied" for event in audit.list())

def test_context_can_be_attached_to_authorization_request_without_granting_human_access():
    users,user,orgs,x,y,memberships,mx,my,principal,resolver,service=setup_context(); context=resolver.resolve(principal,x.organization_id)
    request=AuthorizationRequest(principal,AuthorizationAction.ORGANIZATION_UPDATE,AuthorizationResource("organization",str(x.organization_id)),organization_context=context)
    assert request.organization_context["organization_id"]==str(x.organization_id)
