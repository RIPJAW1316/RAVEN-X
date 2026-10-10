from datetime import datetime, timezone
import pytest
from backend.application.organization import OrganizationMembershipService, OrganizationService
from backend.application.ports.control_plane_authorization import AuthorizationService, ConservativeControlPlaneAuthorizer
from backend.domain.organization import MembershipStatus, Organization, OrganizationId, OrganizationStatus
from backend.domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityPrincipal
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository
from backend.application.identity import HumanIdentityService

PASSWORD="correct horse battery staple"

def test_organization_id_lifecycle_name_mutation_and_serialization():
    now=datetime(2026,1,1,tzinfo=timezone.utc); org=Organization(OrganizationId.new(),"Acme",created_at=now,updated_at=now)
    assert OrganizationId.parse(str(org.organization_id)) == org.organization_id
    suspended=org.transition_to(OrganizationStatus.SUSPENDED,now); assert suspended.organization_id==org.organization_id
    assert suspended.to_dict()["status"]=="suspended"
    with pytest.raises(ValueError): suspended.transition_to(OrganizationStatus.REVOKED,now).transition_to(OrganizationStatus.ACTIVE,now)

def test_memberships_are_many_to_many_and_duplicate_pairs_are_rejected():
    users=InMemoryUserRepository(); a=HumanIdentityService(users).create_initial_user("a@example.com","A",PASSWORD); b=HumanIdentityService(users).create_user("b@example.com","B",PASSWORD,principal=SecurityPrincipal.system())
    orgs=InMemoryOrganizationRepository(); org_service=OrganizationService(orgs); x=org_service.create("X"); y=org_service.create("Y")
    memberships=InMemoryOrganizationMembershipRepository(); service=OrganizationMembershipService(memberships,orgs,users)
    ax=service.create(a.user_id,x.organization_id); ay=service.create(a.user_id,y.organization_id); bx=service.create(b.user_id,x.organization_id)
    assert len(service.repository.list_for_user(a.user_id))==2 and len(service.repository.list_for_organization(x.organization_id))==2
    assert ax.membership_id != ay.membership_id and ax.organization_id != ay.organization_id
    assert not hasattr(ax,"role") and not hasattr(ax,"permissions")
    with pytest.raises(ValueError): service.create(a.user_id,x.organization_id)
    assert service.suspend(ax.membership_id,principal=SecurityPrincipal.system()).status is MembershipStatus.SUSPENDED

def test_membership_does_not_grant_human_organization_authorization_and_system_is_explicit():
    auth=AuthorizationService(ConservativeControlPlaneAuthorizer()); orgs=InMemoryOrganizationRepository(); org=OrganizationService(orgs,authorization_service=auth).create("X",principal=SecurityPrincipal.system())
    human=SecurityPrincipal.human(HumanIdentityService(InMemoryUserRepository()).create_initial_user("a@example.com","A",PASSWORD).user_id)
    decision=auth.authorize(AuthorizationRequest(human,AuthorizationAction.ORGANIZATION_UPDATE,AuthorizationResource("organization",str(org.organization_id))))
    assert not decision.allowed

def test_lifecycle_operations_are_audited_without_sensitive_metadata():
    audit=InMemorySecurityAuditRepository(); orgs=InMemoryOrganizationRepository(); org=OrganizationService(orgs,audit_sink=audit).create("X",metadata={"label":"safe"})
    OrganizationService(orgs,audit_sink=audit).revoke(org.organization_id,principal=SecurityPrincipal.system())
    events=audit.list(); assert [e.event_type for e in events]==["organization.created","organization.revoked"]
    assert all("secret" not in str(e.to_dict()).lower() for e in events)
