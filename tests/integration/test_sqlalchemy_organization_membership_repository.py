from backend.application.identity import HumanIdentityService
from backend.application.organization import OrganizationMembershipService, OrganizationService
from backend.core.database.database import DatabaseManager
from backend.infrastructure.persistence.sqlalchemy_membership_repository import SQLAlchemyOrganizationMembershipRepository
from backend.infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository
from backend.infrastructure.persistence.sqlalchemy_user_repository import SQLAlchemyUserRepository
from backend.infrastructure.persistence.sqlalchemy_security_audit_repository import SQLAlchemySecurityAuditRepository
from backend.domain.security import SecurityPrincipal

def test_organization_and_membership_records_survive_restart_and_retain_revocations(tmp_path):
    db=DatabaseManager(); db.config={"type":"sqlite","sqlite_path":str(tmp_path/'organizations.db'),"echo":False}; db.create_tables()
    users=SQLAlchemyUserRepository(db); user=HumanIdentityService(users).create_initial_user("a@example.com","A","correct horse battery staple")
    orgs=SQLAlchemyOrganizationRepository(db); org=OrganizationService(orgs).create("Acme")
    memberships=SQLAlchemyOrganizationMembershipRepository(db); membership=OrganizationMembershipService(memberships,orgs,users).create(user.user_id,org.organization_id)
    OrganizationMembershipService(memberships).revoke(membership.membership_id,principal=None)
    db.close(); reopened=DatabaseManager(); reopened.config=db.config; reopened.initialize_sync_engine()
    assert SQLAlchemyOrganizationRepository(reopened).get(org.organization_id).name=="Acme"
    assert SQLAlchemyOrganizationMembershipRepository(reopened).get(membership.membership_id).status.value=="revoked"
    reopened.close()

def test_organization_and_membership_lifecycle_audit_is_durable_and_secret_safe(tmp_path):
    db=DatabaseManager(); db.config={"type":"sqlite","sqlite_path":str(tmp_path/'organization-audit.db'),"echo":False}; db.create_tables()
    audit=SQLAlchemySecurityAuditRepository(db); users=SQLAlchemyUserRepository(db); user=HumanIdentityService(users,audit_sink=audit).create_initial_user("a@example.com","A","correct horse battery staple")
    orgs=SQLAlchemyOrganizationRepository(db); organization_service=OrganizationService(orgs,audit_sink=audit); org=organization_service.create("Acme")
    memberships=SQLAlchemyOrganizationMembershipRepository(db); membership_service=OrganizationMembershipService(memberships,orgs,users,audit_sink=audit); membership=membership_service.create(user.user_id,org.organization_id)
    membership_service.suspend(membership.membership_id,principal=SecurityPrincipal.system()); organization_service.revoke(org.organization_id,principal=SecurityPrincipal.system())
    values=audit.list(); types={event.event_type for event in values}
    assert {"organization.created","membership.created","membership.suspended","organization.revoked"} <= types
    assert all("correct horse" not in str(event.to_dict()) for event in values)
    db.close()
