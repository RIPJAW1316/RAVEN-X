"""Audit-trail integrity: an event must never be written into a tenant the
actor has not proven membership of, and a success must never be recorded as a
denial.

Both properties were defects found during live verification of the audit feed.
"""
import pytest

from backend.application.identity import HumanAuthenticationService, HumanIdentityService
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService)
from backend.domain.audit import AuditQuery, derive_severity
from backend.domain.organization import MembershipStatus
from backend.domain.security import SecurityAuditOutcome, SecurityPrincipal
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

PASSWORD = "PASSWORD_SENTINEL"


def build():
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    outsider = identity.create_initial_user("outsider@example.com", "Outsider", PASSWORD)
    insider = identity.create_user("insider@example.com", "Insider", PASSWORD,
                                   principal=SecurityPrincipal.system())
    organizations = InMemoryOrganizationRepository()
    victim = OrganizationService(organizations).create("Victim")
    memberships = InMemoryOrganizationMembershipRepository()
    membership = OrganizationMembershipService(memberships, organizations, users).create(
        insider.user_id, victim.organization_id)
    audit = InMemorySecurityAuditRepository()
    resolver = OrganizationContextResolver(users, memberships, organizations, audit_sink=audit)
    return resolver, audit, victim, outsider, insider, membership, memberships


# ------------------------------------------------- cross-tenant audit injection

def test_non_member_cannot_inject_events_into_a_tenant_feed():
    """An outsider naming a real organization must not pollute its audit trail."""
    resolver, audit, victim, outsider, *_ = build()
    principal = SecurityPrincipal.human(outsider.user_id)

    for _ in range(5):
        with pytest.raises(PermissionError):
            resolver.resolve(principal, victim.organization_id)

    page = audit.query_for_organization(victim.organization_id, AuditQuery())
    assert page.total == 0, "an outsider injected events into the victim tenant feed"


def test_denial_for_a_nonexistent_organization_is_unattributed():
    resolver, audit, _victim, outsider, *_ = build()
    principal = SecurityPrincipal.human(outsider.user_id)
    with pytest.raises(PermissionError):
        resolver.resolve(principal, "11111111-1111-1111-1111-111111111111")
    events = audit.list()
    assert len(events) == 1
    assert events[0].organization_id is None
    assert events[0].reason_code == "ORGANIZATION_NOT_FOUND"


def test_suspended_member_denial_is_attributed_so_the_tenant_can_see_it():
    """Once membership is proven, the denial belongs in that tenant's feed."""
    resolver, audit, victim, _outsider, insider, membership, memberships = build()
    OrganizationMembershipService(memberships, None, None).suspend(
        membership.membership_id, principal=SecurityPrincipal.system())
    assert memberships.get(membership.membership_id).status is MembershipStatus.SUSPENDED

    principal = SecurityPrincipal.human(insider.user_id)
    with pytest.raises(PermissionError):
        resolver.resolve(principal, victim.organization_id)

    page = audit.query_for_organization(victim.organization_id, AuditQuery())
    assert page.total == 1
    assert page.items[0].event_type == "organization.context_denied"
    assert page.items[0].severity.value == "critical"


def test_membership_of_another_tenant_does_not_authorize_attribution():
    resolver, audit, victim, outsider, *_ = build()
    principal = SecurityPrincipal.human(outsider.user_id)
    with pytest.raises(PermissionError):
        resolver.resolve(principal, victim.organization_id)
    event = audit.list()[0]
    assert event.reason_code == "MEMBERSHIP_NOT_FOUND"
    assert event.organization_id is None
    assert event.membership_id is None


# ------------------------------------------------------ outcome correctness

def test_successful_login_is_not_recorded_as_a_denial():
    """SESSION_ISSUED used to be stored with outcome=denied, which rendered
    every successful sign-in as a critical security event."""
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    identity.create_initial_user("op@example.com", "Op", PASSWORD)
    audit = InMemorySecurityAuditRepository()
    HumanAuthenticationService(users, audit_sink=audit).authenticate("op@example.com", PASSWORD)

    by_type = {event.event_type: event for event in audit.list()}
    assert by_type["human.authentication_succeeded"].outcome is SecurityAuditOutcome.SUCCESS
    assert by_type["session.issued"].outcome is SecurityAuditOutcome.SUCCESS
    for event in audit.list():
        assert derive_severity(event.event_type, event.outcome.value).value != "critical"


def test_failed_login_is_still_recorded_as_a_denial():
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    identity.create_initial_user("op@example.com", "Op", PASSWORD)
    audit = InMemorySecurityAuditRepository()
    service = HumanAuthenticationService(users, audit_sink=audit)
    with pytest.raises(Exception):
        service.authenticate("op@example.com", "WRONG_PASSWORD")

    event = audit.list()[0]
    assert event.event_type == "human.authentication_failed"
    assert event.outcome is SecurityAuditOutcome.DENIED
    assert derive_severity(event.event_type, event.outcome.value).value == "critical"


def test_login_events_carry_the_acting_user():
    users = InMemoryUserRepository()
    identity = HumanIdentityService(users)
    user = identity.create_initial_user("op@example.com", "Op", PASSWORD)
    audit = InMemorySecurityAuditRepository()
    HumanAuthenticationService(users, audit_sink=audit).authenticate("op@example.com", PASSWORD)
    assert all(event.user_id == str(user.user_id) for event in audit.list())
