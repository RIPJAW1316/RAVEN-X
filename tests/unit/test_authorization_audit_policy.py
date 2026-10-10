"""Audit-event policy: routine permission checks are telemetry, denials are audit."""
from datetime import datetime, timezone

import pytest

from backend.application.organization.context import OrganizationContext
from backend.application.rbac import (AuthorizationAuditPolicy, OrganizationRbacAuthorizer,
                                      RoleBindingService, RoleService)
from backend.application.organization import OrganizationMembershipService, OrganizationService
from backend.application.identity import HumanIdentityService
from backend.domain.audit import AuditEventClass, AuditQuery, classify
from backend.domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource,
                                     SecurityPrincipal)
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository

GRANTED = ["endpoint.read", "organization.read"]


class World:
    """Two tenants with one member each, sharing one audit sink."""

    def __init__(self, policy=None, permissions=GRANTED):
        self.users = InMemoryUserRepository()
        identity = HumanIdentityService(self.users)
        self.user = identity.create_initial_user("op@example.com", "Op", "PASSWORD_SENTINEL")
        self.other = identity.create_user("other@example.com", "Other", "PASSWORD_SENTINEL",
                                          principal=SecurityPrincipal.system())
        self.orgs = InMemoryOrganizationRepository()
        self.org_a = OrganizationService(self.orgs).create("A")
        self.org_b = OrganizationService(self.orgs).create("B")
        self.memberships = InMemoryOrganizationMembershipRepository()
        member_service = OrganizationMembershipService(self.memberships, self.orgs, self.users)
        self.membership = member_service.create(self.user.user_id, self.org_a.organization_id)
        self.other_membership = member_service.create(self.other.user_id, self.org_b.organization_id)
        self.roles, self.bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
        role = RoleService(self.roles).create(self.org_a.organization_id, "Role", permissions)
        RoleBindingService(self.bindings, self.roles, self.memberships).create(
            self.org_a.organization_id, self.membership.membership_id, role.role_id)
        self.audit = InMemorySecurityAuditRepository()
        self.authorizer = OrganizationRbacAuthorizer(
            membership_repository=self.memberships, role_binding_repository=self.bindings,
            role_repository=self.roles, organization_repository=self.orgs,
            audit_sink=self.audit, audit_policy=policy)

    @property
    def principal(self):
        return SecurityPrincipal.human(self.user.user_id)

    def context(self, organization=None, membership_id=None, user_id=None):
        return OrganizationContext(
            (organization or self.org_a).organization_id,
            membership_id or str(self.membership.membership_id),
            user_id or self.user.user_id)

    def ask(self, action=AuthorizationAction.ENDPOINT_READ, context=None, resource=None):
        return self.authorizer.authorize(AuthorizationRequest(
            self.principal, action,
            resource or AuthorizationResource("endpoint", None, {}),
            organization_context=context if context is not None else self.context()))

    def events(self, event_type=None):
        return [e for e in self.audit.list() if event_type is None or e.event_type == event_type]


# ------------------------------------------------ routine checks are not audit

def test_successful_permission_check_writes_no_audit_record_by_default():
    world = World()
    for _ in range(20):
        assert world.ask().allowed
    assert world.events("authorization.allowed") == []
    assert world.audit.list() == ()


def test_a_page_load_worth_of_checks_produces_zero_audit_rows():
    """Regression guard for the 95 percent noise problem this policy fixes."""
    world = World()
    for action in (AuthorizationAction.ENDPOINT_READ, AuthorizationAction.ORGANIZATION_READ) * 15:
        assert world.ask(action).allowed
    assert len(world.audit.list()) == 0


def test_diagnostic_policy_restores_the_full_trace():
    world = World(policy=AuthorizationAuditPolicy(record_successful_authorizations=True))
    for _ in range(3):
        assert world.ask().allowed
    allowed = world.events("authorization.allowed")
    assert len(allowed) == 3
    assert all(e.organization_id == str(world.org_a.organization_id) for e in allowed)
    assert all(e.user_id == str(world.user.user_id) for e in allowed)


def test_always_recorded_actions_are_audited_even_when_the_flag_is_off():
    world = World(policy=AuthorizationAuditPolicy(
        always_recorded_actions=frozenset({"organization.read"})))
    assert world.ask(AuthorizationAction.ENDPOINT_READ).allowed
    assert world.ask(AuthorizationAction.ORGANIZATION_READ).allowed
    allowed = world.events("authorization.allowed")
    assert len(allowed) == 1
    assert allowed[0].action is AuthorizationAction.ORGANIZATION_READ


# ------------------------------------------------------- denials remain audit

def test_denied_authorization_is_always_recorded():
    world = World(permissions=["organization.read"])
    decision = world.ask(AuthorizationAction.ENDPOINT_READ)
    assert not decision.allowed
    denied = world.events("authorization.denied")
    assert len(denied) == 1
    assert denied[0].reason_code == "permission_not_granted"


def test_denials_are_recorded_even_under_the_default_suppressing_policy():
    world = World(permissions=["organization.read"])
    for _ in range(5):
        world.ask(AuthorizationAction.ENDPOINT_READ)
    assert len(world.events("authorization.denied")) == 5
    assert world.events("authorization.allowed") == []


def test_policy_cannot_switch_denials_off():
    """There is deliberately no flag for this."""
    policy = AuthorizationAuditPolicy()
    assert not hasattr(policy, "record_denied_authorizations")
    world = World(policy=policy, permissions=["organization.read"])
    world.ask(AuthorizationAction.ENDPOINT_READ)
    assert len(world.events("authorization.denied")) == 1


# ------------------------------------------- denial attribution is trustworthy

def test_verified_denial_is_attributed_so_the_tenant_can_see_probing():
    world = World(permissions=["organization.read"])
    world.ask(AuthorizationAction.ENDPOINT_READ)
    event = world.events("authorization.denied")[0]
    assert event.organization_id == str(world.org_a.organization_id)
    assert event.user_id == str(world.user.user_id)
    assert event.membership_id == str(world.membership.membership_id)


def test_cross_tenant_resource_probe_is_attributed_to_the_probing_tenant():
    world = World()
    resource = AuthorizationResource("endpoint", None,
                                     {"organization_id": str(world.org_b.organization_id)})
    decision = world.ask(resource=resource)
    assert not decision.allowed
    event = world.events("authorization.denied")[0]
    assert event.reason_code == "resource_organization_mismatch"
    # Attributed to the tenant whose member probed, never to the target tenant.
    assert event.organization_id == str(world.org_a.organization_id)


@pytest.mark.parametrize("build_context,expected_reason", [
    (lambda w: None, "organization_context_required"),
    (lambda w: w.context(user_id=w.other.user_id), "principal_context_mismatch"),
    (lambda w: w.context(membership_id=str(w.other_membership.membership_id)),
     "membership_context_mismatch"),
])
def test_unverified_denials_carry_no_attribution(build_context, expected_reason):
    """A caller must not write into a tenant whose membership it has not proven."""
    world = World()
    context = build_context(world)
    if context is None:
        decision = world.authorizer.authorize(AuthorizationRequest(
            world.principal, AuthorizationAction.ENDPOINT_READ,
            AuthorizationResource("endpoint", None, {})))
    else:
        decision = world.ask(context=context)
    assert not decision.allowed
    event = world.events("authorization.denied")[0]
    assert event.reason_code == expected_reason
    assert event.organization_id is None
    assert event.user_id is None


def test_spoofed_organization_never_reaches_the_target_tenant_feed():
    """The whole point of withholding attribution on unverified denials."""
    world = World()
    forged = OrganizationContext(world.org_b.organization_id,
                                 str(world.other_membership.membership_id), world.user.user_id)
    assert not world.ask(context=forged).allowed
    page = world.audit.query_for_organization(world.org_b.organization_id, AuditQuery())
    assert page.total == 0, "a forged context leaked an event into the target tenant"


def test_attribution_is_not_taken_from_caller_supplied_resource_metadata():
    world = World(permissions=["organization.read"])
    resource = AuthorizationResource("endpoint", None, {
        "organization_id": str(world.org_a.organization_id),
        "user_id": "attacker", "membership_id": "attacker"})
    world.ask(AuthorizationAction.ENDPOINT_READ, resource=resource)
    event = world.events("authorization.denied")[0]
    assert event.user_id == str(world.user.user_id)
    assert event.membership_id == str(world.membership.membership_id)


# --------------------------------------------------- authorization unchanged

def test_allow_and_deny_decisions_are_unchanged_by_the_policy():
    """Policy governs auditing only; it must not alter access control."""
    for policy in (None,
                   AuthorizationAuditPolicy(record_successful_authorizations=True),
                   AuthorizationAuditPolicy(always_recorded_actions=frozenset({"endpoint.read"}))):
        world = World(policy=policy)
        assert world.ask(AuthorizationAction.ENDPOINT_READ).allowed
        assert not world.ask(AuthorizationAction.ENDPOINT_REVOKE).allowed


def test_authorizer_without_an_audit_sink_still_authorizes():
    world = World()
    world.authorizer.audit_sink = None
    assert world.ask(AuthorizationAction.ENDPOINT_READ).allowed
    assert not world.ask(AuthorizationAction.ENDPOINT_REVOKE).allowed


# -------------------------------------------------------------- taxonomy

def test_event_classification_matches_the_documented_policy():
    assert classify("authorization.allowed") is AuditEventClass.DIAGNOSTIC
    assert classify("authorization.denied") is AuditEventClass.SECURITY
    assert classify("human.authentication_failed") is AuditEventClass.SECURITY
    assert classify("agent.message_replay_rejected") is AuditEventClass.SECURITY
    assert classify("endpoint.registered") is AuditEventClass.OPERATIONAL
    assert classify("compliance.snapshot.create") is AuditEventClass.OPERATIONAL
