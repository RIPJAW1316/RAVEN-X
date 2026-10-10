from datetime import datetime, timezone

import pytest

from backend.application.assessment import TenantAssessmentService
from backend.application.control_plane import RemoteAssessmentDispatcher, RemoteAssessmentRegistry
from backend.application.endpoint import EndpointRegistry
from backend.application.organization import OrganizationContextResolver, OrganizationMembershipService, OrganizationService
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.application.identity import HumanIdentityService
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_agent_work_repository import InMemoryAgentWorkRepository
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository


NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


def _tenant():
    users = InMemoryUserRepository()
    user = HumanIdentityService(users).create_initial_user("a@example.com", "A", "long-test-password")
    organizations = InMemoryOrganizationRepository()
    org_x = OrganizationService(organizations).create("X")
    org_y = OrganizationService(organizations).create("Y")
    memberships = InMemoryOrganizationMembershipRepository()
    membership = OrganizationMembershipService(memberships, organizations, users).create(user.user_id, org_x.organization_id)
    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(org_x.organization_id, "Analyst", ["assessment.create", "assessment.read", "assessment.cancel"])
    RoleBindingService(bindings, roles, memberships).create(org_x.organization_id, membership.membership_id, role.role_id)
    principal = SecurityPrincipal.human(user.user_id)
    context = OrganizationContextResolver(users, memberships, organizations).resolve(principal, org_x.organization_id)
    endpoints = InMemoryEndpointRepository()
    owned = Endpoint(EndpointId.new(), "x", PlatformInfo("Windows"), status=EndpointStatus.ACTIVE,
                     created_at=NOW, organization_id=org_x.organization_id)
    other = Endpoint(EndpointId.new(), "y", PlatformInfo("Windows"), status=EndpointStatus.ACTIVE,
                     created_at=NOW, organization_id=org_y.organization_id)
    endpoints.add(owned); endpoints.add(other)
    authorizer = OrganizationRbacAuthorizer(membership_repository=memberships, role_binding_repository=bindings,
        role_repository=roles, organization_repository=organizations, endpoint_repository=endpoints)
    work = InMemoryAgentWorkRepository()
    assessments = RemoteAssessmentRegistry()
    dispatcher = RemoteAssessmentDispatcher(EndpointRegistry(endpoints), __import__("backend.application.control_plane", fromlist=["AgentSessionRegistry"]).AgentSessionRegistry(), object(), assessments, work_repository=work)
    service = TenantAssessmentService(endpoints, assessments, dispatcher, authorizer)
    return service, principal, context, owned, other, assessments, work


def test_human_assessment_creation_derives_endpoint_tenant_and_cross_tenant_create_is_hidden():
    service, principal, context, owned, other, assessments, work = _tenant()
    assessment = service.create_assessment(principal, context, owned.endpoint_id, ["windows.firewall"], requested_at=NOW)
    assert assessment.organization_id == owned.organization_id
    queued = work.list_for_endpoint(owned.endpoint_id)[0]
    assert queued.organization_id == owned.organization_id
    with pytest.raises(KeyError):
        service.create_assessment(principal, context, other.endpoint_id, ["windows.firewall"], requested_at=NOW)


def test_legacy_assessment_is_not_visible_to_human_tenant_queries():
    service, principal, context, _owned, _other, assessments, _work = _tenant()
    from backend.application.control_plane import RemoteAssessment, RemoteAssessmentState
    from backend.protocol.agent import CorrelationId
    legacy = RemoteAssessment("legacy", EndpointId.new(), CorrelationId(), ("windows.firewall",), NOW, RemoteAssessmentState.CREATED)
    assessments.add(legacy)
    with pytest.raises(KeyError):
        service.get_assessment(principal, context, legacy.assessment_id)


def test_authenticated_agent_result_chain_rejects_persisted_cross_tenant_corruption():
    service, _principal, _context, owned, _other, assessments, work = _tenant()
    from dataclasses import replace
    from backend.application.control_plane import ControlPlaneAgentHandlers, AgentSessionRegistry, RemoteAssessment, RemoteAssessmentState
    from backend.protocol.agent import CorrelationId
    corrupted = RemoteAssessment("corrupt", owned.endpoint_id, CorrelationId(), ("windows.firewall",), NOW,
                                 RemoteAssessmentState.RUNNING, organization_id=__import__("backend.domain.organization", fromlist=["OrganizationId"]).OrganizationId.new())
    assessments.add(corrupted)
    handlers = ControlPlaneAgentHandlers(AgentSessionRegistry(), assessments, work, endpoint_repository=service.endpoint_repository)
    with pytest.raises(ValueError, match="tenant"):
        handlers._validate_tenant(type("Context", (), {"endpoint_id": owned.endpoint_id})(), corrupted)


def test_agent_poll_does_not_lease_work_with_mismatched_tenant():
    service, _principal, _context, owned, _other, assessments, _work = _tenant()
    from datetime import timedelta
    from backend.infrastructure.persistence.in_memory_agent_work_repository import InMemoryAgentWorkRepository
    from backend.application.control_plane import RemoteAssessment, RemoteAssessmentState
    from backend.domain.agent_work import AgentWorkItem, AgentWorkStatus, WorkId
    from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, CorrelationId
    org_y = __import__("backend.domain.organization", fromlist=["OrganizationId"]).OrganizationId.new()
    assessment = RemoteAssessment("wrong-work", owned.endpoint_id, CorrelationId(), ("windows.firewall",), NOW, RemoteAssessmentState.QUEUED, organization_id=org_y)
    envelope = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, AssessmentDispatch(assessment.assessment_id, owned.endpoint_id, assessment.scanner_ids, NOW).to_dict(), endpoint_id=owned.endpoint_id, timestamp=NOW, correlation_id=assessment.correlation_id)
    repository = InMemoryAgentWorkRepository(endpoint_repository=service.endpoint_repository)
    item = AgentWorkItem(WorkId.new(), owned.endpoint_id, assessment.assessment_id, envelope.message_id, assessment.correlation_id, envelope.message_type.value, str(envelope.protocol_version), envelope.to_dict(), AgentWorkStatus.PENDING, NOW, NOW, organization_id=org_y)
    with pytest.raises(ValueError):
        repository.add(item)
