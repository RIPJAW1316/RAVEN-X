from datetime import datetime, timezone

from backend.application.control_plane.assessment_dispatch import RemoteAssessment, RemoteAssessmentState
from backend.application.reporting import TenantSecurityOverviewService
from backend.domain.assessment import AssessmentStatus
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.presence import EndpointPresence, PresenceState
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_presence_repository import InMemoryEndpointPresenceRepository
from backend.infrastructure.persistence.in_memory_remote_assessment_repository import InMemoryRemoteAssessmentRepository
from backend.protocol.agent import AssessmentResultPayload, CorrelationId
from backend.application.organization.context import OrganizationContext
from backend.domain.user import UserId


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class AllowAll:
    def authorize(self, request):
        class Decision:
            allowed = True
        return Decision()


def test_overview_is_tenant_scoped_and_counts_occurrences():
    org = OrganizationId.new()
    endpoint_repo = InMemoryEndpointRepository()
    presence_repo = InMemoryEndpointPresenceRepository()
    assessment_repo = InMemoryRemoteAssessmentRepository()
    endpoint = Endpoint(EndpointId.new(), "host-a", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        organization_id=org, created_at=NOW)
    endpoint_repo.add(endpoint)
    presence_repo.upsert(EndpointPresence(str(endpoint.endpoint_id), str(org), PresenceState.ONLINE, NOW, NOW))
    assessment = RemoteAssessment("a-1", endpoint.endpoint_id, CorrelationId(), ("windows.firewall",), NOW,
                                  RemoteAssessmentState.COMPLETED, organization_id=org,
                                  result=AssessmentResultPayload("a-1", str(endpoint.endpoint_id), AssessmentStatus.COMPLETED,
                                                                  NOW, NOW,
                                                                  ({"severity": "critical", "title": "Firewall", "details": "x",
                                                                    "legacy_metadata": {"powershell_command": "bad"}},), (), None))
    assessment_repo.add(assessment)
    context = OrganizationContext(org, "membership", UserId.new())
    overview = TenantSecurityOverviewService(endpoint_repo, presence_repo, assessment_repo, AllowAll(), clock=lambda: NOW).overview(
        SecurityPrincipal.human(context.user_id), context)
    data = overview.to_dict()
    assert data["endpoints"]["total_endpoints"] == 1
    assert data["presence"]["online"] == 1
    assert data["findings"]["critical"] == 1
    assert data["recent_high_severity_findings"][0]["title"] == "Firewall"
    assert "powershell_command" not in str(data)


def test_malformed_findings_are_skipped_and_recent_list_is_bounded():
    org = OrganizationId.new()
    endpoint_repo = InMemoryEndpointRepository(); presence_repo = InMemoryEndpointPresenceRepository()
    assessments = InMemoryRemoteAssessmentRepository(); endpoint = Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"), organization_id=org, created_at=NOW)
    endpoint_repo.add(endpoint)
    for index in range(3):
        aid = f"a-{index}"
        result = AssessmentResultPayload(aid, str(endpoint.endpoint_id), AssessmentStatus.COMPLETED, NOW, NOW,
                                          ({"severity": "not-a-severity", "title": "unknown"}, object()), (), None)
        assessments.add(RemoteAssessment(aid, endpoint.endpoint_id, CorrelationId(), ("windows.firewall",), NOW,
                                         RemoteAssessmentState.COMPLETED, organization_id=org, result=result))
    context = OrganizationContext(org, "membership", UserId.new())
    report = TenantSecurityOverviewService(endpoint_repo, presence_repo, assessments, AllowAll(), recent_limit=2).overview(
        SecurityPrincipal.human(context.user_id), context)
    assert len(report.recent_assessments) == 2
    assert report.malformed_finding_count == 3
    assert report.findings.unknown == 3
