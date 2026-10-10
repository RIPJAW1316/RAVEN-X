from datetime import datetime, timezone, timedelta

from backend.application.reporting import TenantAssessmentDetailService, TenantFindingRecurrenceService
from backend.application.control_plane import RemoteAssessment, RemoteAssessmentState
from backend.application.organization.context import OrganizationContext
from backend.domain.assessment import AssessmentStatus
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.security import SecurityPrincipal
from backend.domain.user import UserId
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_remote_assessment_repository import InMemoryRemoteAssessmentRepository
from backend.protocol.agent import AssessmentResultPayload, CorrelationId

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Allow:
    def authorize(self, request): return type("Decision", (), {"allowed": True})()


def test_recurrence_is_bounded_endpoint_scoped_and_severity_independent():
    org = OrganizationId.new(); endpoint = Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"), created_at=NOW, organization_id=org)
    endpoints = InMemoryEndpointRepository(); endpoints.add(endpoint); assessments = InMemoryRemoteAssessmentRepository()
    for index, severity in enumerate(("high", "critical", "medium")):
        aid = f"assessment-{index}"
        result = AssessmentResultPayload(aid, str(endpoint.endpoint_id), AssessmentStatus.COMPLETED, NOW + timedelta(days=index), NOW + timedelta(days=index),
            ({"severity": severity, "title": f"wording-{index}", "scanner_id": "windows.firewall", "rule_id": "R1", "resource_key": "HKLM/Policy"},), (), None)
        assessments.add(RemoteAssessment(aid, endpoint.endpoint_id, CorrelationId(), ("windows.firewall",), NOW + timedelta(days=index),
                                          RemoteAssessmentState.COMPLETED, organization_id=org, result=result))
    context = OrganizationContext(org, "membership", UserId.new()); principal = SecurityPrincipal.human(context.user_id)
    details = TenantAssessmentDetailService(endpoints, assessments, Allow())
    source = details.get_detail(principal, context, "assessment-2").findings[0]
    recurrence = TenantFindingRecurrenceService(assessments, details, max_assessments=2, recent_limit=2, clock=lambda: NOW)
    report = recurrence.compare(principal, context, "assessment-2", source.occurrence_id)
    assert report.identity_status == "candidate_matchable"
    assert report.occurrence_count == 2
    assert report.history_complete is False
    assert report.recent_occurrences[0].assessment_id == "assessment-2"


def test_unresolved_fingerprint_does_not_match_by_title():
    org = OrganizationId.new(); endpoint = Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"), created_at=NOW, organization_id=org)
    endpoints = InMemoryEndpointRepository(); endpoints.add(endpoint); assessments = InMemoryRemoteAssessmentRepository()
    for aid in ("a", "b"):
        result = AssessmentResultPayload(aid, str(endpoint.endpoint_id), AssessmentStatus.COMPLETED, NOW, NOW,
                                         ({"severity": "high", "title": "same title"},), (), None)
        assessments.add(RemoteAssessment(aid, endpoint.endpoint_id, CorrelationId(), ("windows.firewall",), NOW,
                                         RemoteAssessmentState.COMPLETED, organization_id=org, result=result))
    context = OrganizationContext(org, "membership", UserId.new()); principal = SecurityPrincipal.human(context.user_id)
    details = TenantAssessmentDetailService(endpoints, assessments, Allow())
    occurrence = details.get_detail(principal, context, "a").findings[0].occurrence_id
    report = TenantFindingRecurrenceService(assessments, details).compare(principal, context, "a", occurrence)
    assert report.identity_status == "unresolved"
    assert report.occurrence_count == 1
