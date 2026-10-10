from datetime import datetime, timezone

import pytest

from backend.application.reporting import TenantAssessmentDetailService
from backend.application.control_plane import RemoteAssessment, RemoteAssessmentState
from backend.application.organization.context import OrganizationContext
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.security import SecurityPrincipal
from backend.domain.user import UserId
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_remote_assessment_repository import InMemoryRemoteAssessmentRepository
from backend.protocol.agent import AssessmentResultPayload, CorrelationId
from backend.domain.assessment import AssessmentStatus
from backend.domain.reporting import FindingOccurrenceId, derive_fingerprint

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Allow:
    def authorize(self, request):
        return type("Decision", (), {"allowed": True})()


def test_fingerprint_is_endpoint_scoped_and_not_title_based():
    first = {"scanner_id": "Windows.Firewall", "rule_id": "Rule-1", "resource_key": "HKLM/Policy"}
    second = {**first, "severity": "high", "title": "different wording"}
    a = derive_fingerprint(first, "endpoint-a")
    b = derive_fingerprint(second, "endpoint-a")
    assert a.digest == b.digest
    assert derive_fingerprint(first, "endpoint-b").digest != a.digest
    assert derive_fingerprint({"title": "same title"}, "endpoint-a") is None


def test_detail_service_roots_occurrence_in_assessment_and_redacts_evidence():
    org = OrganizationId.new(); endpoint = Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"), created_at=NOW, organization_id=org)
    endpoints = InMemoryEndpointRepository(); endpoints.add(endpoint)
    assessments = InMemoryRemoteAssessmentRepository()
    result = AssessmentResultPayload("assessment", str(endpoint.endpoint_id), AssessmentStatus.COMPLETED, NOW, NOW,
        ({"severity": "high", "title": "Finding", "details": "details", "scanner_id": "windows.firewall",
          "rule_id": "R1", "resource_key": "HKLM/Policy", "evidence": ({"description": "ok", "password": "SECRET"},),
          "remediation": "powershell -bad"},), (), None)
    assessments.add(RemoteAssessment("assessment", endpoint.endpoint_id, CorrelationId(), ("windows.firewall",), NOW,
                                      RemoteAssessmentState.COMPLETED, organization_id=org, result=result))
    context = OrganizationContext(org, "membership", UserId.new())
    service = TenantAssessmentDetailService(endpoints, assessments, Allow())
    detail = service.get_detail(SecurityPrincipal.human(context.user_id), context, "assessment")
    assert len(detail.findings) == 1
    occurrence = detail.findings[0].occurrence_id
    assert str(FindingOccurrenceId(occurrence)) == occurrence
    assert "SECRET" not in str(detail.to_dict())
    assert "powershell" not in str(detail.to_dict()).lower()
    assert service.get_finding(SecurityPrincipal.human(context.user_id), context, "assessment", occurrence).occurrence_id == occurrence
    with pytest.raises(KeyError):
        service.get_finding(SecurityPrincipal.human(context.user_id), context, "assessment", str(FindingOccurrenceId.derived("other", 0)))
