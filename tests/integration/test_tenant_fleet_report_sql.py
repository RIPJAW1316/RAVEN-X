"""Fleet reporting reads actual tenant predicates and persisted result evidence."""

from datetime import datetime, timezone

import pytest

from backend.application.control_plane import RemoteAssessment, RemoteAssessmentState
from backend.application.organization.context import OrganizationContext
from backend.application.reporting.fleet_report import TenantFleetReportService
from backend.core.database.database import DatabaseManager
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.security import AuthorizationDecision, SecurityPrincipal
from backend.domain.user import UserId
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository
from backend.infrastructure.persistence.sqlalchemy_presence_repository import SQLAlchemyEndpointPresenceRepository
from backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from backend.protocol.agent import AssessmentResultPayload, CorrelationId


NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


class AllowReport:
    def authorize(self, request):
        assert request.action.value == "reports.read"
        return AuthorizationDecision(True)


def test_sql_fleet_report_excludes_other_tenant_and_reads_persisted_evidence(tmp_path):
    config = tmp_path / "report.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: 'report.db'\n", encoding="utf-8")
    database = DatabaseManager(config)
    database.create_tables()
    endpoints = SQLAlchemyEndpointRepository(database)
    assessments = SQLAlchemyRemoteAssessmentRepository(database)
    org, other = OrganizationId.new(), OrganizationId.new()
    own_endpoint = Endpoint(EndpointId.new(), "own-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                            created_at=NOW, organization_id=org)
    foreign_endpoint = Endpoint(EndpointId.new(), "other-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                                created_at=NOW, organization_id=other)
    endpoints.add(own_endpoint)
    endpoints.add(foreign_endpoint)
    for endpoint, owner, assessment_id in ((own_endpoint, org, "own-scan"),
                                            (foreign_endpoint, other, "foreign-scan")):
        payload = AssessmentResultPayload(
            assessment_id, str(endpoint.endpoint_id), "completed", NOW, NOW,
            ({"finding_id": assessment_id + "-finding", "severity": "high", "title": "Firewall off",
              "description": "Public profile disabled", "evidence": [{"source": "firewall", "observed_value": "off"}]},),
            ({"scanner_id": "windows.firewall", "status": "success", "findings": [{}],
              "execution_evidence": {"completeness": "complete"}},))
        assessments.add(RemoteAssessment(assessment_id, endpoint.endpoint_id, CorrelationId(),
                                         ("windows.firewall",), NOW, RemoteAssessmentState.COMPLETED,
                                         result=payload, completed_at=NOW, organization_id=owner))
    user_id = UserId.new()
    principal = SecurityPrincipal.human(user_id)
    context = OrganizationContext(org, "membership", user_id)
    reports = TenantFleetReportService(endpoints, SQLAlchemyEndpointPresenceRepository(database),
                                       assessments, AllowReport(), clock=lambda: NOW)
    report = reports.build(principal, context)
    assert report["summary"]["total_enrolled"] == 1
    assert report["summary"]["scanned"] == 1
    assert report["endpoints"][0]["hostname"] == "own-pc"
    assert report["endpoints"][0]["findings"][0]["evidence"][0]["observed_value"] == "off"
    with pytest.raises(KeyError):
        reports.build(principal, context, assessment_ids=("foreign-scan",))
    with pytest.raises(KeyError):
        reports.build(principal, context, endpoint_id=str(foreign_endpoint.endpoint_id))

    # Exercise SQL LIMIT predicates; these legacy materialization methods
    # must never be used by the production report path.
    def unbounded_query(*args, **kwargs):
        pytest.fail("report used an unbounded repository query")
    endpoints.list_for_organization = unbounded_query
    assessments.list_for_organization = unbounded_query
    reports.presence.list_for_organization = unbounded_query
    assert reports.build(principal, context)["summary"]["scanned"] == 1
    for index in range(2):
        assessments.add(RemoteAssessment(f"more-{index}", own_endpoint.endpoint_id, CorrelationId(),
                                         ("windows.firewall",), NOW, RemoteAssessmentState.QUEUED,
                                         organization_id=org))
    reports.max_history = 2
    with pytest.raises(ValueError, match="history limit exceeded"):
        reports.build(principal, context)
    # An explicit bounded selection remains available even with large history.
    assert reports.build(principal, context, assessment_ids=("own-scan",))["summary"]["scanned"] == 1
    endpoints.add(Endpoint(EndpointId.new(), "second-owned", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                           created_at=NOW, organization_id=org))
    reports.max_endpoints = 1
    with pytest.raises(ValueError, match="endpoint limit exceeded"):
        reports.build(principal, context)
    database.close()
