from datetime import datetime, timezone

from sqlalchemy import inspect

from backend.application.control_plane import RemoteAssessment, RemoteAssessmentRegistry, RemoteAssessmentState
from backend.core.database.database import DatabaseManager
from backend.domain.agent_work import AgentWorkItem, AgentWorkStatus, WorkId
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.organization import Organization, OrganizationId
from backend.infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository
from backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, CorrelationId


NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


def _manager(tmp_path):
    config = tmp_path / "assessment_tenant.yaml"
    path = tmp_path / "assessment_tenant.db"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    manager = DatabaseManager(str(config)); manager.initialize_sync_engine(); manager.create_tables()
    return manager, config


def test_remote_assessment_and_work_ownership_survive_reload_and_scope_queries(tmp_path):
    manager, config = _manager(tmp_path)
    org_x, org_y = OrganizationId.new(), OrganizationId.new()
    endpoint_id = EndpointId.new()
    endpoint_repo = SQLAlchemyEndpointRepository(manager)
    endpoint_repo.add(Endpoint(endpoint_id, "tenant-x", PlatformInfo("Windows"), status=EndpointStatus.ACTIVE,
                               created_at=NOW, organization_id=org_x))
    assessments = SQLAlchemyRemoteAssessmentRepository(manager)
    assessment = RemoteAssessment("assessment-x", endpoint_id, CorrelationId(), ("windows.firewall",), NOW,
                                  RemoteAssessmentState.CREATED, organization_id=org_x)
    assessments.add(assessment)
    work_repo = SQLAlchemyAgentWorkRepository(manager, endpoint_repository=endpoint_repo, assessment_repository=assessments)
    envelope = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH,
        AssessmentDispatch(assessment.assessment_id, endpoint_id, assessment.scanner_ids, NOW).to_dict(),
        endpoint_id=endpoint_id, timestamp=NOW, correlation_id=assessment.correlation_id)
    work = AgentWorkItem(WorkId.new(), endpoint_id, assessment.assessment_id, envelope.message_id,
        assessment.correlation_id, envelope.message_type.value, str(envelope.protocol_version), envelope.to_dict(),
        AgentWorkStatus.PENDING, NOW, NOW, organization_id=org_x)
    work_repo.add(work)
    assert assessments.get_for_organization(assessment.assessment_id, org_x).organization_id == org_x
    assert assessments.get_for_organization(assessment.assessment_id, org_y) is None
    assert work_repo.list_for_endpoint_and_organization(endpoint_id, org_x)[0].organization_id == org_x
    assert work_repo.list_for_endpoint_and_organization(endpoint_id, org_y) == ()
    assert {"organization_id"} <= {column["name"] for column in inspect(manager.engine).get_columns("remote_assessments")}
    assert {"organization_id"} <= {column["name"] for column in inspect(manager.engine).get_columns("agent_work_items")}
    manager.close()
    reopened = DatabaseManager(str(config)); reopened.initialize_sync_engine()
    restored = SQLAlchemyRemoteAssessmentRepository(reopened).get_for_organization(assessment.assessment_id, org_x)
    assert restored.organization_id == org_x
    assert SQLAlchemyAgentWorkRepository(reopened).list_for_endpoint_and_organization(endpoint_id, org_x)[0].organization_id == org_x
    reopened.close()
