from datetime import datetime, timedelta, timezone

from backend.core.database.database import DatabaseManager
from backend.domain.endpoint import EndpointId
from backend.domain.security import (
    AuthorizationAction, AuthorizationResource, SecurityAuditEvent, SecurityAuditEventType,
    SecurityAuditOutcome, SecurityPrincipal,
)
from backend.infrastructure.persistence.sqlalchemy_security_audit_repository import SQLAlchemySecurityAuditRepository


NOW = datetime(2026, 8, 23, 15, 0, tzinfo=timezone.utc)


def _manager(tmp_path):
    config = tmp_path / "security_audit.yaml"
    database = tmp_path / "security_audit.db"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '" + database.as_posix() + "'\n", encoding="utf-8")
    manager = DatabaseManager(str(config)); manager.initialize_sync_engine(); manager.create_tables()
    return manager, config


def test_sql_audit_persists_filters_orders_and_survives_restart(tmp_path):
    manager, config = _manager(tmp_path)
    repository = SQLAlchemySecurityAuditRepository(manager)
    endpoint = EndpointId.new()
    first = SecurityAuditEvent(event_type=SecurityAuditEventType.ENDPOINT_REVOKED.value, occurred_at=NOW,
                                principal=SecurityPrincipal.system(), action=AuthorizationAction.ENDPOINT_REVOKE,
                                resource=AuthorizationResource("endpoint", str(endpoint), {"endpoint_id": str(endpoint)}),
                                outcome=SecurityAuditOutcome.SUCCESS, endpoint_id=str(endpoint), metadata={"secret": "do-not-store"})
    second = SecurityAuditEvent(event_type=SecurityAuditEventType.ASSESSMENT_COMPLETED.value, occurred_at=NOW + timedelta(seconds=1),
                                 principal=SecurityPrincipal.system(), outcome=SecurityAuditOutcome.SUCCESS,
                                 endpoint_id=str(endpoint), assessment_id="assessment-1")
    repository.append(first); repository.append(second)
    assert repository.list(endpoint_id=endpoint)[0].event_id == first.event_id
    assert repository.list(assessment_id="assessment-1")[0].event_id == second.event_id
    manager.close()
    reloaded = DatabaseManager(str(config)); reloaded.initialize_sync_engine()
    restored = SQLAlchemySecurityAuditRepository(reloaded).get(first.event_id)
    assert restored is not None
    assert restored.metadata["secret"] == "<redacted>"
    assert len(SQLAlchemySecurityAuditRepository(reloaded).list(endpoint_id=endpoint)) == 2
    reloaded.close()
