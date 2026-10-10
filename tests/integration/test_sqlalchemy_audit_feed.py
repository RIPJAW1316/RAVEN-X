"""Durable tenant-isolation tests for the audit feed query."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from backend.core.database.database import DatabaseManager
from backend.domain.audit import AuditQuery, AuditSeverity
from backend.domain.organization import OrganizationId
from backend.domain.security import (AuthorizationAction, AuthorizationResource, SecurityAuditEvent,
                                     SecurityAuditOutcome, SecurityPrincipal)
from backend.infrastructure.persistence.sqlalchemy_security_audit_repository import (
    SQLAlchemySecurityAuditRepository)

NOW = datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)


def _manager(tmp_path, name="audit_feed"):
    config = tmp_path / f"{name}.yaml"
    database = tmp_path / f"{name}.db"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '" + database.as_posix() + "'\n",
                      encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager, config


def _event(organization_id, *, event_type="endpoint.registered", outcome=SecurityAuditOutcome.SUCCESS,
           occurred_at=NOW, principal=None, metadata=None, endpoint_id=None):
    return SecurityAuditEvent(
        event_type=event_type, occurred_at=occurred_at,
        principal=principal or SecurityPrincipal.human("11111111-1111-1111-1111-111111111111"),
        action=AuthorizationAction.ENDPOINT_CREATE,
        resource=AuthorizationResource("endpoint", "endpoint-1"),
        outcome=outcome, endpoint_id=endpoint_id,
        organization_id=str(organization_id) if organization_id else None,
        user_id="11111111-1111-1111-1111-111111111111",
        metadata=metadata or {},
    )


def test_tenant_isolation_is_enforced_in_sql(tmp_path):
    manager, _ = _manager(tmp_path)
    repository = SQLAlchemySecurityAuditRepository(manager)
    org_a, org_b = OrganizationId.new(), OrganizationId.new()
    repository.append(_event(org_a, event_type="endpoint.registered"))
    repository.append(_event(org_b, event_type="endpoint.revoked"))
    repository.append(_event(org_b, event_type="assessment.created"))
    repository.append(_event(None, event_type="human.authentication_failed"))

    page_a = repository.query_for_organization(org_a, AuditQuery())
    page_b = repository.query_for_organization(org_b, AuditQuery())

    assert page_a.total == 1
    assert [item.event_type for item in page_a.items] == ["endpoint.registered"]
    assert page_b.total == 2
    assert "endpoint.registered" not in [item.event_type for item in page_b.items]
    manager.close()


def test_organization_predicate_is_present_in_generated_sql(tmp_path):
    """Guard against a refactor that drops the tenant predicate."""
    manager, _ = _manager(tmp_path, "audit_sql")
    repository = SQLAlchemySecurityAuditRepository(manager)
    org = OrganizationId.new()
    repository.append(_event(org))

    statements = []
    engine = manager.engine
    from sqlalchemy import event as sa_event

    @sa_event.listens_for(engine, "before_cursor_execute")
    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    repository.query_for_organization(org, AuditQuery())
    sa_event.remove(engine, "before_cursor_execute", record)

    selects = [item for item in statements if item.strip().upper().startswith("SELECT")]
    assert selects, "expected a SELECT to be issued"
    assert all("organization_id" in item for item in selects)
    manager.close()


def test_newest_first_and_pagination_are_stable(tmp_path):
    manager, _ = _manager(tmp_path, "audit_page")
    repository = SQLAlchemySecurityAuditRepository(manager)
    org = OrganizationId.new()
    for index in range(25):
        repository.append(_event(org, event_type=f"event.{index:02d}",
                                 occurred_at=NOW + timedelta(minutes=index)))

    first = repository.query_for_organization(org, AuditQuery(limit=10, offset=0))
    second = repository.query_for_organization(org, AuditQuery(limit=10, offset=10))

    assert first.total == 25 and first.returned == 10 and first.has_next
    assert first.items[0].event_type == "event.24"
    assert first.items[-1].event_type == "event.15"
    assert second.items[0].event_type == "event.14"
    assert not set(i.event_id for i in first.items) & set(i.event_id for i in second.items)
    manager.close()


def test_filters_narrow_results(tmp_path):
    manager, _ = _manager(tmp_path, "audit_filter")
    repository = SQLAlchemySecurityAuditRepository(manager)
    org = OrganizationId.new()
    actor = SecurityPrincipal.human("22222222-2222-2222-2222-222222222222")
    repository.append(_event(org, event_type="authorization.denied",
                             outcome=SecurityAuditOutcome.DENIED, principal=actor))
    repository.append(_event(org, event_type="endpoint.registered",
                             occurred_at=NOW - timedelta(days=3), endpoint_id="endpoint-9"))

    assert repository.query_for_organization(org, AuditQuery(event_types=("authorization.denied",))).total == 1
    assert repository.query_for_organization(org, AuditQuery(outcomes=("denied",))).total == 1
    assert repository.query_for_organization(org, AuditQuery(actor_id=actor.principal_id)).total == 1
    assert repository.query_for_organization(org, AuditQuery(endpoint_id="endpoint-9")).total == 1
    assert repository.query_for_organization(org, AuditQuery(occurred_after=NOW - timedelta(hours=1))).total == 1

    critical = repository.query_for_organization(org, AuditQuery(severities=("critical",)))
    assert critical.total == 1
    assert critical.items[0].severity is AuditSeverity.CRITICAL
    manager.close()


def test_sensitive_metadata_is_redacted_and_allowlisted_in_the_feed(tmp_path):
    manager, _ = _manager(tmp_path, "audit_redact")
    repository = SQLAlchemySecurityAuditRepository(manager)
    org = OrganizationId.new()
    repository.append(_event(org, metadata={
        "api_token": "super-secret-token",
        "login": "operator@example.com",
        "session_id": "sess-abc",
        "framework_id": "ravenx.windows.baseline",
    }))

    page = repository.query_for_organization(org, AuditQuery())
    serialized = str(page.to_dict())
    assert "super-secret-token" not in serialized
    assert "operator@example.com" not in serialized
    assert "sess-abc" not in serialized
    assert page.items[0].metadata == {"framework_id": "ravenx.windows.baseline"}
    manager.close()


def test_legacy_rows_without_tenancy_columns_are_backfilled(tmp_path):
    """Rows written before the columns existed must remain visible to their owner."""
    manager, config = _manager(tmp_path, "audit_legacy")
    org = OrganizationId.new()
    repository = SQLAlchemySecurityAuditRepository(manager)
    repository.append(_event(org, event_type="endpoint.registered"))

    # Simulate a pre-migration row: tenancy only inside event_metadata.
    with manager.engine.begin() as connection:
        connection.execute(text(
            "UPDATE security_audit_events SET organization_id = NULL, user_id = NULL"))
    assert repository.query_for_organization(org, AuditQuery()).total == 0

    manager.close()
    reloaded = DatabaseManager(str(config))
    reloaded.initialize_sync_engine()
    reloaded.create_tables()  # runs the additive upgrade + backfill
    assert SQLAlchemySecurityAuditRepository(reloaded).query_for_organization(org, AuditQuery()).total == 1
    reloaded.close()


def test_empty_tenant_history_returns_empty_page(tmp_path):
    manager, _ = _manager(tmp_path, "audit_empty")
    page = SQLAlchemySecurityAuditRepository(manager).query_for_organization(
        OrganizationId.new(), AuditQuery())
    assert page.items == () and page.total == 0 and page.has_next is False
    manager.close()


def test_invalid_query_object_is_rejected(tmp_path):
    manager, _ = _manager(tmp_path, "audit_invalid")
    repository = SQLAlchemySecurityAuditRepository(manager)
    with pytest.raises(ValueError):
        repository.query_for_organization(OrganizationId.new(), {"limit": 10})
    with pytest.raises(ValueError):
        repository.query_for_organization("", AuditQuery())
    manager.close()
