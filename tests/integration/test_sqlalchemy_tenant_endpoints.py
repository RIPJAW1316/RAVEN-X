from datetime import datetime, timezone
from sqlalchemy import inspect, create_engine, text

from backend.core.database.database import DatabaseManager
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository


def test_endpoint_organization_persists_and_scoped_queries_are_isolated(tmp_path):
    path = tmp_path / "tenant.db"
    config = tmp_path / "tenant.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    manager = DatabaseManager(str(config)); manager.initialize_sync_engine(); manager.create_tables()
    x, y = OrganizationId.new(), OrganizationId.new()
    repo = SQLAlchemyEndpointRepository(manager)
    now = datetime(2026, 8, 23, tzinfo=timezone.utc)
    ex = Endpoint(EndpointId.new(), "x", PlatformInfo("Windows"), created_at=now, organization_id=x)
    ey = Endpoint(EndpointId.new(), "y", PlatformInfo("Windows"), created_at=now, organization_id=y)
    repo.add(ex); repo.add(ey)
    assert repo.get_for_organization(ex.endpoint_id, x).endpoint_id == ex.endpoint_id
    assert repo.get_for_organization(ex.endpoint_id, y) is None
    assert [item.endpoint_id for item in repo.list_for_organization(x)] == [ex.endpoint_id]
    manager.close()
    reopened = DatabaseManager(str(config)); reopened.initialize_sync_engine()
    restored = SQLAlchemyEndpointRepository(reopened).get_for_organization(ex.endpoint_id, x)
    assert restored.organization_id == x
    assert "organization_id" in {column["name"] for column in inspect(reopened.engine).get_columns("endpoints")}
    reopened.close()


def test_legacy_sqlite_endpoint_schema_gets_narrow_additive_upgrade(tmp_path):
    path = tmp_path / "legacy.db"
    config = tmp_path / "legacy.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    engine = create_engine("sqlite:///%s" % path)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE endpoints (endpoint_id VARCHAR(36) PRIMARY KEY, hostname VARCHAR(255) NOT NULL, platform VARCHAR(100) NOT NULL, status VARCHAR(20) NOT NULL, created_at DATETIME NOT NULL)"))
        conn.execute(text("INSERT INTO endpoints(endpoint_id,hostname,platform,status,created_at) VALUES ('123e4567-e89b-12d3-a456-426614174000','legacy','Windows','new','2026-08-23 00:00:00')"))
    engine.dispose()
    manager = DatabaseManager(str(config)); manager.initialize_sync_engine(); manager.create_tables()
    columns = {column["name"] for column in inspect(manager.engine).get_columns("endpoints")}
    assert "organization_id" in columns
    with manager.get_db() as session:
        row = session.execute(text("SELECT hostname, organization_id FROM endpoints WHERE endpoint_id='123e4567-e89b-12d3-a456-426614174000'" )).one()
        assert row.hostname == "legacy" and row.organization_id is None
    manager.close()
