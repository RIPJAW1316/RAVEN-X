from datetime import datetime, timezone

from backend.core.database.database import DatabaseManager
from backend.domain.presence import EndpointPresence, PresenceState
from backend.infrastructure.persistence.sqlalchemy_presence_repository import SQLAlchemyEndpointPresenceRepository


def test_presence_snapshot_survives_repository_reload(tmp_path):
    db_path = tmp_path / "presence.db"
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '" + db_path.as_posix() + "'\n", encoding="utf-8")
    manager = DatabaseManager(str(config)); manager.create_tables()
    repository = SQLAlchemyEndpointPresenceRepository(manager)
    timestamp = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    repository.upsert(EndpointPresence("endpoint-1", "org-1", PresenceState.ONLINE, timestamp, timestamp, timestamp, updated_at=timestamp))
    manager.close()
    reopened = DatabaseManager(str(config)); reopened.create_tables()
    restored = SQLAlchemyEndpointPresenceRepository(reopened).get("endpoint-1")
    assert restored.state is PresenceState.ONLINE
    assert restored.organization_id == "org-1"
    reopened.close()
