from datetime import datetime, timedelta, timezone

from backend.core.database.database import DatabaseManager
from backend.core.database.models import AgentMessageReplayRecord
from backend.infrastructure.persistence.sqlalchemy_replay_guard import SQLAlchemyReplayGuard
from backend.protocol.agent import MessageId


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


def _manager(tmp_path):
    path = tmp_path / "replay.db"
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def test_replay_claim_survives_repository_recreation_and_expiry_purge(tmp_path):
    manager = _manager(tmp_path)
    message_id = MessageId()
    guard = SQLAlchemyReplayGuard(manager)
    assert guard.claim(message_id, "endpoint-a", NOW, NOW + timedelta(minutes=5))
    recreated = SQLAlchemyReplayGuard(manager)
    assert not recreated.claim(message_id, "endpoint-a", NOW, NOW + timedelta(minutes=5))
    assert recreated.purge_expired(NOW + timedelta(minutes=6)) == 1
    assert recreated.claim(message_id, "endpoint-a", NOW + timedelta(minutes=6), NOW + timedelta(minutes=11))
    with manager.get_db() as session:
        assert session.get(AgentMessageReplayRecord, str(message_id)).endpoint_id == "endpoint-a"
