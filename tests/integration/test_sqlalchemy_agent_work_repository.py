from datetime import timedelta

from backend.infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from backend.domain.agent_work import AgentWorkStatus
from backend.core.database.database import DatabaseManager

from tests.unit.test_agent_work_repository import NOW, _item


def _manager(tmp_path):
    config = tmp_path / "agent_work.yaml"
    database = tmp_path / "agent_work.db"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '" + database.as_posix() + "'\n", encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager, config


def test_sqlalchemy_work_survives_repository_reload_and_tracks_lease_state(tmp_path):
    manager, config = _manager(tmp_path)
    item = _item()
    repository = SQLAlchemyAgentWorkRepository(manager)
    repository.add(item)
    leased = repository.lease_next(item.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1),
                                   max_attempts=3, retry_delay=timedelta())
    assert leased.item.status is AgentWorkStatus.LEASED
    repository.acknowledge(item.work_id, item.endpoint_id, leased.lease_token,
                           assessment_id=item.assessment_id, correlation_id=item.correlation_id,
                           now=NOW)
    manager.close()

    reloaded = DatabaseManager(str(config))
    reloaded.initialize_sync_engine()
    restored = SQLAlchemyAgentWorkRepository(reloaded).get(item.work_id)
    assert restored is not None
    assert restored.status is AgentWorkStatus.ACKNOWLEDGED
    assert restored.attempt_count == 1
    completed = SQLAlchemyAgentWorkRepository(reloaded).complete(
        item.endpoint_id, item.assessment_id, item.correlation_id, now=NOW + timedelta(seconds=1)
    )
    assert completed.status is AgentWorkStatus.COMPLETED
    reloaded.close()


def test_sqlalchemy_work_expired_lease_is_requeued_before_ack(tmp_path):
    manager, config = _manager(tmp_path)
    item = _item()
    repository = SQLAlchemyAgentWorkRepository(manager)
    repository.add(item)
    repository.lease_next(item.endpoint_id, now=NOW, lease_duration=timedelta(seconds=1),
                          max_attempts=2, retry_delay=timedelta())
    manager.close()
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    repository = SQLAlchemyAgentWorkRepository(manager)
    changed = repository.release_expired_leases(now=NOW + timedelta(seconds=2), max_attempts=2, retry_delay=timedelta())
    assert changed[0].status is AgentWorkStatus.PENDING
    assert repository.lease_next(item.endpoint_id, now=NOW + timedelta(seconds=2), lease_duration=timedelta(seconds=1),
                                 max_attempts=2, retry_delay=timedelta()) is not None
    manager.close()
