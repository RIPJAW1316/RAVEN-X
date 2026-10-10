"""Additive SQL replay claim adapter."""

from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError

from ...core.database.database import DatabaseManager
from ...core.database.models import AgentMessageReplayRecord
from ...protocol.agent import MessageId


class SQLAlchemyReplayGuard:
    def __init__(self, database_manager: DatabaseManager):
        self._database_manager = database_manager

    def claim(self, message_id: MessageId, endpoint_id, now: datetime, expires_at: datetime) -> bool:
        now = _utc(now)
        expires_at = _utc(expires_at)
        with self._database_manager.get_db() as session:
            session.execute(delete(AgentMessageReplayRecord).where(AgentMessageReplayRecord.expires_at <= _store(now)))
            if session.get(AgentMessageReplayRecord, str(message_id)) is not None:
                return False
            session.add(AgentMessageReplayRecord(
                message_id=str(message_id), endpoint_id=str(endpoint_id),
                first_seen_at=_store(now), expires_at=_store(expires_at),
            ))
            try:
                session.flush()
            except IntegrityError:
                session.rollback()
                return False
            return True

    def purge_expired(self, before: datetime) -> int:
        with self._database_manager.get_db() as session:
            result = session.execute(delete(AgentMessageReplayRecord).where(
                AgentMessageReplayRecord.expires_at <= _store(_utc(before))
            ))
            return int(result.rowcount or 0)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _store(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)
