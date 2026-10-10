"""SQLAlchemy adapter for current endpoint presence snapshots."""

from sqlalchemy import select
from datetime import timezone

from ...core.database.database import DatabaseManager
from ...core.database.models import EndpointPresenceRecord
from ...domain.presence import EndpointPresence, PresenceState


class SQLAlchemyEndpointPresenceRepository:
    def __init__(self, database_manager: DatabaseManager):
        self._database_manager = database_manager

    def get(self, endpoint_id):
        with self._database_manager.get_db() as session:
            record = session.get(EndpointPresenceRecord, str(endpoint_id))
            return _from_record(record) if record else None

    def upsert(self, presence):
        with self._database_manager.get_db() as session:
            record = session.get(EndpointPresenceRecord, str(presence.endpoint_id))
            if record is None:
                record = EndpointPresenceRecord(endpoint_id=str(presence.endpoint_id))
                session.add(record)
            _apply(record, presence)
            return presence

    def list_for_organization(self, organization_id):
        with self._database_manager.get_db() as session:
            rows = session.execute(select(EndpointPresenceRecord).where(
                EndpointPresenceRecord.organization_id == str(organization_id)
            ).order_by(EndpointPresenceRecord.endpoint_id)).scalars()
            return tuple(_from_record(row) for row in rows)

    def list_all(self):
        with self._database_manager.get_db() as session:
            rows = session.execute(select(EndpointPresenceRecord).order_by(EndpointPresenceRecord.endpoint_id)).scalars()
            return tuple(_from_record(row) for row in rows)

    def list_for_endpoints_and_organization(self, organization_id, endpoint_ids):
        if len(endpoint_ids) > 500:
            raise ValueError("invalid presence query bound")
        if not endpoint_ids:
            return ()
        with self._database_manager.get_db() as session:
            rows = session.execute(select(EndpointPresenceRecord).where(
                EndpointPresenceRecord.organization_id == str(organization_id),
                EndpointPresenceRecord.endpoint_id.in_(tuple(str(value) for value in endpoint_ids)),
            ).limit(len(endpoint_ids))).scalars()
            return tuple(_from_record(row) for row in rows)


def _apply(record, presence):
    record.organization_id = presence.organization_id
    record.state = presence.state.value
    record.last_seen_at = presence.last_seen_at
    record.last_heartbeat_at = presence.last_heartbeat_at
    record.connected_since = presence.connected_since
    record.stale_since = presence.stale_since
    record.offline_since = presence.offline_since
    record.updated_at = presence.updated_at


def _from_record(record):
    return EndpointPresence(record.endpoint_id, record.organization_id, PresenceState(record.state),
                             *(_utc(value) for value in (record.last_seen_at, record.last_heartbeat_at,
                               record.connected_since, record.stale_since, record.offline_since, record.updated_at)))


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value
