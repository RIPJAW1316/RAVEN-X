"""SQLAlchemy adapter for the endpoint repository port."""

from typing import Optional, Tuple

from sqlalchemy import select, update, func, or_, and_
from datetime import timezone

from ...application.ports.endpoint_repository import DuplicateEndpointError
from ...core.database.database import DatabaseManager
from ...core.database.models import EndpointRecord
from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus
from ...domain.organization import OrganizationId
from .endpoint_mappers import apply_endpoint_record, endpoint_to_record, record_to_endpoint
from ...core.database.models import EndpointPresenceRecord
from ...domain.fleet import FleetEndpointSummary, FleetPage, FleetSortField, SortDirection
from ...domain.presence import PresenceState


class SQLAlchemyEndpointRepository:
    def __init__(self, database_manager: DatabaseManager):
        self._database_manager = database_manager

    def add(self, endpoint: Endpoint) -> None:
        with self._database_manager.get_db() as session:
            if session.get(EndpointRecord, str(endpoint.endpoint_id)) is not None:
                raise DuplicateEndpointError(f"endpoint {endpoint.endpoint_id} already exists")
            session.add(endpoint_to_record(endpoint))

    def get(self, endpoint_id: EndpointId) -> Optional[Endpoint]:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointRecord, str(endpoint_id))
            return record_to_endpoint(record) if record is not None else None

    def list(self, status: Optional[EndpointStatus] = None) -> Tuple[Endpoint, ...]:
        with self._database_manager.get_db() as session:
            statement = select(EndpointRecord).order_by(EndpointRecord.created_at, EndpointRecord.endpoint_id)
            if status is not None:
                statement = statement.where(EndpointRecord.status == status.value)
            return tuple(record_to_endpoint(record) for record in session.execute(statement).scalars())

    def update(self, endpoint: Endpoint) -> None:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointRecord, str(endpoint.endpoint_id))
            if record is None:
                raise KeyError(f"endpoint {endpoint.endpoint_id} does not exist")
            if record.organization_id != (str(endpoint.organization_id) if endpoint.organization_id else None):
                raise ValueError("endpoint organization ownership is immutable")
            if record.status == EndpointStatus.REVOKED.value and endpoint.status is not EndpointStatus.REVOKED:
                raise ValueError("revoked endpoint cannot be reactivated")
            apply_endpoint_record(record, endpoint)

    def transition_status_for_organization(self, endpoint_id, organization_id, allowed_from, target, updated_at):
        """Claim an approval/revocation transition without reviving a revoked row."""
        endpoint_id = str(EndpointId(str(endpoint_id)))
        organization_id = str(OrganizationId.parse(organization_id))
        allowed = tuple(EndpointStatus(item).value for item in allowed_from)
        target = EndpointStatus(target)
        if updated_at.tzinfo is None or updated_at.utcoffset() is None:
            raise ValueError("updated_at must be timezone-aware")
        stored_at = updated_at.astimezone(timezone.utc).replace(tzinfo=None)
        with self._database_manager.get_db() as session:
            changed = session.execute(update(EndpointRecord).where(
                EndpointRecord.endpoint_id == endpoint_id,
                EndpointRecord.organization_id == organization_id,
                EndpointRecord.status.in_(allowed),
                EndpointRecord.created_at <= stored_at,
            ).values(status=target.value, updated_at=stored_at))
            if changed.rowcount != 1:
                existing = session.execute(select(EndpointRecord).where(
                    EndpointRecord.endpoint_id == endpoint_id,
                    EndpointRecord.organization_id == organization_id,
                )).scalar_one_or_none()
                if existing is None:
                    raise KeyError("endpoint not found")
                raise ValueError("endpoint lifecycle conflict")
            session.flush()
            record = session.get(EndpointRecord, endpoint_id)
            return record_to_endpoint(record)

    def exists(self, endpoint_id: EndpointId) -> bool:
        with self._database_manager.get_db() as session:
            return session.get(EndpointRecord, str(endpoint_id)) is not None

    def get_for_organization(self, endpoint_id: EndpointId, organization_id: OrganizationId) -> Optional[Endpoint]:
        with self._database_manager.get_db() as session:
            record = session.execute(select(EndpointRecord).where(
                EndpointRecord.endpoint_id == str(endpoint_id),
                EndpointRecord.organization_id == str(OrganizationId.parse(organization_id)),
            )).scalar_one_or_none()
            return record_to_endpoint(record) if record is not None else None

    def list_for_organization(self, organization_id: OrganizationId, status: Optional[EndpointStatus] = None) -> Tuple[Endpoint, ...]:
        with self._database_manager.get_db() as session:
            statement = select(EndpointRecord).where(
                EndpointRecord.organization_id == str(OrganizationId.parse(organization_id))
            ).order_by(EndpointRecord.created_at, EndpointRecord.endpoint_id)
            if status is not None:
                statement = statement.where(EndpointRecord.status == status.value)
            return tuple(record_to_endpoint(record) for record in session.execute(statement).scalars())

    def exists_for_organization(self, endpoint_id: EndpointId, organization_id: OrganizationId) -> bool:
        return self.get_for_organization(endpoint_id, organization_id) is not None

    def list_for_organization_bounded(self, organization_id, *, limit):
        if not 1 <= limit <= 501:
            raise ValueError("invalid endpoint report query bound")
        with self._database_manager.get_db() as session:
            records = session.execute(select(EndpointRecord).where(
                EndpointRecord.organization_id == str(OrganizationId.parse(organization_id)),
            ).order_by(EndpointRecord.endpoint_id).limit(limit)).scalars()
            return tuple(record_to_endpoint(record) for record in records)

    def query_for_organization(self, organization_id, query, *, presence_repository=None):
        oid=str(OrganizationId.parse(organization_id))
        with self._database_manager.get_db() as session:
            base=select(EndpointRecord,EndpointPresenceRecord).outerjoin(EndpointPresenceRecord, and_(EndpointPresenceRecord.endpoint_id==EndpointRecord.endpoint_id, or_(EndpointPresenceRecord.organization_id==oid, EndpointPresenceRecord.organization_id.is_(None)))).where(EndpointRecord.organization_id==oid)
            if query.search: base=base.where(EndpointRecord.hostname.ilike(f"%{query.search}%"))
            if query.statuses: base=base.where(EndpointRecord.status.in_([x.value for x in query.statuses]))
            if query.platforms: base=base.where(EndpointRecord.platform.in_(list(query.platforms)))
            if query.architectures: base=base.where(EndpointRecord.architecture.in_(list(query.architectures)))
            if query.agent_versions: base=base.where(EndpointRecord.agent_version.in_(list(query.agent_versions)))
            rows=list(session.execute(base).all()); summaries=[]
            for endpoint,presence in rows:
                state=PresenceState(presence.state) if presence is not None and presence.organization_id in (None,oid) else PresenceState.UNKNOWN
                if query.presence_states and state not in query.presence_states: continue
                summaries.append(FleetEndpointSummary(endpoint.endpoint_id,endpoint.hostname,EndpointStatus(endpoint.status),state,presence.last_seen_at.replace(tzinfo=__import__('datetime').timezone.utc) if presence is not None and presence.last_seen_at and presence.last_seen_at.tzinfo is None else (presence.last_seen_at if presence else None),endpoint.platform,endpoint.platform_version,endpoint.architecture,endpoint.agent_version,endpoint.created_at.replace(tzinfo=__import__('datetime').timezone.utc) if endpoint.created_at.tzinfo is None else endpoint.created_at,endpoint.updated_at.replace(tzinfo=__import__('datetime').timezone.utc) if endpoint.updated_at and endpoint.updated_at.tzinfo is None else endpoint.updated_at))
            def key(x): return {FleetSortField.HOSTNAME:x.hostname.casefold(),FleetSortField.CREATED_AT:x.created_at or "",FleetSortField.UPDATED_AT:x.updated_at or "",FleetSortField.STATUS:x.lifecycle_status.value,FleetSortField.LAST_SEEN:x.last_seen_at or "",FleetSortField.PLATFORM:x.platform.casefold(),FleetSortField.AGENT_VERSION:x.agent_version or ""}[query.sort_by]
            summaries.sort(key=lambda x:(key(x),x.endpoint_id),reverse=query.direction is SortDirection.DESC)
            return FleetPage(tuple(summaries[query.offset:query.offset+query.limit]),query.limit,query.offset,len(summaries))
