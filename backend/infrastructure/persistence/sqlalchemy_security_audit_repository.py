"""Durable append-only SQLAlchemy security audit adapter."""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ...core.database.models import SecurityAuditEventRecord
from ...domain.audit import AuditPage, AuditQuery, derive_severity, view_from_event
from ...domain.security import (
    AuthorizationAction, AuthorizationResource, PrincipalType, SecurityAuditEvent,
    SecurityAuditOutcome, SecurityPrincipal,
)


class SQLAlchemySecurityAuditRepository:
    def __init__(self, database_manager):
        self._database_manager = database_manager

    def append(self, event):
        try:
            with self._database_manager.get_db() as session:
                session.add(_record(event)); session.flush()
        except IntegrityError as error:
            raise ValueError("audit event already exists") from error

    def get(self, event_id):
        with self._database_manager.get_db() as session:
            record = session.get(SecurityAuditEventRecord, str(event_id))
            return _event(record) if record else None

    def list(self, *, event_type=None, endpoint_id=None, assessment_id=None, principal_id=None,
             occurred_after=None, occurred_before=None):
        with self._database_manager.get_db() as session:
            query = select(SecurityAuditEventRecord)
            if event_type is not None: query = query.where(SecurityAuditEventRecord.event_type == event_type)
            if endpoint_id is not None: query = query.where(SecurityAuditEventRecord.endpoint_id == str(endpoint_id))
            if assessment_id is not None: query = query.where(SecurityAuditEventRecord.assessment_id == assessment_id)
            if principal_id is not None: query = query.where(SecurityAuditEventRecord.principal_id == principal_id)
            if occurred_after is not None: query = query.where(SecurityAuditEventRecord.occurred_at >= _store(occurred_after))
            if occurred_before is not None: query = query.where(SecurityAuditEventRecord.occurred_at <= _store(occurred_before))
            records = session.execute(query.order_by(SecurityAuditEventRecord.occurred_at, SecurityAuditEventRecord.event_id)).scalars()
            return tuple(_event(record) for record in records)

    def query_for_organization(self, organization_id, query: AuditQuery) -> AuditPage:
        """Return one page of tenant-owned audit events, newest first.

        Tenant isolation is a mandatory SQL predicate on an indexed column.
        Rows with a NULL organization_id are unattributed system events and are
        excluded: they must not be visible to any tenant.
        """
        owner = str(organization_id)
        if not owner.strip():
            raise ValueError("organization_id is required")
        if not isinstance(query, AuditQuery):
            raise ValueError("query must be an AuditQuery")

        with self._database_manager.get_db() as session:
            conditions = [SecurityAuditEventRecord.organization_id == owner]
            if query.event_types:
                conditions.append(SecurityAuditEventRecord.event_type.in_(list(query.event_types)))
            if query.outcomes:
                conditions.append(SecurityAuditEventRecord.outcome.in_(list(query.outcomes)))
            if query.actor_id:
                conditions.append(SecurityAuditEventRecord.principal_id == query.actor_id)
            if query.endpoint_id:
                conditions.append(SecurityAuditEventRecord.endpoint_id == query.endpoint_id)
            if query.occurred_after is not None:
                conditions.append(SecurityAuditEventRecord.occurred_at >= _store(query.occurred_after))
            if query.occurred_before is not None:
                conditions.append(SecurityAuditEventRecord.occurred_at <= _store(query.occurred_before))
            excluded = query.excluded_event_types
            if excluded:
                conditions.append(SecurityAuditEventRecord.event_type.notin_(list(excluded)))

            if query.severities:
                # Severity is derived, not stored, so it cannot be a SQL
                # predicate. Narrow in SQL first, then filter and page the
                # bounded slice in memory.
                return _severity_page(session, conditions, query)

            total = session.execute(
                select(func.count()).select_from(SecurityAuditEventRecord).where(*conditions)
            ).scalar_one()
            records = session.execute(
                select(SecurityAuditEventRecord)
                .where(*conditions)
                .order_by(SecurityAuditEventRecord.occurred_at.desc(), SecurityAuditEventRecord.event_id.desc())
                .limit(query.limit)
                .offset(query.offset)
            ).scalars()
            return AuditPage(tuple(view_from_event(_event(record)) for record in records),
                             query.limit, query.offset, int(total), excluded)


# Bound on rows inspected when a derived-severity filter is active, so the
# filter cannot be used to force an unbounded scan.
_SEVERITY_SCAN_LIMIT = 2000


def _severity_page(session, conditions, query: AuditQuery) -> AuditPage:
    records = session.execute(
        select(SecurityAuditEventRecord)
        .where(*conditions)
        .order_by(SecurityAuditEventRecord.occurred_at.desc(), SecurityAuditEventRecord.event_id.desc())
        .limit(_SEVERITY_SCAN_LIMIT)
    ).scalars()
    wanted = set(query.severities)
    matched = [record for record in records
               if derive_severity(record.event_type, record.outcome).value in wanted]
    window = matched[query.offset:query.offset + query.limit]
    return AuditPage(tuple(view_from_event(_event(record)) for record in window),
                     query.limit, query.offset, len(matched), query.excluded_event_types)


def _record(event):
    data = event.to_dict()
    event_metadata = dict(event.metadata)
    for key in ("user_id", "organization_id", "membership_id"):
        value = getattr(event, key, None)
        if value is not None:
            event_metadata[key] = value
    return SecurityAuditEventRecord(
        event_id=data["event_id"], event_type=data["event_type"], occurred_at=_store(event.occurred_at),
        principal_type=event.principal.principal_type.value, principal_id=event.principal.principal_id,
        principal_metadata=event.principal.display_metadata,
        action=event.action.value if hasattr(event.action, "value") else event.action,
        resource_type=event.resource.resource_type if event.resource else None,
        resource_id=event.resource.resource_id if event.resource else None,
        resource_metadata=event.resource.metadata if event.resource else None,
        outcome=event.outcome.value, reason_code=event.reason_code, correlation_id=event.correlation_id,
        endpoint_id=event.endpoint_id, assessment_id=event.assessment_id, work_id=event.work_id,
        message_id=event.message_id,
        # Promoted to indexed columns for the tenant feed; also retained in
        # event_metadata so existing readers are unaffected.
        organization_id=event.organization_id, user_id=event.user_id,
        event_metadata=event_metadata,
    )


def _event(record):
    resource = AuthorizationResource(record.resource_type, record.resource_id, record.resource_metadata) if record.resource_type else None
    metadata = record.event_metadata or {}
    return SecurityAuditEvent(
        event_id=record.event_id, event_type=record.event_type, occurred_at=_load(record.occurred_at),
        principal=SecurityPrincipal(PrincipalType(record.principal_type), record.principal_id, record.principal_metadata or {}),
        action=_action(record.action), resource=resource,
        outcome=SecurityAuditOutcome(record.outcome), reason_code=record.reason_code,
        correlation_id=record.correlation_id, endpoint_id=record.endpoint_id, assessment_id=record.assessment_id,
        work_id=record.work_id, message_id=record.message_id,
        # Prefer the promoted columns; fall back to metadata for rows written
        # before the tenancy columns existed.
        user_id=getattr(record, "user_id", None) or metadata.get("user_id"),
        organization_id=getattr(record, "organization_id", None) or metadata.get("organization_id"),
        membership_id=metadata.get("membership_id"), metadata=metadata,
    )


def _store(value): return value.astimezone(timezone.utc).replace(tzinfo=None)
def _load(value): return value.replace(tzinfo=timezone.utc)


def _action(value):
    if not value:
        return None
    try:
        return AuthorizationAction(value)
    except ValueError:
        return value
