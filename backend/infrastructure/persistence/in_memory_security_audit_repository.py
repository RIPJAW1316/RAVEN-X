"""Append-only in-memory audit repository for tests."""

from threading import RLock

from ...domain.audit import AuditPage, AuditQuery, derive_severity, view_from_event


class InMemorySecurityAuditRepository:
    def __init__(self):
        self._events = []
        self._ids = set()
        self._lock = RLock()

    def append(self, event):
        with self._lock:
            if str(event.event_id) in self._ids:
                raise ValueError("audit event already exists")
            self._events.append(event)
            self._ids.add(str(event.event_id))

    def get(self, event_id):
        with self._lock:
            return next((event for event in self._events if str(event.event_id) == str(event_id)), None)

    def list(self, *, event_type=None, endpoint_id=None, assessment_id=None, principal_id=None,
             occurred_after=None, occurred_before=None):
        with self._lock:
            values = tuple(self._events)
        return tuple(event for event in values
                     if (event_type is None or event.event_type == event_type)
                     and (endpoint_id is None or event.endpoint_id == str(endpoint_id))
                     and (assessment_id is None or event.assessment_id == assessment_id)
                     and (principal_id is None or event.principal.principal_id == principal_id)
                     and (occurred_after is None or event.occurred_at >= occurred_after)
            and (occurred_before is None or event.occurred_at <= occurred_before))

    def query_for_organization(self, organization_id, query: AuditQuery) -> AuditPage:
        """Mirror of the SQLAlchemy tenant query, including its exclusions."""
        owner = str(organization_id)
        if not owner.strip():
            raise ValueError("organization_id is required")
        if not isinstance(query, AuditQuery):
            raise ValueError("query must be an AuditQuery")
        with self._lock:
            values = tuple(self._events)

        excluded = set(query.excluded_event_types)
        matched = []
        for event in values:
            # Unattributed events belong to no tenant and are never returned.
            if event.organization_id is None or str(event.organization_id) != owner:
                continue
            outcome = getattr(event.outcome, "value", str(event.outcome))
            if event.event_type in excluded:
                continue
            if query.event_types and event.event_type not in query.event_types:
                continue
            if query.outcomes and outcome not in query.outcomes:
                continue
            if query.actor_id and event.principal.principal_id != query.actor_id:
                continue
            if query.endpoint_id and event.endpoint_id != query.endpoint_id:
                continue
            if query.occurred_after is not None and event.occurred_at < query.occurred_after:
                continue
            if query.occurred_before is not None and event.occurred_at > query.occurred_before:
                continue
            if query.severities and derive_severity(event.event_type, outcome).value not in query.severities:
                continue
            matched.append(event)

        matched.sort(key=lambda item: (item.occurred_at, str(item.event_id)), reverse=True)
        window = matched[query.offset:query.offset + query.limit]
        return AuditPage(tuple(view_from_event(item) for item in window),
                         query.limit, query.offset, len(matched), query.excluded_event_types)
