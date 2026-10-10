"""Append-only security audit persistence boundary."""

from datetime import datetime
from typing import Optional, Protocol, Tuple

from ...domain.audit import AuditPage, AuditQuery
from ...domain.security import SecurityAuditEvent


class SecurityAuditRepository(Protocol):
    def append(self, event: SecurityAuditEvent) -> None: ...
    def get(self, event_id: str): ...
    def list(self, *, event_type: Optional[str] = None, endpoint_id: Optional[str] = None,
             assessment_id: Optional[str] = None, principal_id: Optional[str] = None,
             occurred_after: Optional[datetime] = None, occurred_before: Optional[datetime] = None) -> Tuple[SecurityAuditEvent, ...]: ...

    def query_for_organization(self, organization_id, query: AuditQuery) -> AuditPage:
        """Return one page of redacted, tenant-owned events, newest first.

        Implementations MUST apply the organization predicate at the storage
        layer and MUST exclude events with no organization attribution.
        """
        ...
