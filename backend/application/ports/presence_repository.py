"""Persistence boundary for current endpoint presence snapshots."""

from typing import Optional, Protocol, Tuple

from ...domain.presence import EndpointPresence, PresenceState


class EndpointPresenceRepository(Protocol):
    def get(self, endpoint_id: str) -> Optional[EndpointPresence]: ...
    def upsert(self, presence: EndpointPresence) -> EndpointPresence: ...
    def list_for_organization(self, organization_id: str) -> Tuple[EndpointPresence, ...]: ...
