"""Persistence port for durable endpoint identity records."""

from typing import Optional, Protocol, Tuple

from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus
from ...domain.organization import OrganizationId


class DuplicateEndpointError(ValueError):
    """Raised when explicit registration would replace an existing identity."""


class EndpointRepository(Protocol):
    def add(self, endpoint: Endpoint) -> None:
        """Persist a new endpoint; duplicate identity must fail explicitly."""

    def get(self, endpoint_id: EndpointId) -> Optional[Endpoint]:
        """Return an endpoint by its stable identity, if present."""

    def list(self, status: Optional[EndpointStatus] = None) -> Tuple[Endpoint, ...]:
        """List endpoint records in deterministic order."""

    def update(self, endpoint: Endpoint) -> None:
        """Replace the mutable state of an existing endpoint identity."""

    def exists(self, endpoint_id: EndpointId) -> bool:
        """Report whether an endpoint identity has been registered."""

    def get_for_organization(self, endpoint_id: EndpointId, organization_id: OrganizationId) -> Optional[Endpoint]: ...
    def list_for_organization(self, organization_id: OrganizationId, status: Optional[EndpointStatus] = None) -> Tuple[Endpoint, ...]: ...
    def exists_for_organization(self, endpoint_id: EndpointId, organization_id: OrganizationId) -> bool: ...
    def query_for_organization(self, organization_id, query, *, presence_repository=None): ...
