"""Tenant-scoped operational fleet presence summary."""

from dataclasses import dataclass

from ...domain.endpoint import EndpointStatus
from ...domain.presence import EndpointPresence, PresenceState
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource


@dataclass(frozen=True)
class FleetPresenceSummary:
    organization_id: str
    total_endpoints: int
    unknown: int
    online: int
    stale: int
    offline: int
    revoked: int = 0

    def to_dict(self):
        return {"organization_id": self.organization_id, "total_endpoints": self.total_endpoints,
                "unknown": self.unknown, "online": self.online, "stale": self.stale,
                "offline": self.offline, "revoked": self.revoked}


class TenantFleetPresenceService:
    def __init__(self, endpoint_repository, presence_repository, authorizer):
        self.endpoints = endpoint_repository
        self.presence = presence_repository
        self.authorizer = authorizer

    def summary(self, principal, context):
        self._authorize(principal, context)
        endpoints = self.endpoints.list_for_organization(context.organization_id)
        snapshots = {item.endpoint_id: item for item in self.presence.list_for_organization(context.organization_id)}
        counts = {state: 0 for state in PresenceState}
        revoked = 0
        for endpoint in endpoints:
            if endpoint.status is EndpointStatus.REVOKED:
                revoked += 1
                continue
            counts[(snapshots.get(str(endpoint.endpoint_id)) or EndpointPresence(str(endpoint.endpoint_id), str(context.organization_id))).state] += 1
        return FleetPresenceSummary(str(context.organization_id), sum(counts.values()), counts[PresenceState.UNKNOWN],
                                    counts[PresenceState.ONLINE], counts[PresenceState.STALE], counts[PresenceState.OFFLINE], revoked)

    def _authorize(self, principal, context):
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.ENDPOINT_READ,
            AuthorizationResource("fleet_presence", metadata={"organization_id": str(context.organization_id)}),
            organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
