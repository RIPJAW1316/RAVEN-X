from datetime import datetime, timedelta, timezone

from backend.application.endpoint import PresenceMaintenanceRunner, TenantFleetPresenceService
from backend.application.endpoint.presence_service import EndpointPresenceService
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.presence import EndpointPresence, PresencePolicy, PresenceState
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_presence_repository import InMemoryEndpointPresenceRepository


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


class _Allow:
    def authorize(self, request):
        return type("Decision", (), {"allowed": True, "reason_code": "allowed"})()


def test_maintenance_run_once_transitions_and_is_idempotent():
    endpoints = InMemoryEndpointRepository()
    endpoint = Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"), EndpointStatus.ACTIVE, created_at=NOW)
    endpoints.add(endpoint)
    presence = InMemoryEndpointPresenceRepository()
    presence.upsert(EndpointPresence(str(endpoint.endpoint_id), "org", PresenceState.ONLINE, NOW))
    service = EndpointPresenceService(endpoints, presence, policy=PresencePolicy(10, 30, 60))
    runner = PresenceMaintenanceRunner(service, clock=lambda: NOW + timedelta(seconds=30))
    first = runner.run_once()
    assert first.became_stale == 1
    second = runner.run_once()
    assert second.unchanged == 1 and second.became_stale == 0
    offline = PresenceMaintenanceRunner(service, clock=lambda: NOW + timedelta(seconds=60)).run_once()
    assert offline.became_offline == 1


def test_fleet_summary_counts_unknown_and_excludes_revoked():
    endpoints = InMemoryEndpointRepository(); presence = InMemoryEndpointPresenceRepository()
    values = []
    for index, state in enumerate((PresenceState.ONLINE, PresenceState.ONLINE, PresenceState.STALE, PresenceState.OFFLINE, None)):
        ep = Endpoint(EndpointId.new(), f"host-{index}", PlatformInfo("Windows"), EndpointStatus.ACTIVE, created_at=NOW, organization_id="00000000-0000-0000-0000-000000000001")
        endpoints.add(ep); values.append(ep)
        if state is not None:
            presence.upsert(EndpointPresence(str(ep.endpoint_id), str(ep.organization_id), state, NOW))
    revoked = Endpoint(EndpointId.new(), "revoked", PlatformInfo("Windows"), EndpointStatus.REVOKED, created_at=NOW, organization_id="00000000-0000-0000-0000-000000000001")
    endpoints.add(revoked)
    context = type("Context", (), {"organization_id": "00000000-0000-0000-0000-000000000001", "to_dict": lambda self: {"organization_id": self.organization_id}})()
    summary = TenantFleetPresenceService(endpoints, presence, _Allow()).summary(SecurityPrincipal.human("user"), context)
    assert summary.total_endpoints == 5
    assert (summary.online, summary.stale, summary.offline, summary.unknown, summary.revoked) == (2, 1, 1, 1, 1)
