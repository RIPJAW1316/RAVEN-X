"""Application boundary for authenticated endpoint presence updates and reads."""

from dataclasses import replace
from datetime import datetime, timezone

from ...domain.endpoint import EndpointStatus
from ...domain.presence import EndpointPresence, EndpointPresenceEvaluator, PresencePolicy, PresenceState
from ...domain.security import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource


class EndpointPresenceService:
    def __init__(self, endpoint_repository, presence_repository, *, policy=None, clock=None, audit_sink=None, metrics=None):
        self.endpoints = endpoint_repository
        self.presence = presence_repository
        self.policy = policy or PresencePolicy()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.audit_sink = audit_sink
        self.metrics = metrics

    def record_heartbeat(self, endpoint_id, *, receipt_at=None, observed_at=None):
        now = receipt_at or self.clock()
        endpoint = self.endpoints.get(endpoint_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        if endpoint.status is EndpointStatus.REVOKED:
            raise PermissionError("revoked endpoint cannot become present")
        current = self.presence.get(str(endpoint_id))
        if current is None:
            current = EndpointPresence(str(endpoint_id), str(endpoint.organization_id) if endpoint.organization_id else None)
        next_state = PresenceState.ONLINE
        connected_since = current.connected_since or now
        updated = replace(current, organization_id=str(endpoint.organization_id) if endpoint.organization_id else None,
                          state=next_state, last_seen_at=now, last_heartbeat_at=now,
                          connected_since=connected_since, stale_since=None, offline_since=None, updated_at=now)
        self.presence.upsert(updated)
        self._metric("heartbeat.accepted")
        if current.state is not PresenceState.ONLINE:
            self._transition_audit(current.state, next_state, endpoint, now)
        return updated

    def evaluate(self, endpoint_id, *, now=None):
        timestamp = now or self.clock()
        endpoint = self.endpoints.get(endpoint_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        current = self.presence.get(str(endpoint_id)) or EndpointPresence(
            str(endpoint_id), str(endpoint.organization_id) if endpoint.organization_id else None)
        if endpoint.status is EndpointStatus.REVOKED:
            return current
        updated = EndpointPresenceEvaluator.evaluate(current, timestamp, self.policy)
        if updated is not current and updated.state is not current.state:
            latest = self.presence.get(str(endpoint_id))
            if latest is not None and latest.last_seen_at != current.last_seen_at:
                # A heartbeat won the race while this evaluation was in
                # flight; never overwrite its newer server receipt.
                return latest
            self.presence.upsert(updated)
            self._transition_audit(current.state, updated.state, endpoint, timestamp)
            self._metric(f"presence.transition.{updated.state.value}")
        return updated

    def get(self, endpoint_id):
        return self.presence.get(str(endpoint_id))

    def list_for_organization(self, organization_id):
        return self.presence.list_for_organization(str(organization_id))

    def _transition_audit(self, old, new, endpoint, now):
        if self.audit_sink is None or new is PresenceState.UNKNOWN:
            return
        event_name = {PresenceState.ONLINE: SecurityAuditEventType.ENDPOINT_PRESENCE_ONLINE,
                      PresenceState.STALE: SecurityAuditEventType.ENDPOINT_PRESENCE_STALE,
                      PresenceState.OFFLINE: SecurityAuditEventType.ENDPOINT_PRESENCE_OFFLINE}.get(new)
        if event_name:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=event_name.value, principal=SecurityPrincipal.endpoint(endpoint.endpoint_id),
                outcome=SecurityAuditOutcome.SUCCESS, endpoint_id=str(endpoint.endpoint_id),
                organization_id=str(endpoint.organization_id) if endpoint.organization_id else None,
                metadata={"previous_state": old.value, "state": new.value, "observed_at": now.isoformat()},
            ))

    def _metric(self, name, value=1):
        if self.metrics is not None:
            self.metrics.increment(name, value)


class TenantEndpointPresenceService:
    def __init__(self, presence_service, authorizer):
        self.presence_service = presence_service
        self.authorizer = authorizer

    def get(self, principal, context, endpoint_id):
        if principal.principal_type.value != "human":
            raise PermissionError("human context required")
        endpoint = self.presence_service.endpoints.get_for_organization(endpoint_id, context.organization_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.ENDPOINT_READ,
            AuthorizationResource("endpoint", str(endpoint_id), {"organization_id": str(context.organization_id)}),
            organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
        return self.presence_service.get(str(endpoint_id)) or EndpointPresence(
            str(endpoint_id), str(context.organization_id))
