# Endpoint presence security

Presence is evidence of authenticated communication, not evidence of a secure
endpoint. Credential authentication, endpoint binding, freshness, and replay
protection mitigate forged, stale, and replayed heartbeats. Server receipt time
prevents an agent clock from extending liveness indefinitely. Revoked endpoint
records cannot transition back to online.

Tenant ownership is derived from the persisted endpoint record, never from an
agent tenant claim. Cross-organization reads are denied. Database tampering,
compromised valid endpoints, heartbeat-volume denial of service, and false
offline observations remain operational risks requiring later controls.
