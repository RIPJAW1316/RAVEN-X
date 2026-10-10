# Endpoint presence

Presence is a durable operational snapshot separate from endpoint lifecycle,
agent sessions, assessment state, and security posture:

```text
authenticated heartbeat
        ↓
control-plane receipt time
        ↓
EndpointPresence (SQLite snapshot)
        ↓
UNKNOWN / ONLINE / STALE / OFFLINE
```

The agent timestamp is retained only as protocol observation; `last_seen_at`
uses the server receipt clock. Heartbeats update presence only after existing
credential, endpoint-binding, freshness, replay, and direction checks succeed.
Revoked endpoints cannot be revived. No row-per-heartbeat history is stored.
Presence reads are exposed only through organization-scoped human endpoint
authorization.
