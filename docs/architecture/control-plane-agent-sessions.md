# Control-plane agent sessions

Phase 2G adds an in-memory control-plane session boundary for the local agent runtime.

```text
Authenticated agent message
        ↓
AgentMessageProcessor (Phase 2E)
        ↓
ControlPlaneAgentHandlers
        ↓
AgentSessionRegistry (ephemeral)
```

`Endpoint` remains the durable identity. `AgentSession` is a short-lived connection/runtime observation keyed by `EndpointId`; it is not an endpoint record and is not persisted. A session can be `CONNECTED`, `READY`, `BUSY`, `DEGRADED`, or `DISCONNECTED`. Active duplicate sessions are rejected, while an explicitly disconnected identity may reconnect.

Heartbeat, capability, status, progress, and result messages are accepted only through the existing authenticated message processor. The in-process duplex transport is a transport seam: control-plane dispatches are envelopes delivered to the agent receiver, and agent reports are envelopes delivered back to the authenticated processor. There are no sockets or implicit direct control-to-agent calls.

Implemented: one in-process session and transport implementation, session freshness marking, authenticated lifecycle handlers, and session-isolated remote assessment tracking.

Partial: sessions are process-memory only; there is no connection manager, scheduler, heartbeat timer, or network transport.

Deferred: HTTP/WebSocket/gRPC transport, durable session history, organizations, RBAC, enrollment orchestration, and fleet coordination.
