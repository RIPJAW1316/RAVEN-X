# HTTP agent transport

Phase 2H introduces the first real transport boundary without changing the protocol contracts.

```text
Agent
  ↓ outbound HTTPS POST /api/v1/agent/messages
Control-plane HTTP ingress
  ↓
AgentMessageEnvelope
  ↓
AgentMessageProcessor
  ↓
Authentication / freshness / replay / direction / typed handler
```

The agent never listens for inbound connections. It submits heartbeat, capability, status, progress, and result envelopes using a Bearer presentation of its endpoint credential. The secret is an HTTP authentication concern and is never placed in the protocol payload.

Work is pull-based:

```text
RemoteAssessmentDispatcher → PendingWorkQueue
Agent --POST /api/v1/agent/work--> Control Plane
Agent <-- {message: assessment.dispatch | null} -- Control Plane
```

The queue is in-memory, partitioned by EndpointId, and leases a dispatch once returned. It intentionally does not claim durable delivery or implement retries. The agent can call `poll_once()` and pass the returned envelope to its existing receiver boundary.

Implemented: HTTP message ingress, work polling, outbound client, credential presentation, explicit timeouts, JSON-only parsing, body-size limits, endpoint isolation, and structured transport errors.

Partial: the integration test uses FastAPI/TestClient through an injected client adapter, so it proves serialization and application boundaries but not TLS cryptography.

Production requirement: `HttpTransportConfig` requires an `https://` URL and enables certificate/hostname verification by default. There is no `verify=False` production default.

Deferred: mTLS, rate limiting, durable outbox/retries, long polling, WebSockets, enrollment over HTTP, scheduling, and external deployment configuration.
