# HTTP agent transport security

## Mitigated

- HTTPS is required by the production client configuration; certificate and hostname verification are enabled by default.
- Agent credentials are presented only in the HTTP Authorization header, never in protocol payloads or server responses.
- Normal messages pass through the existing credential authentication, endpoint binding, freshness, replay, direction, and authorization pipeline.
- Body size and JSON content type are checked before protocol processing.
- Authentication errors are externally shaped without credential details.
- Work queues are partitioned by EndpointId, and work responses are checked against the polling identity.
- No agent inbound port exists.

## Partial

- Bearer credentials can be replayed if stolen until revoked or expired; TLS protects them in transit but does not replace credential rotation.
- HTTP ingress is authenticated, but human/RBAC authorization and tenant scoping remain outside this phase.
- The in-memory outbox leases work but has no durable retry or acknowledgement protocol.

## Deferred

- mTLS and certificate lifecycle
- rate limiting and abuse controls
- durable delivery/retry semantics
- long polling/WebSockets
- secure network enrollment
- compromised control-plane or compromised-agent containment

The test suite uses an in-process ASGI adapter and therefore does not claim to prove TLS cryptography. It verifies the production TLS configuration contract and all application-layer authentication and replay boundaries.
