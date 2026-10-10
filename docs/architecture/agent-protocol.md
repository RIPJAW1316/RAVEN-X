# Versioned endpoint-agent protocol

Phase 2D defines messages without choosing a transport:

```text
Endpoint Agent
      ↕
Message Envelope
      ↕
Typed JSON-safe Payload
      ↕
Future Control Plane
```

## Implemented

- `ProtocolVersion` accepts `major.minor`; major `1` is currently supported,
  while unknown major versions are rejected.
- `AgentMessageEnvelope` carries message ID, type, protocol version, optional
  endpoint ID, timestamp, correlation ID, nonce, and a typed payload mapping.
- Heartbeat, capability report, agent status, enrollment request/response,
  assessment dispatch/progress/result, and protocol error payload contracts are
  defined.
- Dispatch messages use stable scanner IDs and map explicitly to the existing
  `AssessmentOptions` contract. They cannot carry code, PowerShell, or AI
  commands.
- Finding/evidence/scanner-result data is converted to JSON-safe structures;
  no ORM or transport types are imported by the protocol package.
- Configurable freshness/clock-skew and payload-size validation are provided.
- `InMemoryReplayGuard` establishes the replay-protection port without Redis or
  another distributed dependency.
- Message directions and a duplicate-rejecting message registry are defined.

## Secret boundary

Enrollment request/response DTOs are bootstrap-sensitive. Their default
`repr()` and `to_dict()` redact raw token/credential values. An explicit
`to_wire_dict()` is required for the future enrollment transport boundary.
Normal authenticated messages contain no reusable credential field. Protocol
validation does not authenticate an endpoint and does not authorize actions.

## Partial / deferred

- No HTTP, WebSocket, socket, TLS/mTLS, polling, queue, agent process, or
  command channel exists.
- Replay storage is in-memory only; durable/distributed replay protection is
  deferred to transport/control-plane implementation.
- Payload parsing is strict for envelope structure but additive optional-field
  compatibility and negotiated protocol capability exchange are deferred.
- Authentication must later verify that credential identity equals the claimed
  endpoint ID before accepting messages.
