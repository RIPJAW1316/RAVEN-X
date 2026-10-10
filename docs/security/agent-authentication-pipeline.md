# Authenticated agent-message acceptance pipeline

Phase 2E establishes this in-process, transport-neutral sequence:

```text
Transport input
    ↓
Envelope/payload validation and size limit
    ↓
Protocol version and freshness validation
    ↓
Existing credential verifier
    ↓
Credential ↔ envelope EndpointId binding
    ↓
Endpoint revocation enforcement
    ↓
Inbound direction policy
    ↓
Authorization hook
    ↓
Replay claim
    ↓
Typed router/handler
```

Authentication uses the Phase 2C `EnrollmentService`; no second credential
database or custom message-signing scheme was introduced. `PresentedCredential`
is kept outside normal envelope payloads. The authenticated context contains
only endpoint ID, credential ID, timestamp, and method—not raw secret material.

Replay state is claimed only after authentication, direction, authorization,
and handler availability checks. A successfully claimed message remains
consumed even if its handler later fails; application idempotency is separate.
Exact-message replay is prevented, but logically equivalent messages with
different IDs are not deduplicated.

Enrollment is separate: `EnrollmentMessageProcessor` converts the bootstrap
DTO into the existing `EnrollmentService` flow. Enrollment tokens are not
accepted as normal endpoint credentials.

No HTTP, WebSocket, socket, TLS/mTLS, agent process, command channel, or
authorization/RBAC implementation exists.
