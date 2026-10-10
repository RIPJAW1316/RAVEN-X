# Endpoint enrollment and trust boundary (Phase 2C)

The local trust model now separates four concepts:

```text
Enrollment Authorization (one-time bootstrap secret)
        ↓ verify once
Endpoint identity (new Raven-X EndpointId)
        ↓ issue once
Machine credential (long-lived verifier-backed identity proof)
        ↓ future transport
Authentication (deferred)
        ↓ separate policy
Authorization (deferred)
```

## Implemented

- `EnrollmentAuthorization` has `PENDING`, `CONSUMED`, `EXPIRED`, and
  `REVOKED` lifecycle states and timezone-aware expiry metadata.
- Enrollment uses **Pattern B**: a successful authorization creates a new
  `EndpointId`; endpoint binding is explicit in the enrollment result.
- Bootstrap and machine secrets use cryptographically secure URL-safe random
  values. Only salted `scrypt` verifiers are stored. Raw values are returned
  through a redacted `IssuedSecret` exactly once.
- `EndpointCredential` has explicit active, rotated, revoked, and expired
  states. Rotation adds a replacement and invalidates the old credential;
  revocation preserves history.
- SQLAlchemy enrollment completion consumes the authorization and inserts the
  endpoint and credential in one database transaction. The in-memory adapter
  provides the same contract for isolated unit tests.
- Credential verification checks the endpoint lifecycle first, then verifier,
  expiry, and credential state. A valid credential proves identity only; it
  grants no command or remediation authority.

## Partial / deferred

- SQLite's `FOR UPDATE` is advisory; production concurrent-consumption
  guarantees require a database with row-locking or an equivalent conditional
  update. The repository operation is nevertheless transaction-shaped and
  sequential reuse is rejected.
- Machine metadata and capabilities are recorded as unverified enrollment
  claims. Server-side capability validation is deferred.
- No HTTP endpoint, WebSocket, agent process, heartbeat, certificate/mTLS,
  organization scope, RBAC, or authorization policy exists in this phase.

## Threat boundary

The model reduces accidental secret disclosure and token replay after a
successful consume, but it does not establish transport trust. Stolen tokens,
stolen credential material, cloned machines, forged metadata/capabilities,
replay at an unimplemented transport layer, and database theft require later
enrollment UX, authenticated protocol, key protection, and policy controls.
