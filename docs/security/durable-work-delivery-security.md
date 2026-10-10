# Durable work delivery security

## Controls implemented

- Work rows are partitioned by endpoint identity; a poll cannot retrieve another
  endpoint's work.
- Lease tokens are random, returned only to the authenticated agent, and stored as
  SHA-256 hashes. ACK ownership checks include endpoint, assessment, correlation,
  work ID, token, status, and lease freshness.
- Expired pre-ACK leases are retried only up to a configured attempt limit. Expired
  work is not delivered.
- Existing credential authentication, protocol freshness, replay protection, and
  message-direction checks remain in front of ACK/progress/result handlers.
- Work envelopes are structured JSON and contain no credential material.

## Partial or deferred risks

- A stolen endpoint credential can poll and submit messages until it is revoked;
  transport TLS and credential rotation remain essential.
- Phase 2I does not claim exactly-once scanner execution. An agent crash after ACK
  intentionally prevents automatic redelivery, while a crash before ACK may cause a
  bounded retry.
- SQLite transaction leasing is adequate for the current local control plane, not a
  substitute for a distributed row-claim protocol.
- Database tampering, cross-instance durable outboxes, rate limiting, audit retention,
  cancellation, and tenant/RBAC authorization are deferred.
