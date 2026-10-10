# Remote assessment state security

## MITIGATED

- Assessment and work identities are linked by endpoint, assessment, and correlation
  identifiers.
- Existing credential authentication, freshness, replay, direction, and endpoint
  ownership checks protect ACK, progress, and result handlers.
- Terminal assessment states reject conflicting updates and duplicate terminal results.
- Cancelled work clears its lease token hash; stale ACKs cannot revive it.
- Results and progress use safe JSON serialization; no pickle or executable payloads
  are persisted.

## PARTIAL

- Cancellation and ACK can race because they occur in separate requests. Pre-ACK
  cancellation is conservative, but an already delivered HTTP response may still be
  executing at the endpoint.
- Separate assessment/work repositories use compensation, not a distributed
  transaction. Reconciliation repairs observable state after restart.
- A compromised authenticated endpoint can submit false results; authorization and
  endpoint trust policy remain limited in this phase.

## DEFERRED

Database tamper evidence, durable audit history, tenant/RBAC authorization, remote
process cancellation, mTLS, scheduling, and multi-control-plane coordination.
