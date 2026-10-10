# Durable agent work delivery (Phase 2I)

Remote assessment tracking and delivery are separate concerns. A dispatcher creates a
`RemoteAssessment` and, when the durable repository is configured, stores an
`AgentWorkItem` containing the existing `assessment.dispatch` envelope:

```text
RemoteAssessment
      ↓
AgentWorkItem (stable work_id)
      ↓
PENDING → LEASED → ACKNOWLEDGED → COMPLETED / FAILED
                    ↘
                     result/progress recovery
```

Work is partitioned by `EndpointId`. Polling leases only pending work for the
authenticated endpoint. A lease token is returned once, retained only as a hash,
and is required for acknowledgement. Before acknowledgement, an expired lease is
made pending again until `max_attempts` is reached; after that it becomes failed.
Work with an assessment deadline is never delivered after expiration.

Acknowledgement is an explicit `assessment.ack` protocol message sent before local
scanner execution. A valid progress or result message can recover a lost ACK while
the lease is active. Once acknowledged, Phase 2I deliberately does not auto-redeliver
after an agent crash; this conservative rule avoids duplicate execution but means
delivery is not exactly-once.

Phase 2J adds the durable `RemoteAssessment` side of this relationship. Reconciliation
maps pending/leased/acknowledged work to queued/dispatched/running workflow state,
propagates max-attempt exhaustion to `DELIVERY_FAILED`, and propagates pre-execution
expiration to `EXPIRED`. A completed work row does not imply a successful assessment
without an accepted result.

Cancellation before ACK marks the work cancelled and makes it undeliverable. After
ACK it records `CANCEL_REQUESTED` only; no remote stop command exists.

Implemented: domain lifecycle, repository port, in-memory and additive SQLAlchemy
repositories, endpoint-isolated leasing, bounded pre-ACK retries, work expiration,
HTTP poll integration, ACK ownership checks, and an HTTP end-to-end completion test.

Partial: SQLite provides the current persistence boundary. Lease selection is safe
for the current single-process deployment and uses the database transaction, but a
future multi-worker deployment needs an explicit row-lock/claim strategy.

Deferred: durable outbox delivery across multiple control-plane instances, persistent
lease recovery policy, cancellation UI/API, scheduling, tenant policy, and exactly-once
execution claims.
