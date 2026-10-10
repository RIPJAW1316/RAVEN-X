# Durable remote assessments (Phase 2J)

`RemoteAssessment` is the durable control-plane workflow. `AgentWorkItem` remains
the separate delivery record linked by `assessment_id` and `correlation_id`:

```text
RemoteAssessment (workflow truth)
             ↕
AgentWorkItem (delivery truth)
```

The additive `remote_assessments` table stores identity, scanner selection, lifecycle
timestamps, latest progress, structured result, errors, cancellation metadata, and
failure codes. SQLAlchemy and in-memory repositories expose the same minimal port.

Reconciliation is explicit and idempotent. Pending work keeps an assessment queued;
leased work represents delivery in progress; acknowledged work moves the assessment
to running; delivery exhaustion becomes `DELIVERY_FAILED`; work expiration becomes
`EXPIRED`. A completed work item alone never invents a successful assessment result.

Execution results and progress are persisted through JSON-safe protocol mappers, so
completed, failed, queued, running, and cancelled workflows survive control-plane
restart. Agent sessions remain ephemeral and are recreated by authenticated agent
messages.

Implemented: durable assessment repository, restart-safe state, reconciliation,
delivery-failure/expiration propagation, offline queueing when durable delivery is
configured, and structured result/progress persistence.

Partial: assessment/work creation uses safe compensation across separate repository
transactions rather than a single cross-repository transaction. Timeout evaluation is
explicit and does not run a worker.

Deferred: scheduling, durable multi-instance outbox coordination, tenant policy,
RBAC, and event history.
