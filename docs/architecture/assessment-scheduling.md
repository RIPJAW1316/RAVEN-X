# Assessment scheduling (Phase 3R)

Assessment schedules are tenant-owned policies, not executable jobs:

```text
AssessmentSchedule → ScheduleRun → RemoteAssessment → AgentWorkItem
```

The schedule domain supports bounded daily, weekly, and interval recurrence in
an explicit IANA timezone. Timestamps are persisted in UTC. Missed occurrences
use `COALESCE`: one due run is created and the next future occurrence is
calculated; downtime does not create a catch-up storm.

`DAILY` and `WEEKLY` use wall-clock calendar occurrences in the selected
timezone; `INTERVAL` is expressed in hours. Zoneinfo supplies DST behavior.

Only explicit endpoint IDs are accepted. Targets are revalidated at execution;
revoked endpoints are skipped, while offline endpoints follow the existing
durable work policy. A schedule run uses `SKIP_IF_ACTIVE` for overlapping
scheduled assessments. Manual assessments remain unchanged and have no
`schedule_id`.

`AssessmentScheduleRunner.run_once()` is the only execution primitive in this
phase. It is bounded by a batch size and is not automatically started as a
background service. Schedule administration is human, organization-context
and RBAC protected; due execution is an internal/system operation.

Implemented: domain, in-memory/SQLAlchemy persistence, tenant CRUD/lifecycle,
run idempotency marker, ordinary assessment dispatch integration.

Partial: process-local runner and outbox semantics are not leader-elected or
cluster-safe. A durable run marker reduces restart duplication, but separate
control-plane instances can still race.

Deferred: cron, dynamic fleet queries, scheduler workers/queues, run-history
HTTP API, distributed coordination, remediation/command/AI/compliance
scheduling.
