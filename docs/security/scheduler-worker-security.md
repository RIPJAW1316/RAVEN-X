# Scheduler worker security

**MITIGATED:** bounded schedule targets, recurrence validation, unique run
occurrences, target snapshots, per-target idempotency, organization checks,
interruptible shutdown, and single-worker in-process guarding.

**PARTIAL:** SQLite/process-local coordination does not provide a distributed
lock; operators should enable scheduling on one instance only. A transient DB
outage degrades the worker and is retried at the normal poll interval.

**DEFERRED:** stale claim leases, leader election, distributed rate controls,
remediation/command workers, and generic background-job infrastructure.
