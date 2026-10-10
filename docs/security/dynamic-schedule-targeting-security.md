# Dynamic schedule targeting security

* **MITIGATED:** target references are discriminated, tenant-owned, active,
  bounded, and revalidated at execution. Group corruption and revoked/missing
  endpoints are excluded from dispatch. Scope resolution reuses the established
  tenant fleet-query path.
* **MITIGATED:** durable run snapshots prevent crash/re-resolution drift and
  preserve historical target truth. Oversized targets fail explicitly rather
  than being truncated.
* **PARTIAL:** multi-instance scheduler coordination remains absent, although
  schedule-run occurrence uniqueness and snapshots reduce duplicate execution.
* **DEFERRED:** generic scheduling, remediation/command/compliance targets,
  nested groups, Boolean scope composition, and distributed leader election.
