# Reporting tenant-isolation notes

## Mitigated now

* Human reporting is rooted in `OrganizationContext` and requires both
  `endpoint.read` and `assessment.read`.
* Endpoint and assessment repositories are queried by organization; findings
  are traversed only through tenant-owned assessments.
* Legacy `NULL`-organization assessments and malformed finding entries do not
  enter a tenant report.
* Assessments whose endpoint does not belong to the same tenant are excluded
  defensively if contradictory/corrupted state is encountered.
* Responses are bounded and omit evidence blobs, credentials, and remediation
  / PowerShell metadata.
* No report route performs writes, maintenance, remediation, or command
  execution.

## Partial

* The read model is computed on demand and is not a serializable snapshot of
  every table. Presence freshness depends on the separately controlled
  maintenance run.
* Assessment result JSON is currently traversed through the existing
  repository object API; large-history scalability remains limited.

## Deferred

Risk/compliance scoring, stable finding deduplication, historical snapshots,
global search, exports, caching, analytics query languages, and additional
rate/DoS controls are intentionally deferred. Audit remains the durable
security history; operational logs/metrics are not a substitute for it.
