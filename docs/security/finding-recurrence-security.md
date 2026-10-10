# Finding recurrence security

## MITIGATED

* Requests are rooted in `OrganizationContext`, `assessment_id`, and
  `occurrence_id` and require `assessment.read`.
* History is loaded through organization and endpoint-scoped repository
  operations; cross-tenant and cross-endpoint matches are excluded.
* Fingerprints are derived/validated server-side. Evidence and remediation
  metadata are never returned.
* Historical traversal and recent results are bounded; malformed entries are
  skipped safely.

## PARTIAL

Legacy results may have read-time derived occurrence IDs. Candidate fingerprints
can collide or reflect compromised scanner data, so they are not authority for
authorization or lifecycle decisions. Contradictory database ownership is
excluded defensively rather than repaired.

## DEFERRED

Durable logical finding entities, trusted identity backfills, deduplication,
global search, lifecycle/resolution semantics, scoring, AI similarity, and
distributed reporting controls remain deferred.
