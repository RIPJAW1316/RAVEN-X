# Finding-detail security

## Mitigated

Assessment-rooted lookups, organization context, per-request RBAC, endpoint
ownership checks, wrong-assessment rejection, bounded findings/evidence, and
secret/remediation metadata filtering prevent common IDOR and disclosure paths.
Malformed findings are skipped rather than failing the complete response.

## Partial

Legacy occurrence IDs are deterministic read-boundary identities because old
result JSON may lack persisted IDs. Contradictory database relationships are
excluded defensively, but database tampering is not prevented by this read
model. Candidate fingerprints can collide and must not drive authorization or
automatic deduplication.

## Deferred

Stable persisted finding tables, migrations/backfills, semantic matching,
deduplication, lifecycle state, global search, exports, and remediation remain
deferred.
