# Finding recurrence

Phase 3M compares the versioned `FindingFingerprint` carried by concrete
finding occurrences. Equality means **candidate recurrence**, not definitive
vulnerability identity. Comparison is endpoint- and organization-scoped and
starts from a server-resolved occurrence; clients cannot submit a fingerprint
digest for searching.

The recurrence read model reports occurrence count, first/last observation in
available retained history, bounded recent occurrence summaries, fingerprint
version, and whether the bounded history is complete. Multiple occurrences in
one assessment are counted separately. Observation time uses a finding time
when present, then assessment completion/request time.

Unresolved or malformed fingerprints do not fall back to title or description
matching. No logical finding table, cache, deduplication, resolution, reopen,
or suppression lifecycle exists. Absence from a later assessment is not
interpreted as resolution because scanner coverage is not yet modeled.
