# Assessment tenant-isolation notes

| Risk | Status | Control |
|---|---|---|
| Assessment IDOR/read/cancel | MITIGATED | Tenant queries and RBAC protect HUMAN operations. |
| Forged organization IDs | MITIGATED | Ownership derives from the endpoint; agents carry no tenant authority claim. |
| Cross-tenant work routing | MITIGATED | Work inherits assessment ownership and polling remains endpoint-scoped. |
| Endpoint/assessment mismatch | MITIGATED | Agent handlers validate persisted ownership. |
| Assessment/work mismatch | MITIGATED | Dispatcher and repository validators reject inconsistency. |
| Compromised valid agent | PARTIAL | Credential, endpoint, correlation, replay, and tenant checks apply. |
| Legacy NULL assessment/work | MITIGATED for HUMAN access | Tenant queries exclude unassigned rows. |
| Raw repository misuse | PARTIAL | Global lookup remains for internal processing. |
| Migration ambiguity | MITIGATED | Backfill occurs only when ownership is unambiguous. |
| Assessment transfer | DEFERRED | No transfer/adoption workflow exists. |
