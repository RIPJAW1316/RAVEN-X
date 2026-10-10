# Endpoint tenant-isolation notes

| Risk | Status | Boundary |
|---|---|---|
| IDOR/cross-tenant endpoint read or revoke | MITIGATED | Context, repository scope, and resource ownership are checked. |
| Raw repository lookup misuse | PARTIAL | Raw `get` remains for machine/internal paths; human service never calls it. |
| Forged organization context | MITIGATED | Active user, membership, and organization are rechecked. |
| Stale RBAC after binding revocation | MITIGATED | Permissions are resolved per request; no cache. |
| Legacy unassigned endpoint leakage | MITIGATED | Tenant queries exclude `NULL` ownership. |
| Agent-supplied tenant claim | MITIGATED | Ownership is derived centrally from the endpoint record. |
| Database tampering / SQLite FK behavior | PARTIAL | Application checks are authoritative; deployment DB controls remain required. |
| Suspended organization | MITIGATED for HUMAN access | Context rejects suspended/revoked organizations. |
| Endpoint transfer | DEFERRED | No transfer or adoption workflow exists. |

Identity, authentication, and tenant authorization remain separate boundaries.
