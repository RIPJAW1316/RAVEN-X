# Tenant security overview

Phase 3K provides a read-only, on-demand `TenantSecurityOverviewService` and
the tenant-explicit route
`GET /api/v1/organizations/{organization_id}/security/overview`.

The service requires a human `OrganizationContext` and both `endpoint.read`
and `assessment.read`. It reads organization-owned endpoints, persisted
presence snapshots, and organization-owned remote assessments. Findings are
derived through those assessments; legacy global vulnerability rows are not
queried.

Endpoint and presence summaries reuse the established Phase 3J semantics.
Assessment counts use the existing workflow state values. Finding totals are
**occurrence counts**, not unique vulnerabilities. Unknown severities are
placed in `unknown`. Recent assessments and critical/high finding occurrences
are bounded lists, sorted deterministically.

The response contains summaries only: evidence blobs and legacy remediation
metadata (including PowerShell guidance) are excluded. No risk score,
compliance score, AI summary, cache, export, scheduler, or report table is
introduced. Reports are read models and may observe normal cross-repository
read consistency boundaries; presence maintenance is not triggered by a read.

Malformed finding entries are skipped and counted diagnostically. Corrupted or
legacy assessments without an organization are excluded from tenant reports.
