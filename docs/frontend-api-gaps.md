# Frontend API gaps

Capabilities the enterprise UI needs that the control plane does not currently
expose. Each entry records what the UI wanted, what it does instead, and what a
backend implementation would have to provide.

**Rule applied throughout:** where no route exists, the interface states the
gap. It does not synthesise values, call an untenanted legacy route, or render
controls that cannot work.

---

## GAP-1 — Scanner discovery

| | |
|---|---|
| **Feature** | Choosing scanners when dispatching an assessment or creating a schedule |
| **Required endpoint** | `GET /api/v1/organizations/{organization_id}/scanners` |
| **Expected data** | `[{ scanner_id, name, description, required_capabilities[], status }]` |
| **Backend status** | **Missing.** `ScannerRegistry` exists in `backend/application/scanner/registry.py` and adapters are registered in `legacy_adapters.py`, but no HTTP route exposes the catalogue. |
| **Current behaviour** | `frontend/src/lib/scanners.ts` holds a hard-coded catalogue of the four adapters that are actually registered (`windows.firewall`, `windows.uac`, `windows.smb`, `windows.bitlocker`). The dispatch UI labels this explicitly as a client-side constant. |
| **Recommended implementation** | Expose the existing registry through a tenant-scoped read route guarded by an `assessment.create` or `endpoint.read` permission. Then delete the constant from `scanners.ts` and replace `KNOWN_SCANNERS` with the API call. |

Without this, the UI cannot know when a scanner is added, removed, or
unavailable on a given platform.

---

## GAP-2 — Tenant-scoped AI analysis

| | |
|---|---|
| **Feature** | AI Security Analyst: interpretation of a finding in operator language |
| **Required endpoint** | `POST /api/v1/organizations/{org}/assessments/{assessment_id}/findings/{occurrence_id}/analysis` |
| **Expected data** | `{ what_happened, why_it_matters, likely_impact, recommended_action, rationale, confidence: "low"\|"medium"\|"high", evidence_references[] }` |
| **Backend status** | **Missing for the enterprise control plane.** A legacy router exists at `/api/v1/analysis/*` (`backend/api/v1/analysis.py`) but it is unauthenticated, carries no organization context, and is only mounted when optional AI dependencies are installed. |
| **Current behaviour** | The finding drawer renders an analyst section containing only deterministic facts already held (detection source, scanner purpose, evidence count) and states that interpretation is unavailable. The AI Analyst page publishes the contract above. No call is made to the legacy router. |
| **Recommended implementation** | A new tenant-scoped route enforcing the same organization context and RBAC as every other tenant route. It must never return executable commands — remediation is deliberately outside the assessment path. |

**Why the legacy route was not reused:** calling it from a tenant screen would
cross the tenant boundary the rest of the control plane enforces, and it cannot
attribute a result to an organization.

The presentation components are already written: `AnalystNarrativeView` in
`frontend/src/features/Analyst.tsx` consumes exactly the shape above.

---

## GAP-3 — Cross-assessment findings query

| | |
|---|---|
| **Feature** | An organization-wide, filterable findings backlog |
| **Required endpoint** | `GET /api/v1/organizations/{org}/findings?severity=&endpoint_id=&scanner_id=&status=&limit=&offset=` |
| **Expected data** | A paged list of finding occurrences with the same shape as `FindingOccurrenceDetail`, plus total count |
| **Backend status** | **Missing.** Findings are only reachable through their parent assessment via `/assessments/{id}/details`. There is no index across assessments. |
| **Current behaviour** | The Findings screen shows the severity distribution from the overview route and the `recent_high_severity_findings` window that route returns. It states plainly that this is a recent window, not a complete backlog. |
| **Recommended implementation** | A findings index scoped by organization, with the same authorization check as `ASSESSMENT_READ`. Needs a persistence-level index on severity and endpoint to stay bounded. |

---

## GAP-4 — Findings time series

| | |
|---|---|
| **Feature** | Threat-trend chart on the Command Center |
| **Required endpoint** | `GET /api/v1/organizations/{org}/security/findings-trend?from=&to=&granularity=` |
| **Expected data** | `[{ bucket_start, critical, high, medium, low, info }]` |
| **Backend status** | **Missing.** The overview route returns current counts only. Compliance has snapshots and a timeline; findings have no equivalent. |
| **Current behaviour** | The Threat Trends panel declares that no historical series exists. A `Sparkline` component is already available in `frontend/src/components/charts.tsx` to render one. |
| **Recommended implementation** | Either aggregate on read from stored assessments, or capture periodic finding snapshots in the way compliance snapshots already work. |

---

## GAP-5 — General reporting service

| | |
|---|---|
| **Feature** | Executive summaries, fleet reports, assessment reports; PDF output; scheduled generation |
| **Required endpoints** | `POST /api/v1/organizations/{org}/reports`, `GET .../reports`, `GET .../reports/{id}/download` |
| **Expected data** | Report descriptor `{ report_id, type, scope, created_at, status, formats[] }` plus a binary download |
| **Backend status** | **Partially present.** Only compliance snapshot export exists: `GET /compliance/{framework}/snapshots/{id}/export?format=json\|csv`. There is no report entity, no PDF renderer, no scheduling, no delivery. |
| **Current behaviour** | The Reports screen exposes the compliance snapshot exports that genuinely work (JSON and CSV, verified end-to-end) and declares the rest unimplemented. No fake download links are rendered. |
| **Recommended implementation** | A report domain with generation, storage, retention, and signed download URLs. PDF rendering should happen server-side; the signing and retention story should be settled before exports are advertised as audit evidence. |

---

## GAP-6 — RBAC administration

| | |
|---|---|
| **Feature** | Listing, creating and assigning roles from the tenant admin UI |
| **Required endpoints** | `GET/POST /api/v1/organizations/{org}/roles`, `GET/POST /api/v1/organizations/{org}/role-bindings` |
| **Expected data** | `Role { role_id, name, description, permissions[], status }`, `RoleBinding { role_binding_id, membership_id, role_id, status }` |
| **Backend status** | **Missing at the HTTP layer.** `RoleService` and `RoleBindingService` exist in `backend/application/rbac/service.py` and the SQLAlchemy repositories are wired in `main.py`, but no route exposes them. Roles are provisioned server-side only. |
| **Current behaviour** | Settings declares that role administration has no API. Membership create/suspend/revoke — which *do* have routes — are fully functional. |
| **Recommended implementation** | Expose the existing services behind `role.read` / `role.create` / `role_binding.create` permissions. The domain already forbids secrets in role metadata, so the main work is the HTTP boundary and its tests. |

---

## GAP-7 — Agent and integration administration

> **Audit review: RESOLVED.** `GET /api/v1/organizations/{org}/audit-events`
> now exposes the durable audit log through the tenant boundary, and the
> Command Center and Activity screens render it. See
> [`architecture/security-activity-feed.md`](architecture/security-activity-feed.md).
> Requires the new `audit.read` permission, which existing roles must be
> granted explicitly. The remainder of this gap is still open.

| | |
|---|---|
| **Feature** | Agent enrollment management, integration configuration, API-key issuance |
| **Required endpoints** | `GET /api/v1/organizations/{org}/enrollments`, integration CRUD |
| **Expected data** | Enrollment descriptors (never the token), integration configuration without secrets |
| **Backend status** | **Missing.** Enrollment happens through the agent transport (`/api/v1/agent/enroll`); there is no human-facing management route. |
| **Current behaviour** | Settings declares the remaining gaps. |
| **Recommended implementation** | Enrollment listing must expose descriptors and lifecycle state only — never a token value, not even once. |

---

## Not a gap: things deliberately absent

These are **by design** and the UI does not ask for them:

- **Remote remediation / generic command execution.** Raven-X has no command
  transport. The assessment path collects evidence only. The dispatch dialog
  says so explicitly.
- **Inbound endpoint connections.** Agents poll outbound; the control plane
  never opens a connection to an endpoint.
- **Command-bearing evidence fields.** `TenantAssessmentDetailService._safe()`
  strips `powershell`, `shell_command`, `remediation` and credential-like keys
  before evidence reaches the API. The finding drawer notes this.

## Not a gap: no push channel

There is no WebSocket or SSE channel for human clients. The UI polls instead:
30s on the Command Center, 45s on Fleet, 8s on the assessment list while work is
in flight, 6s on an active assessment detail. Polling pauses while the browser
tab is hidden. A push channel would reduce latency but is not required for
correctness.
