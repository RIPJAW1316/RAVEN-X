# RAVEN-X — Engineering Handoff Brief

> Paste this entire document as your first message to Codex. It is written to be
> read by a model with no prior context on this codebase.

---

You are taking over engineering on **RAVEN-X Enterprise**, a production-oriented
multi-tenant endpoint security assessment platform. This brief is your complete
context. Read all of it before you touch a file.

The codebase is in a **good, verified state**. Your default assumption must be
that existing design decisions are deliberate and were paid for in blood. Several
of them look wrong at first glance and are explained in §5 — read that section
before you "fix" anything.

---

## 1. What RAVEN-X is

RAVEN-X began as `scanner.py`: a 1,740-line monolithic Windows security scanner
with a Tkinter desktop GUI, direct PowerShell/registry/WMI inspection, local
SQLite, and OpenAI-compatible AI analysis. **That file still exists and still
works. It is the preserved "personal mode" and is not to be refactored, split,
or removed.**

Layered on top of it — not replacing it — is an **enterprise control plane**:

- Multi-tenant, organization-scoped, RBAC-enforced
- Human operators authenticate with server-side opaque sessions
- Windows endpoints run an agent that makes **outbound-only** HTTPS calls to poll
  for work and submit results
- Assessments are dispatched as durable, leased work items
- Compliance evaluation with immutable historical snapshots
- A durable security audit trail plus a separate in-memory telemetry/detection layer
- A dark SOC-style React console

**Current scale:** ~19,700 lines of backend Python, ~10,200 lines of frontend
TypeScript/CSS, 81 test files, **412 passing backend tests**, 123 documentation files.

---

## 2. Architecture

### Layering (strict — respect it)

```
backend/
  domain/          Pure business contracts. No I/O, no framework imports.
  application/     Use cases and services. Depends on domain + ports only.
    ports/         Protocol interfaces (repositories, transports).
  infrastructure/  Adapters implementing ports: SQLAlchemy, HTTP, crypto, metrics.
  protocol/        Agent wire protocol: envelopes, typed messages, validation.
  agent/           The endpoint agent runtime itself.
  api/             FastAPI composition. main.py wires everything explicitly.
  core/            LEGACY. Old DB models, enhanced_scanner, AI, monitoring.
```

Dependencies point **inward only**: `api → application → domain`, with
`infrastructure` implementing `application/ports`. Domain imports nothing from
the outer layers. If you find yourself importing SQLAlchemy into `domain/`, stop.

### Domain modules

`assessment` `scanner` `endpoint` `enrollment` `agent_work` `user` `security`
`identity` `organization` `rbac` `reporting` `scheduling` `presence` `fleet`
`group_scope` `compliance` `compliance_snapshot` `audit` `security_signals`

### Application packages

`agent` `assessment` `audit` `authentication` `compliance` `control_plane`
`endpoint` `enrollment` `fleet` `identity` `observability` `organization`
`ports` `rbac` `reporting` `scanner` `scheduling` `security`

### Frontend

React + TypeScript + Vite, `lucide-react`, `framer-motion`. **No router library**
(hash router in `hooks/useRoute.ts`), **no state library**, **no charting library**
(hand-rolled SVG in `components/charts.tsx`). These are deliberate — do not add
dependencies without a strong reason.

```
frontend/src/
  types/api.ts        Wire types mirroring backend to_dict() output exactly
  api/client.ts       fetch core, ApiError, session, blob download
  api/endpoints.ts    One typed function per control-plane route
  lib/                format, domain vocabulary, scanners, auditEvents
  hooks/              useApi (aborting loader + polling + mutation), useRoute
  components/         ui.tsx (primitives), charts.tsx (SVG)
  features/           One module per screen (14 files)
  app/App.tsx         Shell: auth gate, org context, nav, routing
```

Screens: Command Center, Fleet, Assessments, Schedules, Groups & Scopes,
Findings, Activity, AI Analyst, Compliance, Reports, Settings.

### API surface

**59 routes** in `backend/api/human_control_plane.py`, all tenant-scoped under
`/api/v1/organizations/{organization_id}/...`, plus `/api/v1/auth/*` and a
separate agent transport at `/api/v1/agent/*`.

---

## 3. NON-NEGOTIABLE INVARIANTS

These are the load-bearing security properties. Several were defects we found
and fixed. **Breaking any of them is a security regression, not a refactor.**

### 3.1 Tenant isolation is enforced in SQL, not in the service layer

Every tenant query applies `organization_id == owner` as a **mandatory, first,
unconditional** predicate at the storage layer. Not in Python. Not in the UI.

`AuditQuery` deliberately **has no organization field** — the tenant always comes
from the resolved `OrganizationContext`, never from the request. There is a test
that asserts the string `organization_id` appears in every `SELECT` the audit
query emits, so a refactor that drops the predicate fails CI.

### 3.2 Attribution must be earned

> An audit or telemetry record may name an organization **only after** a
> membership linking the acting principal to that organization has been read back
> from the repository and validated.

Before that point the organization is an unproven claim. Attributing to it lets
any authenticated user inject records into another tenant's audit feed by naming
that tenant in a URL. **This was a real vulnerability we found and fixed in two
places** (`OrganizationRbacAuthorizer._deny` and
`OrganizationContextResolver._deny`). Unverified denials carry `organization_id =
None` and land in a reserved `__unattributed__` bucket no tenant query can reach.

Attribution is **never** taken from caller-supplied resource metadata.

### 3.3 Audit log and telemetry are separate subsystems

| | Audit trail | Telemetry |
|---|---|---|
| Question | What happened, who, when? | How much, is it normal? |
| Granularity | One row per significant event | Aggregate counts per minute |
| Durability | Durable, append-only, evidentiary | In-memory, lost on restart |
| Home | `security_audit_events` | `SecurityTelemetry` |

**Successful routine permission checks are telemetry, not audit records.** They
used to be audit rows and were 97.8% of the table. Do not reintroduce them.

**Denials are both** — audited *and* counted. A denial is simultaneously a
historical fact and an operational signal. `AuthorizationAuditPolicy` deliberately
has **no flag** to disable denial auditing.

### 3.4 Redaction is allowlist, never deny-list

`backend/domain/audit.py` exposes only an explicit allowlist of metadata keys. A
key added to a future audit write **cannot leak by default** — it is dropped until
explicitly allowed. A deny-list has the opposite failure mode. Audit metadata
legitimately contains operator emails, session IDs and credential IDs; none of it
reaches the API.

### 3.5 The agent transport is outbound-only

- Agents poll; the control plane **never** opens a connection to an endpoint.
- There is **no generic command execution** and **no remote remediation**. The
  assessment path collects evidence only.
- Evidence is stripped of command-bearing fields (`powershell`, `shell_command`,
  `remediation`) before it reaches the API.
- Replay protection, message freshness and direction validation are enforced on
  every agent message.

If a feature request implies pushing commands to endpoints, that is a **separate,
deliberately-deferred phase** requiring policy gating, approval workflow, dry-run
and rollback. Do not slip it in.

### 3.6 Permissions fail closed

`audit.read` is a separate grant from `organization.read` because audit history
reveals who did what. New permissions fail closed — existing roles don't have them
until explicitly granted. That is correct; don't "fix" it by defaulting to allow.

### 3.7 The UI never fabricates backend capability

Where no API exists, the interface **says so**, with a gap ID. It does not show
plausible-looking numbers, fake download links, or dead controls. Honest
"unavailable" states are a feature. See `docs/frontend-api-gaps.md`.

### 3.8 Telemetry can never fail a security decision

Both telemetry call sites wrap recording in `try/except`. An authorization
decision is computed and returned identically whether or not telemetry is
attached. There is a test for this.

---

## 4. Current verified state

| Gate | Command | Result |
|---|---|---|
| Backend compile | `python -m compileall -q backend` | exit 0 |
| Backend tests | `python -m pytest -q` | **412 passed** |
| Frontend types | `npx tsc --noEmit -p tsconfig.json` | exit 0 |
| Frontend build | `npm run build` | ~444 kB JS / 133 kB gzip |

There is **no frontend test runner** configured. `tsc` and the production build
are the only automated frontend gates. Adding Vitest is a reasonable task.

---

## 5. TRAPS — things that look wrong but are deliberate

Read this before you "fix" anything.

1. **`authorization.allowed` is not written for routine checks.** This is the
   audit-event policy, not a bug. See `docs/architecture/audit-event-policy.md`.

2. **`include_permission_checks=true` still exists** on the audit API. It reads
   historical rows and rows captured during diagnostic mode. Keep it.

3. **Audit rows with `organization_id IS NULL` are never returned to tenants.**
   Unattributed system events belong to no organization. Deliberate.

4. **Login events have no organization context** so they don't appear in any
   tenant feed. Sign-in precedes tenant selection. Known limitation, documented,
   not an oversight.

5. **Two different endpoint shapes.** `/fleet/endpoints` returns a **flat**
   `platform` string; `/endpoints/{id}` returns **nested** `platform: {name,
   version, architecture}`. Both are modelled separately (`FleetEndpoint` vs
   `EndpointDetail`). Do not "unify" them without changing the backend.

6. **Severity is derived, not stored.** `derive_severity()` computes it from
   event type + outcome. The audit table has no severity column. A severity
   filter therefore narrows a bounded 2000-row window in memory.

7. **`requirements.txt` is garbage** — 1,105 packages, an uncurated dump of a
   whole Kali environment. **`requirements-dev.txt` (23 packages) is the real
   dependency manifest.** Use it.

8. **Python 3.11 only.** The system Python here is 3.14 and is **not supported**.
   The project venv is `.venv-ravenx/Scripts/python.exe`. Always use it.

9. **Vite binds IPv6 only** (`[::1]:5173`). Use `localhost:5173`, not
   `127.0.0.1:5173`, or you'll get connection refused.

10. **The scanner catalogue is a hard-coded client-side constant**
    (`frontend/src/lib/scanners.ts`). The backend has no scanner-discovery route.
    This is tracked as GAP-1 and is clearly labelled in the UI.

11. **No Alembic migrations.** Schema comes from SQLAlchemy models via
    `create_tables()`, with narrow idempotent additive upgrades in
    `_upgrade_legacy_tenancy_columns()` (sync) and `create_tables_async()` (async
    — the API uses this one, so **both** must be updated for a column add).

12. **The one pytest warning is pre-existing** (SQLAlchemy `declarative_base()`
    deprecation in legacy models). Not caused by recent work.

---

## 6. Known gaps (documented, not bugs)

Tracked in `docs/frontend-api-gaps.md`:

| ID | Gap |
|---|---|
| GAP-1 | No scanner-discovery API |
| GAP-2 | No tenant-scoped AI analysis route (legacy `/api/v1/analysis/*` is unauthenticated and untenanted — **do not call it from tenant UI**) |
| GAP-3 | No cross-assessment findings index |
| GAP-4 | No findings time-series |
| GAP-5 | No general reporting service (only compliance snapshot export) |
| GAP-6 | No RBAC administration API (services exist, HTTP boundary doesn't) |
| GAP-7 | Agent/integration administration (audit read is **done**) |

Other known limitations:

- **Telemetry is process-local** — multi-instance deployments each see only their
  own traffic. No `/metrics` export endpoint exists yet.
- **PostgreSQL is not validated.** SQLite only. Migrations are SQLite-guarded.
- No MFA, no SSO/OIDC, no mTLS, no agent installer, no SIEM forwarding.
- Single-instance scheduler (`RAVENX_ASSESSMENT_SCHEDULER_ENABLED` on exactly one).
- In-memory rate limiting, not distributed.

---

## 7. Running it

```bash
# Backend (from repo root)
RAVENX_ENABLE_LEGACY_ROUTES=false .venv-ravenx/Scripts/python.exe \
  -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000

# Frontend
cd frontend && npm run dev     # http://localhost:5173  (IPv6 — use localhost)

# Verify
.venv-ravenx/Scripts/python.exe -m compileall -q backend
.venv-ravenx/Scripts/python.exe -m pytest -q
cd frontend && npx tsc --noEmit -p tsconfig.json && npm run build
```

**QA tenant credentials** (local dev DB only):

| Account | Password | Role |
|---|---|---|
| `operator@ravenx.local` | `QaOperator!2026` | full permissions |
| `limited@ravenx.local` | `LimitedUser!2026` | `organization.read` + `audit.read` only — use this to generate genuine RBAC denials |

---

## 8. Documentation map

123 markdown files under `docs/`. The ones that matter most to you:

| Document | Why |
|---|---|
| `architecture/current-enterprise-implementation-status.md` | Full implementation inventory |
| `architecture/audit-event-policy.md` | Audit vs telemetry, attribution rules |
| `architecture/security-observability.md` | Metrics taxonomy, detection, cardinality |
| `architecture/security-activity-feed.md` | Audit read API, redaction, tenant isolation |
| `frontend-api-gaps.md` | Every missing backend capability, with IDs |
| `frontend-implementation-status.md` | Screen-by-screen status |
| `deployment/production.md` | Deployment topology and constraints |

There is a security doc under `docs/security/` for nearly every boundary. Read
the relevant one before changing that boundary.

---

## 9. How to work on this codebase

**Inspect before you change.** This codebase has a lot of deliberate structure.
Read the relevant domain module and its security doc first. Do not assume a
pattern is accidental.

**Follow the existing house style.** Some files are written in a dense,
single-line style (`authorizer.py`, `service.py` in rbac/organization). That is
the established style in those files — match it rather than reformatting, which
produces unreviewable diffs.

**Verify with evidence, not assertion.** Run the four gates. If you claim
something works, show the command output. Do not claim "production-ready" unless
the evidence supports it.

**Zero regressions is the bar.** 412 tests pass today. If your change breaks one,
fix the cause — do not weaken the test.

**Tests must cover security boundaries.** For anything touching auth, tenancy, or
audit, add tests for: cross-tenant isolation, unauthorized access, spoofed
attribution, and malformed input rejection. Look at
`tests/unit/test_authorization_audit_policy.py` and
`tests/integration/test_security_observability_api.py` as the standard to match.

**Never fabricate data to make a demo look good.** If you need test data, seed it
through the real services and say so.

**Don't commit or push unless asked.**

---

## 10. Your first task

Do not start writing code yet. First:

1. Read `docs/architecture/current-enterprise-implementation-status.md`.
2. Read `docs/architecture/audit-event-policy.md` and
   `docs/architecture/security-observability.md` — these contain the reasoning
   behind the most subtle parts of the system.
3. Run the four verification gates and confirm you reproduce 412 passing tests.
4. Report back: a short architecture map in your own words, which invariants you
   consider most fragile, and what you think the highest-value next capability is
   and why.

Then wait for direction before implementing.

---

## 11. Suggested next capabilities (for context, not instruction)

In rough value order, if asked:

1. **Prometheus `/metrics` endpoint + shared counter backend** — makes telemetry
   usable by infrastructure monitoring and makes detection correct across
   multiple API instances. Fixes the two biggest observability limitations at once.
2. **RBAC administration API** (GAP-6) — services and repositories already exist;
   only the HTTP boundary and its tests are missing.
3. **Scanner discovery route** (GAP-1) — small, removes the only hard-coded
   catalogue in the frontend.
4. **Cross-assessment findings index** (GAP-3) — unlocks a real findings backlog
   workflow, currently the most bounded screen.
5. **Frontend test runner** (Vitest) — the only gate the project lacks.
6. **PostgreSQL validation path** — required before any real deployment.

---

**Summary of the one thing to remember:** this is an enterprise security product.
Optimize in this order — **security, correctness, tenant isolation, audit
integrity, maintainability, observability, performance.** When those conflict,
the earlier one wins.
