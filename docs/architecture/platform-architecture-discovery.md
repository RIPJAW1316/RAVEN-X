# RAVEN-X Platform Architecture Discovery and Target Architecture

> **Date:** 2026-10-09
> **Scope:** the whole working tree, tracked and untracked, read against `docs/RAVEN-X-NORTH-STAR.md`
> **Method:** I read the code paths end to end. I inspected a read-only *copy* of `data/raven_x.db`, ran the full test suite on an isolated copy (Python 3.11.9: **412 passed in 67 s**), and micro-benchmarked the credential hashing parameters.
> **Changes made:** none to code. This file is the only artifact.
> **Reference deployment:** a college lab of about 70 Windows PCs, one RAVEN-X server on the LAN, no Internet, and an optional local LLM.

Code references use `path:line`. Wherever this document disagrees with an older doc in `docs/`, the code was checked and wins. The places where older docs are stale are listed in §13.4.

---

## 1. Executive summary

RAVEN-X is already well past a single-endpoint scanner. It is a layered modular monolith: about 13k lines across domain, application, infrastructure and protocol layers, with explicit ports. It has:

- tenant-scoped RBAC,
- a typed and replay-protected agent protocol,
- durable per-endpoint work leasing,
- idempotent schedule occurrences,
- compliance snapshots with digests,
- a redacted security activity feed,
- a 12-screen operator console,
- and 412 passing tests.

The direction (modular monolith, outbound-polling agents, SQLite first) is right for 1 to about 500 endpoints. **Keep it. Do not rewrite it.**

Even so, the platform **cannot run the reference deployment end to end today.** Five blocking problems stand in the way, plus one operational emergency.

1. **No onboarding path exists.** There is:
   - no HTTP enrollment route,
   - no API that issues enrollment tokens,
   - no way to create users, organizations or roles outside Python,
   - and no deployable agent. `RavenXAgent` is a library with no run loop, no service host, and in-memory identity, so a restart forces re-enrollment and creates a duplicate endpoint.

   The seeded dev database confirms this: it holds 3 endpoints with **0 credentials and 0 enrollments**.
2. **Background maintenance never runs.** The reconciler, the presence evaluator, retention and the purges exist as classes but are never hosted. The effects are:
   - Presence never leaves `online`.
   - Failed or crashed assessments never become terminal.
   - The scheduler's `skip_if_active` overlap rule then skips that endpoint **forever**.
   - The scheduler itself is off by default.
3. **Powered-off PCs can never receive queued work.** A dispatch envelope keeps its creation timestamp, and the agent rejects anything older than the 5-minute skew window. A 02:00 scheduled scan for a PC that boots at 08:00 is rejected, retried 3 times, and fails.
4. **Hot-path cost grows with history, not with load.**
   - Every authenticated UI request runs scrypt across *every session ever issued*. I measured 38.5 ms per scrypt, so the 22 sessions in your dev DB already cost about 0.8 s of event-loop CPU per request. A random bearer token forces a full scan, which makes this an unauthenticated DoS vector.
   - Every agent poll runs scrypt and writes an audit row.
   - Listing and overview endpoints load every assessment's full `result_json`.
5. **The LAN server ships with unsafe defaults.** Unauthenticated legacy routes are mounted by default on `0.0.0.0` behind wildcard CORS. One of them is `POST /api/v1/remediation/fix`, which runs `subprocess.run(..., shell=True)` PowerShell **on the server host**.
6. **Operational emergency: none of the enterprise platform is in version control.** Git tracks 34 files. `backend/domain`, `application`, `infrastructure`, `protocol` and `agent`, `frontend/src`, every test, and every doc are untracked. They live in a OneDrive folder with a manual zip as the only backup. The CI workflow is untracked too, so it runs nowhere.

None of this needs a new architecture. About 80% of the fix is wiring, hardening, and a handful of new modules:

- an agent service host,
- an in-process job host,
- a findings store,
- an onboarding/admin API,
- migrations.

The prioritized plan is in §22.

---

# Part I: Current state

## 2. Current architecture map

### 2.1 Runtime topology (as built)

```
 Operator browser
 └─ React SPA (Vite dev server :5173, /api proxied to :8000). frontend/dist exists but nothing serves it.
          │  HTTP (no TLS configured anywhere), Authorization: Bearer <session token>
          ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ ONE uvicorn process. run.py starts `--reload` on 0.0.0.0:8000; `python -m backend.api.main`  │
│ would start workers=4 from config.yaml.                                                      │
│ backend/api/main.py is the composition root: about 60 module-level singletons built at       │
│ import time.                                                                                 │
│                                                                                              │
│  Routers                                                                                     │
│   /api/v1/auth/*, /api/v1/organizations/{org}/*  human control plane (session + org ctx + RBAC)│
│   /api/v1/agent/messages, /api/v1/agent/work     agent ingress (endpoint bearer credential)  │
│   /api/v1/{scan,analysis,remediation,reports,system}  LEGACY, unauthenticated, ON by default │
│   /ws/realtime (unauthenticated echo), /health, /ready, /api/v1/stats                        │
│                                                                                              │
│  async route handlers ──call──► sync application services ──► sync SQLAlchemy repositories  │
│  (each repository call = its own Session + commit)                                           │
│                                                                                              │
│  In-memory only: AgentSessionRegistry, PendingWorkQueue (legacy fallback), login rate limiter,│
│                  SecurityTelemetry windows, MetricsCollector                                 │
│  Background: AssessmentScheduleWorker daemon thread, only if RAVENX_ASSESSMENT_SCHEDULER_    │
│              ENABLED=true (default false). Reconciler, presence maintenance, retention, and  │
│              replay/session purges are never run.                                            │
└───────────────┬───────────────────────────────────────────────────────────────┬──────────────┘
                │ sync engine, StaticPool = ONE shared DBAPI connection           │ async engine (aiosqlite):
                │                                                                 │ startup DDL, /ready, legacy
        ┌───────▼─────────────────────────────────────────────────────────────────▼───┐
        │ SQLite data/raven_x.db (path relative to CWD), WAL, 33 tables,               │
        │ FKs declared but NOT enforced (no PRAGMA foreign_keys), no busy_timeout      │
        └─────────────────────────────────────────────────────────────────────────────┘

 Windows endpoint: no deployable agent exists yet
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │ RavenXAgent (backend/agent/runtime.py): library only, no loop, no service host     │
 │  InMemoryAgentIdentityStore / InMemoryAgentCredentialStore (lost on restart)       │
 │  HttpAgentTransport (httpx, sync, HTTPS required, CA bundle path supported)        │
 │  LocalAssessmentOrchestrator → ScannerRegistry → 4 legacy adapters                 │
 │     → scanner.py (imports tkinter, customtkinter, openai at module load and        │
 │       installs a root FileHandler("raven_x.log") in the CWD)                       │
 └───────────────────────────────────────────────────────────────────────────────────┘

 Personal mode (separate, preserved): scanner.py Tkinter GUI → local sqlite3, LM Studio, optional SMTP
```

### 2.2 Code inventory

| Area | Lines | Files | Role |
|---|---:|---:|---|
| `backend/domain` | 3,454 | 35 | Pure contracts: identities, lifecycles, invariants |
| `backend/application` | 5,428 | 80 | Use cases, tenant services, ports, scheduler, reconciler |
| `backend/infrastructure` | 3,174 | 48 | SQLAlchemy + in-memory repositories, HTTP transport, security, settings |
| `backend/protocol` | 620 | 3 | Agent envelope, payloads, validation |
| `backend/agent` | 387 | 3 | Agent runtime library + heartbeat primitive |
| `backend/api` | 2,629 | 8 | Composition root, human router (766 lines), legacy routers |
| `backend/core` (legacy) | 4,035 | 13 | ORM models + DB manager (shared), legacy scanner/AI/remediation/monitoring |
| `scanner.py` (legacy) | 1,740 | 1 | Personal-mode scanner, 25 `check_*` functions, Tkinter GUI |
| `frontend/src` | 7,596 | 28 | React/TS console |
| `tests` | 7,669 | 81 | 371 test functions → 412 cases |
| `docs` | — | 122 `.md` | Architecture, security, ops |

### 2.3 The three request paths

**Human request.** It goes through these steps:

1. `async def` route
2. `_bearer_token`
3. `HumanSessionAuthenticator.authenticate_bearer`, which scans all sessions with scrypt (`sqlalchemy_user_repository.py:45-52`) and then verifies again (`identity/service.py:88`)
4. `OrganizationContextResolver.resolve`: user, org and membership reads (`organization/context.py:46-66`)
5. Tenant service
6. `OrganizationRbacAuthorizer.authorize`: membership, org, bindings and roles, plus a resource-ownership read (`rbac/authorizer.py:23-55`)
7. Repository call(s)
8. Audit append, in a separate transaction
9. `_json_safe` serialization

Every DB and CPU step runs **on the event-loop thread**.

**Agent request.**

- `POST /api/v1/agent/messages`:
  1. Read the body (1 MiB cap).
  2. `AgentMessageEnvelope.from_dict`, then `AgentMessageProcessor.process`.
  3. Validate the envelope (skew ±5 min, version, size).
  4. Authenticate the credential (scrypt) and write audit rows ×2.
  5. Authorize (message-type allow-list and endpoint scope).
  6. Decode the typed payload.
  7. **Claim the replay ID (committed)**.
  8. Run the handler, which makes several repository calls, each committing separately.
- `POST /api/v1/agent/work`: scrypt verify (plus 1 audit row), then `lease_next`, which first runs `release_expired_leases` across **all** pending and leased work for **all** endpoints.

**Scheduler (opt-in).** A daemon thread calls `AssessmentScheduleRunner.run_once` every 30 s:

1. `list_due`
2. Create the run occurrence (unique on `(schedule_id, scheduled_for)`).
3. Resolve targets (explicit endpoints, group, or scope; the result is snapshotted on the run).
4. For each endpoint: run an overlap check (`list_for_schedule`, which loads every assessment of that schedule with results), then dispatch.
5. Persist outcomes, advance `next_run_at`, write audit.

### 2.4 State that lives only in memory, and what that costs

| State | Where | Effect of a restart or of `workers>1` |
|---|---|---|
| `AgentSessionRegistry` | `control_plane/sessions.py:50` | Lost on restart. Dispatch tolerates this because work is durable. Capability reports are kept *only* here. |
| `PendingWorkQueue` | `transport/http/outbox.py:11` | Only used when no work repository is set; inert in `main.py` |
| Login rate limiter | `operational/rate_limiter.py` | Per process |
| `SecurityTelemetry`, `MetricsCollector` | `operational/` | Per process; reset on restart (documented as acceptable) |
| Scheduler status | `scheduling/worker.py:49` | Per process; with `workers: 4` and the scheduler enabled, **four schedulers** would run |

---

## 3. Current capability matrix

Status meanings:

- **READY:** works as designed and is tested; you can build on it.
- **PARTIAL:** correct but incomplete.
- **FRAGILE:** works in demos but fails under a realistic condition such as time, history, restart, concurrency, or a hostile LAN.
- **MISSING:** does not exist.
- **SHOULD NOT BUILD YET:** deliberately out of scope for now.

### 3.1 READY

| Capability | Evidence | Notes |
|---|---|---|
| Layered architecture with ports/adapters | `backend/{domain,application,infrastructure,protocol}` | Clean seams; in-memory twins make unit tests cheap |
| Organization context and tenant isolation on human routes | `organization/context.py:46`, `rbac/authorizer.py:23-75` | Org comes from the path and is verified against membership. Resource ownership is re-read (IDOR-safe). Denials are attributed only after verification. |
| RBAC evaluation engine | `rbac/authorizer.py`, `domain/rbac/models.py` | Org-scoped roles map to `AuthorizationAction` permissions. The admin surface is missing (see MISSING). |
| Agent protocol envelope | `protocol/agent/models.py:449-487` | Typed messages, direction rules, version gate, 1 MiB bound |
| Durable replay guard | `sqlalchemy_replay_guard.py` | Ordering caveat in §5.5 |
| Durable per-endpoint work leasing | `sqlalchemy_agent_work_repository.py:69-103` | The conditional `UPDATE … WHERE status='pending'` is the claim; lease tokens are stored hashed |
| Schedule model and calculator, occurrence idempotency, coalesced misfire | `domain/scheduling/*`, `assessment_schedule_runs` unique constraint | Crash-resumable runs |
| Endpoint groups and saved fleet scopes | `application/fleet/groups.py` | Bounded at 200 members per group |
| Compliance evaluation semantics and snapshots | `compliance/service.py`, `compliance_snapshot.py` | Distinguishes unknown from non-compliant; stale-evidence handling; SHA-256 snapshot digest; JSON/CSV export |
| Security activity feed | `domain/audit.py`, `sqlalchemy_security_audit_repository.py:45` | Allow-listed metadata projection, derived severity, SQL tenant predicate |
| Finding detail, recurrence and coverage read models | `application/reporting/*`, `domain/reporting/*` | Bounded, computed at read time |
| Request IDs, structured logs, `/health`, `/ready` | `main.py:154-181, 413-436` | |
| Login rate limiting | `human_control_plane.py:93-102` | Single process only |
| Operator console shell | `frontend/src/app/App.tsx`, `features/*` | Honest 403/503/empty states, aborting fetches, polling pauses while the tab is hidden |
| Backend test suite | `tests/` | **412 passed**, including security-boundary suites |
| Personal-mode scanner | `scanner.py` | Preserved; characterization-tested |

### 3.2 PARTIAL

| Capability | Evidence | Gap |
|---|---|---|
| Endpoint identity | `domain/endpoint/models.py`, `enrollment/service.py:128-139` | Server-assigned UUID plus credential is good. But status never leaves `new`, there is no machine fingerprint, and re-enrollment creates duplicates. |
| Enrollment | `enrollment/service.py` | Domain and service are complete but single-use only. There is no HTTP route (`EnrollmentMessageProcessor` at `processor.py:185` is unused) and no issuance API. |
| Agent runtime | `agent/runtime.py` | A library only (see MISSING: agent service) |
| Agent scanner coverage | `scanner/legacy_adapters.py:30-62` | **4** checks (firewall, UAC, BitLocker, SMB) out of the 25 in `scanner.py` |
| Compliance content | `domain/compliance.py:161-164` | A 4-control "RAVEN-X Windows baseline" |
| Cancellation | `control_plane/cancellation.py` | Before ACK only. After ACK it records intent and nothing more (by design). |
| Fleet query | `sqlalchemy_endpoint_repository.py:71-87` | Server-side API, but it loads every endpoint and then filters, sorts and pages in Python. Fine at 70; not SQL paging. |
| Organization administration | `human_control_plane.py:140-192` | Memberships for existing users only. No creation of orgs, users or roles. |
| Reporting and exports | `human_control_plane.py:500-508` | Compliance snapshot JSON/CSV only |
| Metrics and telemetry | `operational/metrics.py`, `security_telemetry.py` | Process-local |
| PostgreSQL | `core/database/database.py:59-69` | URL builder only. The sync URL needs psycopg2, which isn't in requirements. Never validated. |
| AI analysis | `core/ai/llm_client.py`, `api/v1/analysis.py` | Reached only through an unauthenticated legacy route. Defaults to LM Studio on localhost, which is good. No tenant route (GAP-2). |
| Console: Findings, Reports, Settings, AI Analyst | `features/*` | Bounded windows or scaffolds, honestly labelled |

### 3.3 FRAGILE

| ID | Capability | Failure mode | Evidence |
|---|---|---|---|
| F-1 | Human session verification | O(number of session rows) × scrypt per request. Sessions are never purged, the newest is found last, and a random token scans every row (unauthenticated CPU DoS). | `sqlalchemy_user_repository.py:45-52`; `identity/service.py:88,110-113` |
| F-2 | Agent credential verification | One 38.5 ms scrypt per poll and per message on the event loop, plus 1–2 `credential.authentication_succeeded` audit rows | `enrollment/service.py:164-183,259-261`; `processor.py:129-135`; `transport/http/server.py:52` |
| F-3 | DB runtime | Sync DB and CPU work inside `async def` blocks the loop. `StaticPool` shares **one** connection between the event loop and the scheduler thread, so transactions can interleave. | `database.py:84,125`; `scheduling/worker.py:56` |
| F-4 | Presence | Only `record_heartbeat` writes state (always ONLINE). `evaluate()` runs only from `PresenceMaintenanceRunner`, which is never started. The UI reads stored state, so a dead PC shows `online` forever. | `presence_service.py:21-61`; `main.py:214`; `fleet_presence.py:32-44` |
| F-5 | Terminal-state convergence | `RemoteAssessmentReconciler` is never instantiated. FAILED or EXPIRED work never becomes a terminal assessment. ACKed work whose agent died stays `running` forever, and even the reconciler's timeout only sets a flag. Then the scheduler's `skip_if_active` blocks that endpoint permanently. | `reconciliation.py:78-84`; `scheduling/runner.py:60-62` |
| F-6 | Offline work delivery | The agent validates the stored dispatch envelope's *creation* timestamp against ±5 min, so delivery fails if the PC wasn't polling within 5 minutes of queueing. Rejection is tested as intended (`tests/unit/test_agent_runtime.py:117`). | `agent/runtime.py:225-228`; `assessment_dispatch.py:231-234`; `protocol/agent/models.py:449-472` |
| F-7 | Result ingestion | The replay claim commits before the handler runs, so a handler failure burns the message ID. Work completion, assessment update and audit are three transactions. The agent has no outbox: a failed send loses the result. A duplicate result returns 409 rather than "already accepted". | `processor.py:147-150`; `handlers.py:105-139`; `agent/runtime.py:276-280` |
| F-8 | Schema evolution | `create_all` plus **two divergent** ad-hoc ALTER paths. API startup runs only the async path, which skips the endpoint, assessment and work tenancy columns. | `database.py:144-238,240-274`; `main.py:112` |
| F-9 | Read paths over history | `GET …/assessments` returns **all** assessments with `result_json`, unpaginated. The Command Center (polled every 30 s) loads all assessments and results. Compliance, recurrence and coverage load every assessment for an endpoint. Each agent ack, progress or result loads every work item for that endpoint. | `sqlalchemy_remote_assessment_repository.py:75-80`; `security_overview.py:41-49`; `handlers.py:155-166` |
| F-10 | Hard ceilings | Compliance summary and snapshots, schedule targets: **100 endpoints**. Groups: 200. A 101-endpoint org gets `422 BOUND_EXCEEDED`. | `compliance/service.py:67-68`; `settings.py:30,35`; `main.py:286` |
| F-11 | Multi-process configuration | `config.yaml` sets `workers: 4`, which splits in-memory state and would run up to four schedulers | `config/config.yaml:11`; `main.py:457-464` |
| F-12 | Audit volume and atomicity | No retention. Agent auth success is logged on every contact (about 200 rows per endpoint per hour; see §19). The audit write is a separate transaction from the action it records. | `sqlalchemy_security_audit_repository.py:20-25` |
| F-13 | Legacy surface (security defect) | Unauthenticated `/scan/start`, `/remediation/fix` and `/rollback` execute PowerShell on the server host. The "guard" is a caller-supplied flag. CORS is `*`. | `settings.py:69`; `main.py:145-151,356-360`; `remediation.py:71-80,165-167`; `auto_fixer.py:41-42,115,231-244` |
| F-14 | Source control | 34 tracked files; the enterprise layer is untracked. `data/raven_x.db-wal`, which holds DB pages including verifiers, **is** tracked. | `git ls-files` |
| F-15 | Agent dependency footprint | Importing `scanner.py` pulls in tkinter, customtkinter and openai, and writes `raven_x.log` to the CWD. A service's CWD is `System32`. | `scanner.py:9-26`; `legacy_adapters.py:8-9` |
| F-16 | Clock skew in Internet-less labs | The ±5 min rule with no time-offset correction: drifting lab PCs get silently rejected (`stale_or_future_message`) | `protocol/agent/models.py:469-472` |
| F-17 | Config honesty | `config.yaml: environment: production` is ignored because the env-var default `development` wins, so production validation never triggers unless the env var is set | `settings.py:53-57` |

### 3.4 MISSING

| Capability | North Star area |
|---|---|
| HTTP enrollment, enrollment-key issuance, endpoint approval queue | Endpoint identity, agent management |
| Bootstrap of the first admin/org/roles; user, role and binding admin API (GAP-6) | Authentication, RBAC, organizations |
| Agent service host, DPAPI-protected identity store, local outbox, backoff and jitter, version reporting | Agent management, offline operation |
| Background job host (reconcile, presence, retention, purges) | Fleet, assessments, audit |
| Endpoint lifecycle transitions; inventory updates after enrollment | Inventory, fleet |
| Finding entity, lifecycle (open/resolved/accepted/false-positive) and backlog (GAP-3) | Findings, evidence |
| Audit tamper evidence; audit retention and archival | Audit |
| Group- or site-scoped RBAC ("Lab A technician") | RBAC |
| LAN PKI (local CA), SPA hosting, server and agent service packaging, automated backups | Offline operation |
| Scanner discovery route (GAP-1); assessment profiles | Assessments, policy |
| Remediation *tracking* workflow (non-executing) | Remediation |
| Clock-offset handling | Offline operation |
| Frontend tests; pinned frontend dependency versions (`"latest"` everywhere) | UI |
| Tenant-scoped, advisory local-AI service (GAP-2) | Local AI |

### 3.5 SHOULD NOT BUILD YET

| Item | Why not now |
|---|---|
| Microservices, Kubernetes, Redis, Celery or Kafka | Load at 1,000 endpoints is about 40 req/s; a single process with DB-leased jobs covers it (§19) |
| Async SQLAlchemy rewrite | Running sync repositories in a threadpool fixes loop blocking without a rewrite |
| Multi-instance HA control plane, leader election | One lab server; DB job leases prevent accidental double runs |
| Agent-executed remediation, any generic command channel | The trust model isn't ready; North Star: AI must never authorize destructive actions |
| AI that triggers actions or writes scripts | Advisory only (§17.6) |
| WebSocket or SSE push (agents or UI) | Polling with server-suggested intervals is enough and works offline |
| SSO, OIDC, SCIM | Not available offline; local accounts first, then TOTP MFA (P2) |
| Agent self-update channel | Use MSI via GPO, a startup script, or a manual push; report versions centrally |
| Per-agent mTLS PKI | First ship server TLS with a pinned local CA and fast bearer verification |
| Expanding legacy ML or behavioral monitoring | Not on the critical path; keep it isolated |
| PostgreSQL as the default | SQLite in WAL mode is right for 70 to about 500 endpoints; Postgres stays an option |

---

## 4. Current domain model

```
Organization (active|suspended|revoked)
 ├─ OrganizationMembership (User ↔ Org; active|suspended|revoked)
 │    └─ RoleBinding (membership ↔ role; active|disabled|revoked)
 │         └─ Role (org-scoped; permissions ⊆ AuthorizationAction)
 ├─ Endpoint (UUID; status NEW|ACTIVE|DEGRADED|OFFLINE|REVOKED; platform, agent info,
 │    │       capabilities (unverified claims), metadata)
 │    ├─ EndpointCredential (opaque, scrypt verifier; active|rotated|revoked|expired)
 │    ├─ EndpointPresence (UNKNOWN|ONLINE|STALE|OFFLINE; persisted snapshot)
 │    ├─ [AgentSession: in-memory: CONNECTED|READY|BUSY|DEGRADED|DISCONNECTED]
 │    └─ EndpointGroup membership (static)            SavedFleetScope (dynamic FleetQuery)
 ├─ EnrollmentAuthorization (single-use token verifier; pending|consumed|expired|revoked)
 ├─ AssessmentSchedule (explicit|group|scope target; daily|weekly|interval; skip_if_active)
 │    └─ AssessmentScheduleRun (unique per occurrence; resolved targets snapshot; outcomes)
 ├─ RemoteAssessment (created→queued→dispatched→running→completed|failed|delivery_failed|
 │    │               expired|cancel_requested→cancelled|endpoint_unavailable)
 │    │   progress_json, result_json  ◄── findings live HERE, embedded
 │    └─ AgentWorkItem (pending→leased→acknowledged→completed|failed|expired|cancelled)
 ├─ ComplianceSnapshot (+ per-endpoint + per-control rows, SHA-256 digest)
 └─ SecurityAuditEvent (append-only by convention)
User (active|disabled|revoked) ─ HumanCredential (scrypt) ─ UserSession (scrypt token verifier)
Catalogs (code, not DB): ComplianceFramework/Control (4 controls), ScannerManifest (4 scanners),
                         ScannerCoverageContract, AuthorizationAction (~60 actions)
Read models: OrganizationSecurityOverview, FindingFingerprint (candidate identity), Finding
             coverage/recurrence, FleetPage, CompliancePostureSummary, AuditEventView
```

**Strengths.** Identities are validated value objects. Lifecycles have explicit transition tables (`Role.transition_to`, `AssessmentSchedule.transition_to`). Every timestamp is timezone-aware. Coverage semantics refuse to treat "not observed" as "fixed" without strong absence evidence. That last point is unusually rigorous, and it is the right foundation for a finding lifecycle.

**Weaknesses.**

1. **Three overlapping liveness models.** `EndpointStatus` has `OFFLINE`/`DEGRADED`, `PresenceState`, and `AgentSessionState`. None is authoritative, and `EndpointStatus` never leaves `NEW`.
2. **No `Finding` entity.** Findings are dictionaries inside `result_json`. Occurrence IDs are derived on read; logical fingerprints exist only when scanner, rule and resource hints are all present.
3. **`RemoteAssessment` is defined in the application layer** (`control_plane/assessment_dispatch.py:42`), not the domain, while the separate `domain/assessment` models describe a *local* run. There are two assessment vocabularies.
4. **No inventory.** Endpoint attributes are an enrollment-time snapshot. Capability reports update only the in-memory session (`handlers.py:49-56`), and nothing calls `endpoint_repository.update`.
5. **No `Policy` concept.** Scanner lists are repeated on each schedule and ad-hoc request; there are no profiles, thresholds or exceptions.

---

## 5. Current agent/server protocol

### 5.1 Transport and endpoints

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/v1/agent/messages` | `Authorization: Bearer <credential secret>`; `envelope.endpoint_id` | Every agent→server message |
| `POST /api/v1/agent/work` | Bearer + `X-Raven-Endpoint-Id` | Lease the next pending work item |
| *(none)* | — | Enrollment. `ENROLLMENT_REQUEST`/`RESPONSE` types and `EnrollmentMessageProcessor` exist, but no route exposes them. |

The client enforces `https://` and certificate verification and accepts a CA-bundle path (`client.py:33-54`). The server has no TLS configuration (`run.py` starts plain HTTP), so a real agent cannot connect without a proxy or uvicorn TLS flags.

### 5.2 Envelope

The envelope carries `message_id` (UUID), `message_type`, `protocol_version` (`1.0`; major must equal 1), `endpoint_id`, `timestamp`, `correlation_id` (required for ack, progress and result) and `payload`.

Validation (`protocol/agent/models.py:458-475`):

- `|now − timestamp| ≤ 5 min`
- serialized size ≤ 1 MiB
- direction allowed for this route
- typed decode by `TypedMessageRouter`

### 5.3 Message types

| Type | Direction | Handler effect |
|---|---|---|
| `agent.heartbeat` | A→S | Upserts presence ONLINE (server receipt clock); updates the in-memory session |
| `agent.capabilities` | A→S | In-memory session only (**not persisted**) |
| `agent.status` | A→S | In-memory session only |
| `assessment.dispatch` | S→A | Returned in the `/work` response with `{work_id, lease_token, lease_expires_at}` |
| `assessment.ack` | A→S | Lease-token-checked ACK; assessment → RUNNING |
| `assessment.progress` | A→S | Progress stored; can recover a lost ACK while the lease is active |
| `assessment.result` | A→S | Work COMPLETED or FAILED; assessment COMPLETED or FAILED with `result_json` |
| `enrollment.request` / `enrollment.response` / `protocol.error` | — | Defined; not routed or used |

### 5.4 Lifecycle as implemented

```
(enrollment: in-process only)  →  startup: heartbeat + capabilities + status
loop (the integrator must write it; none exists):
   heartbeat every 60 s
   POST /work → lease (5 min, max 3 attempts, retry delay 0)
      → agent validates the dispatch (±5 min on the dispatch's CREATION time)  ← F-6
      → assessment.ack (lease token) → progress… → result
```

### 5.5 Protocol defects that matter for the lab

1. **Stale-dispatch rejection (F-6).** Message freshness, which is a replay concern, is conflated with work validity, which is a business deadline.
2. **Replay claim ordering (F-7).** `_claim` commits before `router.invoke`. If the handler fails transiently, the same envelope is rejected as a replay (409) on retry.
3. **Non-idempotent result acceptance.** A second identical result raises `DuplicateTerminalResultError` and returns 409. An agent can't tell "already accepted" apart from "rejected".
4. **No clock-offset feedback.** Responses don't carry server time, and heartbeats don't report skew (F-16).
5. **No server-shaped polling.** There's no `next_poll_after`, so load can't be shaped.
6. **Two audit rows per authenticated message, one per poll (F-2/F-12).**
7. **Unauthenticated work-poll probing costs one scrypt per request** when the endpoint ID exists. Agent routes have no rate limit.

---

## 6. Current job/scheduling architecture

| Component | State |
|---|---|
| `AssessmentScheduleWorker` (`scheduling/worker.py`) | A solid lifecycle wrapper: daemon thread, `run_once` lock, status, metrics. **Disabled by default** (`settings.py:73`). |
| `AssessmentScheduleRunner` (`scheduling/runner.py`) | Idempotent occurrences (`add_if_absent`), target snapshot, per-endpoint outcomes, coalesced misfire, audit per run. Per target it calls `list_for_schedule()` (N+1, unbounded, loads results). Outcomes are persisted only at the end of the run, but a resume is protected by the overlap check. |
| `RemoteAssessmentReconciler` | Implemented and tested, **never hosted**. Its timeout sets a flag without making the assessment terminal. |
| `PresenceMaintenanceRunner` | Constructed in `main.py:214`, **never run**. `presence_maintenance_enabled` is a dead setting. |
| `ComplianceSnapshotRetentionRunner` | Implemented, **never constructed**. `compliance_retention_*` are dead settings. |
| Replay purge | Runs inline on every message (`DELETE … WHERE expires_at <= now`) |
| Work expiry and lease release | Runs inline on **every poll**, over every endpoint's work (`agent_work_repository.py:71,151-171`) |
| Session purge, audit retention, result retention | None |
| Job table or leases | None. `agent_work_items` is the only durable queue. Documented rule: "exactly one scheduler-enabled instance", which is not enforced. |

---

## 7. Current database architecture

- **Engine:** SQLite at `data/raven_x.db`, relative to the repository when the default config is used. WAL mode, `synchronous=FULL` on both the sync and async engines, 64 MB cache, `busy_timeout=30000`. FULL flushes commit frames to the OS and is not hardware power-loss proof. **No `foreign_keys=ON`**, so the declared FKs are decorative.
- **Two engines.**
  - Sync engine: every enterprise repository uses `StaticPool`, i.e. *one* connection shared by every thread.
  - Async engine (aiosqlite): startup DDL, `/ready`, legacy routes.
- **Transactions:** `get_db()` gives every repository call its own commit. No unit of work spans repositories.
- **Schema:** 33 tables. Eleven are legacy personal-mode tables (`scans`, `vulnerabilities`, `fixes`, `audit_logs`, …); 22 are enterprise.
- **Schema management:** `create_all` plus `_upgrade_legacy_tenancy_columns` (sync; never called by the API) plus a different subset inside `create_tables_async` (F-8). No version table.
- **Indexes:** single-column indexes on nearly every FK and status column (60+). Hot-path composites are missing:
  - `agent_work_items(endpoint_id, status, available_at)`
  - `remote_assessments(organization_id, requested_at)`
  - `remote_assessments(schedule_id, endpoint_id, status)`
  - an indexed token-lookup hash on sessions and credentials

  `security_audit_events` carries 15 secondary indexes on an append-heavy table, which inflates write cost.
- **Data shape:** naive-UTC timestamps; JSON columns for scanner lists, results and metadata. Findings are only inside `remote_assessments.result_json`.
- **PostgreSQL:** not validated (§3.2).
- **Backup/restore:** documented (`docs/operations/database-*.md`) and unit-tested, but not automated.

---

## 8. Current tenant/RBAC architecture

- **Tenancy chain:** `User → Membership → Organization`. Every tenant table carries `organization_id`, and repositories expose `get_for_organization` and `list_for_organization`. Work items and assessments inherit the org from the endpoint and are cross-checked on write and on every agent message (`agent_work_repository.py:37-47`, `handlers.py:155-166`).
- **Context:** the org comes from the URL and is verified each request. Organization existence is never disclosed: an unknown org and "not a member" both return 403.
- **RBAC:**
  - Permissions are `AuthorizationAction` strings on org-scoped roles bound to memberships.
  - There are no built-in templates. The dev DB's 8 roles were seeded by a script that isn't in the repo.
  - No resource scoping below the org: no group or site scope.
  - Successful checks are telemetry, not audit (good). Denials are always audited.
- **Principals:**
  - `HUMAN`: RBAC.
  - `ENDPOINT`: allow-list of `agent.*` and `assessment.*.submit` within its own scope.
  - `SYSTEM`: allow-list in `ConservativeControlPlaneAuthorizer` (used by the scheduler).
- **Gaps:**
  - No admin API for roles, users or orgs.
  - Human-requested dispatches are audited as `SYSTEM` (`assessment_dispatch.py:271-279` always uses `self._principal`).
  - About 8–10 DB reads per authorized request, uncached.

---

## 9. Current audit architecture

- **Write:** `SecurityAuditEvent` (event type, principal, action, resource, outcome, reason, correlation/endpoint/assessment/work/message IDs, `organization_id`, `user_id`, redacted metadata) goes to `security_audit_events` via `append()` in **its own transaction**.
- **Classification:** OPERATIONAL, SECURITY, or DIAGNOSTIC. `authorization.allowed` isn't persisted by default (`domain/audit.py:69-100`; `audit_policy.py`).
- **Read:** the tenant feed applies a mandatory `organization_id` predicate, allow-listed metadata projection, derived severity, and a 2,000-row bound on severity scans.
- **Telemetry:** process-local sliding windows produce security signals (denial spikes, repeated authentication failures, cross-tenant probing) at `/security/metrics`.
- **Integrity:** none. There is no hash chain, signature or anchor. A legacy JSONL hash-chain logger exists (`core/security/audit_logger.py`, plus the `audit_logs` table holding 0 rows) but isn't wired in. Accepted risk today: "Database administrators can modify persisted data."
- **Retention:** none.
- **Defects:**
  - Volume from agent authentication successes (F-12).
  - Dual-write without atomicity.
  - `SYSTEM` attribution on human-initiated dispatch.
  - Unattributed rows (NULL org) grow invisibly, since tenants never see them and nothing prunes them.

---

## 10. Current frontend architecture

- **Stack:** React, TypeScript and Vite; `lucide-react`; `framer-motion`; no router library (a roughly 40-line hash router); no state library; hand-rolled SVG charts. **Every dependency is pinned to `"latest"`** (`frontend/package.json`).
- **Structure:**
  - `types/api.ts` holds wire types mirroring `to_dict()`.
  - `api/client.ts` handles fetch, `ApiError`, and a `sessionStorage` token.
  - `api/endpoints.ts` holds typed route bindings.
  - `hooks/useApi.ts` provides aborting loaders and polling that pauses when the tab is hidden.
  - `components/ui.tsx` is the design system.
  - `features/*` has one module per screen.
- **Navigation:**
  - Command Center
  - Operations: Fleet, Assessments, Schedules, Groups & Scopes
  - Security: Findings, Activity, AI Analyst
  - Governance: Compliance, Reports
  - Administration: Settings
- **Polling:**
  - Command Center: 30 s
  - Fleet: 45 s
  - Assessments: 8 s while any is active, otherwise 45 s
  - Active assessment detail: 6 s
  - Activity feed: 20–30 s
- **Gaps:**
  - No screens for enrollment, agents, endpoint approval or users and roles.
  - The scanner catalogue is a client constant (GAP-1).
  - Findings is a recent window, not a backlog (GAP-3).
  - The Analyst page is a scaffold (GAP-2).
  - No tests (`tsc` and the build are the only gates).
  - Production hosting of `dist/` is undefined.
- **Offline:** fully self-contained, with no CDN or font fetches (`index.html`). Good.

---

## 11. Current testing architecture

| Aspect | State |
|---|---|
| Runner | pytest 9.0.2, Python 3.11.9 (`.venv-ravenx`); `pytest.ini` excludes venvs and the nested clone |
| Size | 81 files, 371 functions, **412 cases**, 67 s |
| Unit | Domain invariants; services with in-memory repositories and fakes; protocol; RBAC; audit policy; telemetry |
| Integration | SQLAlchemy repositories on temporary SQLite files; FastAPI routes via TestClient or httpx ASGI; HTTP agent transport end to end in-process; audit signal quality |
| Isolation | Real-route tests inject temporary DB managers. The isolated run wrote nothing to `data/`. Importing `scanner` creates `raven_x.log` and `ml_models/` in the CWD. |
| Platform | Windows-only environment, because `requirements-dev.txt` pins pywin32 and customtkinter |
| Not covered | Real Windows check execution (mocked); time-based behavior at scale (presence decay, timeouts); restart and recovery scenarios; concurrency and threading against a file DB; performance and volume; frontend |
| CI | `.github/workflows/test.yml` (windows-latest, compileall, pytest) is **untracked**, so CI runs nowhere |

---

## 12. Current deployment architecture

- **Dev:** `run.py --mode backend|gui|all` runs uvicorn `--reload` on `0.0.0.0:8000`, and `npm run dev` serves the SPA on :5173 with a proxy (`.claude/launch.json` `ravenx-ui`).
- **Documented production topology:** HTTPS reverse proxy → API → shared DB, with exactly one scheduler instance (`docs/deployment/production.md`). Nothing in the repo implements TLS, the proxy, service registration or SPA serving.
- **`docker-compose.yml` is broken.** It references `docker/Dockerfile.backend` and `docker/nginx.conf`, which don't exist, plus a Redis that no code uses.
- **Dependencies:**
  - `requirements.txt` is a 1,105-line environment dump.
  - `requirements-dev.txt` is curated, but it mixes server, agent and legacy-GUI dependencies.
  - No `agent` dependency set exists.
- **Config:** `config/config.yaml` and `raven_x_config.json` are both read relative to the CWD. Secrets come from env vars only.
- **Repository hygiene:** the enterprise code is untracked (F-14). There is a nested older clone, `Raven-x-enterprise/`, with its own `.git`; a 45 MB `Raven-x-enterprise.zip`; and tracked DB WAL/SHM files.

---

## 13. Gap analysis: current vs. target

### 13.1 Topic-by-topic

| Topic | Current | Gap vs. target | Sev. | Fix |
|---|---|---|---|---|
| **Endpoint identity** | Server-assigned UUID; scrypt-verified opaque credential; rotation and revocation in the service | No machine fingerprint, so a re-imaged PC re-enrolls as a new endpoint. Status stuck at `new`. No trust state ("registered ≠ trusted"). | High | WS-08, WS-09 |
| **Agent lifecycle** | Library with in-memory identity; no loop, service, outbox or version reporting | A Windows service with persistent DPAPI identity, run loop, backoff and jitter, local outbox, health and version reporting | **Blocker** | WS-07 |
| **Fleet management** | Fleet query, presence summary, endpoint detail | Presence is wrong (F-4). No agent health, version or skew view. No approve, revoke or decommission routes. Inventory frozen at enrollment. | High | WS-05, WS-08, WS-09 |
| **Endpoint groups** | Static groups and dynamic scopes; schedule targeting | Groups capped at 200. No group-scoped RBAC. No enrollment-into-group. | Med | WS-08, WS-15 |
| **Assessment orchestration** | Human and scheduled dispatch through durable work; 4 scanners | Offline delivery broken (F-6). Assessments never converge to terminal (F-5). No profiles. No scanner discovery. | **Blocker** | WS-05, WS-06, WS-13 |
| **Concurrent assessments** | Agent rejects a second dispatch while BUSY; server overlap via `skip_if_active` | Agent loop must not poll while busy. Overlap check O(history). No per-scanner timeout at service level. A scheduled burst for 70 PCs is fine once results are transactional. | Med | WS-07, WS-13 |
| **Job queues** | Per-endpoint work table only; scheduler thread opt-in | No job host or job leases. Maintenance never runs. | **Blocker** | WS-05 |
| **Retry and idempotency** | Pre-ACK lease retry (3 attempts); occurrence idempotency; replay guard | Replay claim burns IDs on failure; duplicate result returns 409; no agent outbox; non-atomic multi-repo writes | High | WS-07, WS-10 |
| **Heartbeat handling** | Server-receipt clock; ONLINE upsert; session update | Never decays (F-4). Writes 2 audit rows. Polls aren't treated as liveness. No skew reporting. | High | WS-02, WS-05, WS-06 |
| **Offline endpoints** | Work stays queued (no TTL configured) | Stale-dispatch rejection (F-6); no business TTL; no "delivered late" semantics | **Blocker** | WS-06 |
| **Server restart recovery** | Durable work, assessments and schedule occurrences; coalesced misfire | In-memory session registry lost (benign). Schema upgrades diverge (F-8). No reconciliation pass at startup. Scheduler disabled by default. | High | WS-04, WS-05 |
| **Agent restart recovery** | None. Identity, credential and in-flight results are lost. | DPAPI store; outbox replay; ACKed-but-unfinished work handled through timeout plus re-dispatch policy | **Blocker** | WS-07, WS-05 |
| **Result ingestion** | Synchronous handler on the event loop; `result_json` blob; 3 transactions | Single unit of work; idempotent acceptance by digest; normalize findings; update summaries at ingest | High | WS-10, WS-11 |
| **Finding lifecycle** | None. Occurrences derived on read; candidate fingerprints; coverage eligibility. | `Finding` entity with lifecycle, exceptions and backlog; auto-resolve only on strong absence (reuse coverage contracts) | High | WS-11 |
| **Compliance aggregation** | Evaluates from assessment history per endpoint; hard 100-endpoint cap; 4 controls | Evaluate from a "latest evidence per endpoint×scanner" table; remove the cap; more controls as more scanners are promoted | Med | WS-12, WS-18 |
| **Remediation workflow** | Legacy unauthenticated execution on the server host; enterprise: none (by design) | Disable the legacy surface. Add a non-executing remediation-task workflow tied to findings, verified by re-scan. Defer execution. | **Blocker (security)** / Med | WS-01, WS-17 |
| **Audit integrity** | Append-only by convention; no chain; no retention; dual-write | Per-org hash chain written in the same transaction; anchors; retention by class; drop noise; correct attribution | Med | WS-14 |
| **Tenant isolation** | Strong on human routes; agent cross-checks; SQL predicate on the feed | Keep. Extend the same discipline to new routes (enrollment keys, findings, admin). Add group scope. | Low | WS-08, WS-15 |
| **RBAC** | Engine ready; no admin, no templates, no sub-org scope | Templates (Owner, Security Admin, Technician, Auditor, Viewer); admin API and UI; group-scoped bindings; per-request permission cache | High | WS-08, WS-15 |
| **Scalability** | F-1, F-2, F-3, F-9, F-10, F-12 | O(1) per-request auth; threadpool DB; summary tables; pagination; caps removed (§19) | **Blocker** | WS-02, WS-03, WS-12 |
| **Database indexing** | Many single-column indexes; missing hot-path composites; audit over-indexed | Composite indexes per §19.4; trim audit indexes | Med | WS-04, WS-12 |
| **Pagination** | Audit, snapshots and group members paginated; fleet pages in Python; assessments, schedules, runs, endpoints and memberships unpaginated | Keyset pagination for assessments, findings and audit; SQL paging for fleet | High | WS-12 |
| **API performance** | Loop-blocking sync calls; repeated authorization reads; result blobs in lists | Threadpool offload; projections without `result_json`; permission cache; summary reads | High | WS-03, WS-12 |
| **Local LLM integration** | Legacy LM Studio client behind unauthenticated routes; prompts carry raw details plus system info | An advisory AI service in the monolith: off by default, LAN-allow-listed, minimized and redacted input, provenance, human approval for anything actionable | Low (P2) | WS-16 |
| **Privacy boundaries** | No default egress (good); evidence is legacy free text; no retention; operator PII in audit metadata (projected out of the feed) | Data classification, retention per class, evidence minimization at the agent, AI redaction, export auditing | Med | WS-14, WS-16, §17 |

### 13.2 Restart and recovery scenarios walked through

| Scenario | Today | After the P0 and P1 work |
|---|---|---|
| Server restarts mid-schedule run | The run resumes. The overlap check prevents most duplicates. | Same, plus outcomes persisted in chunks and a reconcile pass at startup |
| Server down for 3 days | Schedules coalesce (good). Agents fail silently (there's no agent). | Agents back off with jitter and buffer results; work TTLs expire stale requests explicitly |
| PC off overnight with work queued | The work is rejected as stale, fails after 3 leases, and the assessment stays `queued` forever, blocking the schedule | Delivered at boot, or expired with an explicit reason |
| Agent crashes after ACK | Assessment `running` forever; endpoint blocked forever | Timeout → `timed_out` (terminal for overlap); next occurrence proceeds; a late result is still accepted |
| PC re-imaged or reboot-restored (Deep Freeze is common in labs) | Identity lost; a duplicate endpoint on re-enroll (manual) | Fingerprint match flagged; operator-approved "replace endpoint" keeps the history; agent state stored where reboot-restore doesn't wipe it, or re-enrollment is automatic under policy |
| Lab PC clock drifts 12 min (no Internet NTP) | Every message rejected `stale_or_future_message` | Agent applies the server-time offset; heartbeat reports skew; the UI flags drift |

### 13.3 What should remain untouched (global)

- `scanner.py` check logic and GUI (personal-mode source of truth). WS-07 allows one exception: behavior-preserving lazy imports and moving logging setup.
- Domain invariants and transition tables: extend them, never loosen them.
- The `OrganizationRbacAuthorizer` deny and attribution logic, and the `OrganizationContextResolver`.
- The protocol envelope validation core. Evolve it by version, and keep every existing check except the one corrected in WS-06.
- The conditional-claim leasing logic.
- Compliance evaluator semantics and coverage-contract semantics.
- The audit feed projection and allow-list (`domain/audit.py`).
- The frontend design system and hooks (`components/ui.tsx`, `hooks/useApi.ts`), and the honest-state UX.
- The existing test suite. Every change must keep it green.

### 13.4 Stale documentation, for awareness

- `current-enterprise-implementation-status.md` is wrong on several points:
  - It says 275 tests; there are 412.
  - It describes five placeholder screens; they are implemented.
  - It lists `/enroll`, `/ack` and `/fail` agent routes; they don't exist.
  - It calls the password hashing bcrypt; it is scrypt.
  - It describes the SQLite database as Postgres-ready; Postgres is not validated.
- `feature-status-matrix.md` marks "Endpoint agent and remote assessment" READY. It is PARTIAL: there is no deployable agent.

---

# Part II: Target platform

## 14. A. Target architecture

**Shape: one modular-monolith server, one headless Windows agent, one SPA, and an optional local LLM.** There are no new services. Everything below is a module or a process *role* inside the existing codebase.

```
                 LAN only (Internet optional, never required)
┌──────────────────────── RAVEN-X Server (one Windows/Linux host) ─────────────────────────┐
│ Process: ravenx-server (Windows service or systemd), uvicorn workers=1 (SQLite)           │
│                                                                                           │
│  HTTPS (local CA)                                                                         │
│   ├─ /            SPA static files (served by FastAPI StaticFiles)                        │
│   ├─ /api/v1/*    Human API: auth · orgs/users/roles · fleet · enrollment · assessments · │
│   │               schedules · findings · compliance · reports · audit · system            │
│   └─ /api/v1/agent/*  Agent API: enroll · messages · work (server_time, next_poll_after)  │
│                                                                                           │
│  Application modules (existing layering)                                                  │
│   identity · org/rbac · enrollment · endpoint+inventory · fleet/groups · assessment ·     │
│   scheduling · ingestion · findings · compliance · reporting · audit · ai-advisory (opt)  │
│                                                                                           │
│  Job host (in-process thread; DB-leased; restart-safe)                                    │
│   schedule-runner 30s · reconciler 60s · presence 30s · work-expiry 60s · purge-replay    │
│   5m · purge-sessions 1h · audit-retention 24h · result-retention 24h · compliance        │
│   retention 24h · backup 24h · ai-jobs (opt)                                              │
│                                                                                           │
│  Persistence: SQLAlchemy sync repositories in a threadpool, unit of work on the ingest    │
│  path, Alembic migrations                                                                 │
│   SQLite WAL (default; per-thread connections, busy_timeout, FKs on) │ PostgreSQL (opt.)  │
└───────────────▲─────────────────────────────────────────────────────────────▲─────────────┘
                │ outbound HTTPS poll only (no listener on endpoints)          │ HTTP (LAN allow-list)
┌───────────────┴──────────── Windows endpoint × 70 ───────────────┐  ┌──────┴───────────────┐
│ ravenx-agent (Windows service, LocalSystem)                       │  │ Local LLM (optional) │
│  identity+credential: DPAPI (machine scope) in %ProgramData%      │  │ Ollama / LM Studio / │
│  loop: heartbeat 60s±10% · poll per server hint · backoff+jitter  │  │ llama.cpp (OpenAI-   │
│  executor: scanner adapters, per-scanner timeouts, read-only      │  │ compatible API)      │
│  outbox: durable queue of results/progress, idempotent replay     │  └──────────────────────┘
│  clock: server-time offset applied to message timestamps          │
└───────────────────────────────────────────────────────────────────┘
```

**Principles**

1. **Same codebase, process roles.** `ravenx-server` hosts the API and the job host. Past about 500 endpoints the same code can run `--role api` (N workers, Postgres) and `--role jobs` (1 process). There is no new service boundary.
2. **The DB is the coordination point.** Job leases, work leases, idempotency keys and summary tables live in the DB. There is no broker.
3. **The agent is a dumb, safe executor.** It exposes no inbound port and no generic commands, runs read-only checks, and is fully restartable.
4. **The server-receipt clock is authoritative.** Agent time is observational, with the offset corrected.
5. **Everything degrades gracefully offline.** No feature needs the Internet, and AI is never required.

## 15. B. Target domain model

New or changed elements are marked ★.

```
Organization ─┬─ User ─ Session(★lookup_hash) ─ ★TotpFactor(P2)
              ├─ Membership ─ RoleBinding(★scope: org | endpoint_group) ─ Role(★template_key)
              ├─ ★Site/Lab = EndpointGroup(kind=static) · SavedFleetScope(kind=dynamic)
              ├─ ★EnrollmentKey (multi-use: max_uses, use_count, ttl, target_group,
              │                  approval_policy: manual|auto) → replaces single-use tokens
              ├─ Endpoint ★trust_state: pending_approval → active ⇄ quarantined → decommissioned
              │     │                                    └────────────→ revoked
              │     ├─ EndpointCredential(★lookup_hash)
              │     ├─ ★MachineFingerprint (SMBIOS UUID + MachineGuid + MAC hash; duplicate
              │     │                       detection only, never trust)
              │     ├─ ★EndpointInventory (versioned snapshot: OS build, agent version, hostname,
              │     │                       IPs, security products, last boot, clock skew)
              │     └─ Presence (derived from last contact; ONE liveness model; EndpointStatus
              │                  OFFLINE/DEGRADED retired)
              ├─ ★AssessmentProfile (named scanner set + options + per-scanner timeout)   (P2)
              ├─ AssessmentSchedule(target, ★profile_id) ─ ScheduleRun
              ├─ Assessment (★moved to domain; + ★timed_out terminal; ★deadline)
              │     ├─ WorkItem (delivery; ★business TTL)
              │     ├─ ★AssessmentResult (immutable raw result, digest, retention-managed)
              │     └─ ★FindingOccurrence (immutable; occurrence_id, fingerprint?, evidence ref)
              ├─ ★Finding (logical: endpoint × fingerprint)
              │     state: open → acknowledged → resolved(auto, strong absence) → reopened
              │            open → risk_accepted(expiry, approver) | false_positive(justification)
              │     └─ ★FindingStateChange (who/why; audited)
              ├─ ★EndpointPosture (summary: open counts by severity, last assessment, last
              │                     evidence per scanner) — maintained at ingest
              ├─ Compliance: Framework/Control (catalog) · ControlEvaluation (derived from
              │              ★LatestEvidence) · Snapshot (immutable, digest)
              ├─ ★RemediationTask (P2: linked to finding; assignee, due, status; verified by
              │                    re-scan; no execution)
              ├─ ★AiAdvisory (P2: scope, model, input digest, output, created_by; advisory only)
              └─ AuditEvent (★seq, ★prev_hash, ★entry_hash per org) · ★AuditAnchor
System: ★JobLease(name, holder, lease_until, last_run, last_status)
```

**State machines that matter most**

```
Endpoint:   pending_approval ──approve──► active ──quarantine──► quarantined ──release──► active
                │                           │                       │
                └────────reject─────────────┴──decommission/revoke──┴──► decommissioned | revoked
            (pending: heartbeat accepted and visible; no work leased; results rejected)

Assessment: created → queued → dispatched → running → completed | failed
                  │        │          │          └─(timeout)─► timed_out (terminal for overlap;
                  │        │          │                         a late result upgrades it to completed)
                  │        └──────────┴─► delivery_failed | expired | cancelled
Finding:    (first occurrence) open ──(strong absence per coverage contract)──► resolved
            resolved ──(re-observed)──► open (reopened_count++)
            open ──(human, RBAC)──► risk_accepted [expires_at] | false_positive
            risk_accepted ──(expiry)──► open
```

## 16. C. Trust boundaries

```
 [Operator browser]──TB1──►[ RAVEN-X Server ]◄──TB2──[ Agent (SYSTEM) ]──TB5──►[ Windows OS ]
                               │      │    ▲
                              TB3    TB4   TB6 (local admin console / CLI)
                               ▼      ▼
                         [DB + files] [Local LLM]          TB7: Server ↔ Internet = none by default
```

| Boundary | Trust assumption | Controls |
|---|---|---|
| **TB1** browser ↔ server | Browser and LAN untrusted | TLS (local CA); opaque bearer session; org context and RBAC on every route; CSP and security headers; same-origin CORS; login and enrollment rate limits |
| **TB2** agent ↔ server | Agent data is **untrusted observation**; an enrolled endpoint is not trusted until approved | TLS with a pinned local CA; per-endpoint credential (fast keyed lookup); envelope validation; replay guard; payload bounds; approval gate; endpoint-scoped authorization; results can never change server config |
| **TB3** server ↔ DB/files | Host trusted; DB admin *could* tamper | Audit hash chain and anchors make tampering evident; verifiers only, never raw secrets; ACL'd data dir; encrypted backups (P2) |
| **TB4** server ↔ local LLM | Semi-trusted LAN service; **output untrusted**: endpoint-sourced evidence can carry prompt injection | Off by default; base-URL allow-list (localhost/RFC1918); minimized and redacted input; output stored as advisory text, never executed and never used for authorization |
| **TB5** agent ↔ OS | Agent runs as SYSTEM with a large blast radius | Read-only scanner adapters; no command channel; no inbound listener; per-scanner timeouts; signed MSI (P2) |
| **TB6** local console | Physical or RDP admin on the server host | Bootstrap and backup CLIs require local admin; actions audited |
| **TB7** Internet | Not required | No telemetry, update checks or CDNs; SMTP or webhooks only if explicitly configured |

## 17. D. Security model

1. **Identities.** `HUMAN` (password, plus TOTP in P2), `ENDPOINT` (credential bound to EndpointId), `SYSTEM` (job host). AI is never a principal.
2. **Authentication.**
   - Passwords: scrypt (keep).
   - Session tokens and agent credentials: these are 256-bit random secrets, so use an **indexed HMAC-SHA256 lookup hash** with constant-time compare. Measured at 1.24 µs against 38.5 ms for scrypt; a slow KDF adds nothing for high-entropy tokens.
   - Purge expired and revoked sessions.
3. **Authorization.**
   - Org-scoped RBAC with templates.
   - Optional group scope on bindings.
   - Sensitive actions require explicit permissions: enrollment keys, approve or revoke endpoints, role admin, exports, risk acceptance.
   - The two-person rule is optional for risk acceptance (P2).
4. **Endpoint trust.** Enrollment produces `pending_approval` unless the key's policy says auto-approve. Quarantine stops work and flags results. Revocation kills credentials immediately; this already holds in the model.
5. **Transport.**
   - The server presents a certificate from a local CA generated at install.
   - The agent installer embeds the CA bundle (the `verify=<path>` path already exists).
   - Per-agent mTLS comes later.
6. **AI rules.** Advisory only, opt-in, LAN-only, redacted. Outputs are labelled and kept with provenance. Any action derived from AI goes through the same human-approved, RBAC-checked workflow as a human proposal. This holds North Star line 64: "AI must never independently authorize destructive actions."
7. **Safe defaults.**
   - Legacy routes off in server mode, and refused in production.
   - No unauthenticated WebSocket.
   - `workers=1` enforced with SQLite.
   - The config-file `environment` value honored.
   - CORS same-origin.
8. **Audit.**
   - Every state change by a human or the system is audited in the same transaction.
   - A per-org hash chain.
   - Daily anchors exported to a file and shown in the UI.
   - Denials are always kept; success telemetry stays out of audit.
9. **Privacy.**
   - Data classes: credentials (secret); audit (PII, since it holds operator emails); findings and evidence (sensitive); inventory (internal).
   - Retention per class.
   - Agent evidence is minimized: no file contents, no browsing history, no student usernames beyond counts unless a check requires them.
   - Exports are audited.
10. **Rate limits and bounds.** Login (exists), enrollment per source IP, agent auth failures per endpoint and IP, and the payload bounds that already exist.

## 18. E. Offline-first model

| Condition | Required behavior | Mechanism |
|---|---|---|
| No Internet | 100% of features work | Already true at the core. Keep CI checks that forbid new egress (an import/egress test). |
| Server unreachable | Agents keep retrying with backoff and buffer unsent results. No autonomous local scans in P0/P1: work only comes from the server. | Agent outbox (durable, bounded about 50 MB, oldest-first drop with a counter); exponential backoff 5 s → 5 min with ±20% jitter |
| Endpoint powered off | Queued work waits until a business TTL, then expires explicitly | `work_ttl` (manual 24 h; scheduled = min(next occurrence, 72 h)); the agent validates the deadline, not the envelope age |
| Agent restart | No re-enrollment; resume outbox; never re-run ACKed work implicitly | DPAPI store; outbox replay with idempotent server acceptance; the server times out ACKed work |
| Server restart | Nothing lost; maintenance resumes | DB-leased jobs; reconcile at startup; Alembic at startup with a backup first |
| Clock drift (no NTP) | Messages accepted; drift visible | `server_time` in every agent response; the agent stamps `timestamp = local + offset`; heartbeat reports skew; the UI flags skew over 2 min |
| Reboot-restore or re-image | Endpoint continuity without trusting the fingerprint | Agent data on a thawed or persistent path when available; otherwise auto re-enroll under key policy, with a fingerprint-match "replace" suggestion for the operator |
| LLM host down | Everything except AI advice works; the AI UI shows unavailable | AI behind a feature flag and job queue with timeouts |
| Disk or DB failure | Bounded loss | Nightly `VACUUM INTO` backups with retention; restore runbook (exists) plus a restore test |

## 19. F. Scalability strategy

### 19.1 Load model

Assumptions: heartbeat every 60 s, poll every 45 s idle, one assessment per endpoint per day, a result of about 20 KB.

| Endpoints | Agent req/s | Writes/s after fixes (steady) | Raw results per year | Current audit rows per year (F-12) | Audit rows per year after fixes |
|---:|---:|---:|---:|---:|---:|
| 70 | 2.7 | ~3 | 0.5 GB | **~123 M** (tens of GB) | ~100 k |
| 300 | 11.7 | ~12 | 2.2 GB | ~525 M | ~400 k |
| 1,000 | 38.9 | ~40 | 7.3 GB | ~1.75 B | ~1.3 M |

Current-code CPU ceiling: agent scrypt alone costs 2.7 × 38.5 ms ≈ 10% of a core at 70 endpoints and **≈ 150% at 1,000**, all on the event-loop thread. Human-request scrypt grows with every login (F-1).

### 19.2 Tiers

| Tier | Topology | Must-haves |
|---|---|---|
| **1–100** (reference lab) | 1 process; SQLite WAL; in-process job host | WS-02 (fast verifiers), WS-03 (threadpool plus per-thread connections), WS-05, WS-12 (pagination, no blobs in lists) |
| **100–500** | Same | Summary tables at ingest; retention of raw results (90 days); poll hints (`next_poll_after` 30–120 s); presence driven by any contact |
| **500–1,000+** | `--role api` × 2–4 workers plus `--role jobs` × 1; PostgreSQL | Postgres validated (WS-19); `SKIP LOCKED` work and job leasing; DB-backed rate limiter; agent liveness via the poll itself (drop separate heartbeats or slow them to 5 min) |

### 19.3 Per-request cost budgets (targets)

- **Heartbeat or poll:** O(1). One indexed credential lookup, one presence upsert, one indexed `SELECT … LIMIT 1` for work. No table scans and no audit row on success.
- **Result ingest:** one transaction, at most 1 MiB, with occurrences, finding upserts and posture update bounded by the result's finding count.
- **UI page:** at most about 10 indexed queries, at most 200 rows, never `result_json` in lists.

### 19.4 Indexes to add (WS-04/WS-12)

- `agent_work_items(endpoint_id, status, available_at)`
- `agent_work_items(status, lease_expires_at)`
- `remote_assessments(organization_id, requested_at DESC, assessment_id)`
- `remote_assessments(endpoint_id, requested_at DESC)`
- `remote_assessments(schedule_id, endpoint_id, status)`
- `human_sessions(lookup_hash UNIQUE)` and `endpoint_credentials(lookup_hash UNIQUE)`
- `endpoint_presence(organization_id, last_seen_at)`
- `findings(organization_id, status, severity)`
- `findings(endpoint_id, fingerprint UNIQUE)`
- `finding_occurrences(assessment_id)`
- **Trim** `security_audit_events` to `(organization_id, occurred_at)`, `(organization_id, event_type, occurred_at)`, `(endpoint_id)`, `(correlation_id)`

## 20. G. Frontend information architecture

```
Overview            Command Center (posture, presence with age, open findings by severity, schedule health,
                    agents needing attention: offline > 24 h, skew, outdated, pending approval)
Fleet               Endpoints (SQL-paged; filters: group, presence, trust state, OS, agent version)
                     └ Endpoint detail tabs: Overview · Inventory · Findings · Assessments · Compliance · Activity
                    Groups & Scopes (Labs/Sites)
                    Enrollment ★ (enrollment keys; approval queue; duplicate/fingerprint suggestions)
                    Agents ★ (versions, last contact, skew, outbox backlog, errors)
Assessments         Runs (paged) · Schedules (+ run history) · Profiles (P2)
Findings ★          Backlog (paged; status/severity/group/scanner/age) · Exceptions (risk accepted / false positive)
Compliance          Posture · Snapshots & history · Frameworks/controls
Remediation (P2)    Tasks (finding-linked, verified by re-scan; no execution)
Reports             Exports (compliance, findings, fleet; audited)
Activity            Audit feed · Security signals · Chain verification ★
AI Analyst (P2)     Hidden unless enabled; every output labelled "advisory"
Administration ★    Users · Roles & bindings · Organization · System (jobs, DB size, backups, version, CA download)
```

UX rules to keep: honest unavailable and forbidden states, server-side paging, abortable fetches, severity shown with more than colour, and no fabricated data.

UX rules to add:

- **"Data as of" stamps** on every derived number.
- **Confirmation with impact preview** for approve, revoke and bulk actions.
- **Staleness surfacing:** presence age and evidence age.
- **AI clearly separated** from facts.

---

## 21. H. Implementation roadmap: workstreams

Every workstream lists the same six fields: **Why**, **Extend**, **Leave untouched**, **Depends on**, **Tests**, **Migration risks**.

### WS-00 Version control and repository hygiene (P0, day 1)
- **Why:** About 20k lines of enterprise code plus 412 tests exist only in a OneDrive working tree (F-14). One sync conflict or deletion wipes the platform, and CI can't run.
- **Extend:**
  - `.gitignore`: add `data/*.db-wal`, `data/*.db-shm`, `*.zip`, `.venv-ravenx/`, `frontend/node_modules`, `frontend/dist`, `raven_x.log`.
  - `.github/workflows/test.yml`: commit it as is.
- **Leave untouched:** all code.
- **Depends on:** nothing.
- **Tests:** CI green on the first push; `git status` clean apart from local data.
- **Migration risks:**
  - `git rm --cached data/raven_x.db-*`. The WAL already committed in `b68c3fa9` holds DB pages from that date. Decide whether to rewrite history, or to treat any credentials in it as compromised and rotate them.
  - Move the nested older clone `Raven-x-enterprise/` and the zip **outside** the tree. Don't delete them until the commit is verified.
  - Commit in reviewable slices (domain → application → infrastructure → api → frontend → tests → docs).

### WS-01 Close unsafe defaults (P0)
- **Why:** An unauthenticated LAN client, or any web page a lab user opens (CORS `*`), can make the server run PowerShell on itself (F-13). There is also an unauthenticated `/ws/realtime`, and the config's `environment` is ignored (F-17).
- **Extend:**
  - `settings.py`: `enable_legacy_routes` default `false`; refuse in `production`; honor the config `environment` when the env var is unset; same-origin CORS by default.
  - `main.py`: `_mount_optional_router` binds legacy routes only when explicitly enabled. Remove `/ws/realtime` or require a session.
  - `run.py`: legacy GUI mode sets the flag explicitly.
- **Leave untouched:** the legacy route modules, `auto_fixer.py`, `scanner.py`. Personal mode runs `scanner.py` directly.
- **Depends on:** none.
- **Tests:**
  - Default app has no `/api/v1/remediation/*`, `/scan/*` or `/system/*` (404).
  - Production plus legacy-enabled refuses to start.
  - CORS preflight from a foreign origin is rejected.
  - The WebSocket requires auth, or is gone.
- **Migration risks:** Anyone relying on the legacy API from `frontend/gui/enhanced_gui.py` must set `RAVENX_ENABLE_LEGACY_ROUTES=true`. Document it.

### WS-02 Fast, O(1) verification of high-entropy secrets (P0)
- **Why:** F-1 (O(sessions) scrypt; unauthenticated DoS) and F-2 (scrypt per agent contact). Measured: 38.5 ms against 1.24 µs.
- **Extend:**
  - `infrastructure/security/secret_verifiers.py`: add `token_lookup_hash(secret)` (HMAC-SHA256 with an install-time key in the protected data dir, or SHA-256 for agent credentials) and a constant-time compare.
  - `HumanSessionRecord` and `EndpointCredentialRecord`: add a `lookup_hash` column (unique index).
  - `SQLAlchemyUserRepository.get_session_for_token`: indexed lookup.
  - `EnrollmentService.verify_credential`: lookup by hash.
  - A session purge job (WS-05).
- **Leave untouched:** `PasswordHasher` (scrypt for passwords); session semantics; HTTP contracts.
- **Depends on:** WS-04 preferred. The existing additive-ALTER pattern works if WS-04 slips.
- **Tests:**
  - Query-count test: auth is 1 indexed query regardless of session count.
  - An invalid token does no scrypt.
  - Revoked and expired sessions are rejected.
  - Old-format sessions are rejected (forced re-login).
  - Old agent credentials are lazily upgraded on the next successful scrypt verification.
  - The lookup key is never logged.
- **Migration risks:**
  - All human sessions are invalidated once, which is acceptable at 8 h lifetimes.
  - Losing the HMAC key invalidates agent credentials, forcing re-enrollment. Use plain SHA-256 for agent credentials (256-bit entropy makes offline brute force infeasible), or back the key up with the DB.

### WS-03 Database runtime correctness (P0)
- **Why:** F-3 (event-loop blocking; one shared connection across threads) and F-11 (multi-worker).
- **Extend:**
  - `core/database/database.py`: for file SQLite, drop `StaticPool` and use the default per-thread pool. Set pragmas on connect: `busy_timeout=5000`, `foreign_keys=ON`, WAL. Make paths absolute from a configured data dir.
  - Route handlers: call services through one helper (`await run_in_threadpool(...)`) in `human_control_plane.py` and `transport/http/server.py`, or declare the handlers `def`.
  - Startup guard: SQLite requires `workers == 1`. Set `config.yaml` `workers: 1`.
- **Leave untouched:** repository query logic, services, domain.
- **Depends on:** none.
- **Tests:**
  - Concurrent HTTP requests against a file DB (threads) don't corrupt or interleave.
  - Scheduler thread plus requests run concurrently.
  - The `workers>1`-with-SQLite guard works.
  - `PRAGMA foreign_key_check` on the dev DB copy is clean.
- **Migration risks:** turning on `foreign_keys` can surface orphan rows. Run `foreign_key_check` first and repair or archive them before enabling (enabling FKs touches no data).

### WS-04 Versioned migrations (P0)
- **Why:** F-8. Every following workstream adds columns or tables, and today there are two diverging ALTER paths.
- **Extend:**
  - Add Alembic (pure Python, offline) under `backend/infrastructure/persistence/migrations/`.
  - Baseline equals the current models. Fold both ad-hoc upgrade functions into revision 0001 as idempotent steps.
  - `ravenx db upgrade` CLI; startup runs `upgrade head` after an automatic `VACUUM INTO` backup.
- **Leave untouched:** ORM models as the source of truth; `DatabaseManager` API.
- **Depends on:** WS-00.
- **Tests:**
  - Migrating an empty DB yields the `create_all` schema (compare `sqlite_master`).
  - Migrating a fixture copy of a Phase-3 DB, including the dev DB shape, succeeds and is idempotent.
  - A failed migration leaves the backup intact.
- **Migration risks:** existing installs need `alembic stamp` after verification. SQLite `ALTER` limits mean using batch mode. Keep the `create_all` path for tests only.

### WS-05 Job host with DB leases (P0)
- **Why:** F-4 and F-5. Maintenance never runs; dead PCs show online; stuck assessments starve schedules forever. It also enables session, replay and audit purges and retention.
- **Extend:**
  - Generalize `AssessmentScheduleWorker` (already robust) into `JobHost` with registered jobs `(name, interval, jitter, callable)`.
  - Add a `job_leases` table so a second process can't double-run a job.
  - Register:
    - `AssessmentScheduleRunner.run_once`
    - `RemoteAssessmentReconciler.reconcile_all`, with an execution timeout that becomes a **new terminal `timed_out`**
    - `PresenceMaintenanceRunner.run_once`
    - work expiry (move `release_expired_leases` **off the poll path**)
    - `SQLAlchemyReplayGuard.purge_expired`
    - session purge
    - `ComplianceSnapshotRetentionRunner`
  - Expose status via `/ready` details and an admin route.
  - Also compute presence **at read time** from `last_seen_at`, so the UI is right even if a job lags.
- **Leave untouched:** runner, reconciler and presence semantics apart from the timeout terminal state; the calculator.
- **Depends on:** WS-03 (thread-safe DB).
- **Tests:**
  - Fake-clock tests: online → stale → offline; FAILED work → `delivery_failed`; ACKed work past the timeout → `timed_out`, then the next occurrence dispatches.
  - The lease prevents a double run.
  - One failing job doesn't stop the others.
  - A late result upgrades `timed_out` to `completed`.
  - Startup reconcile pass.
- **Migration risks:**
  - New terminal state: update `_TERMINAL_ASSESSMENT_STATES`, the repository conflict rule (allow `timed_out` → `completed`), the UI vocabulary and compliance (treat `timed_out` as incomplete evidence).
  - Choose a generous default timeout (2 h).
  - Presence will suddenly show offline machines. That's correct, but tell operators.

### WS-06 Offline-safe delivery and clock handling (P0)
- **Why:** F-6 and F-16. Powered-off PCs never receive queued work, and drifting clocks get silently rejected.
- **Extend:**
  - `transport/http/server.work`: return `{message, work, server_time, next_poll_after}`.
  - `agent/runtime.handle_dispatch`: apply the skew check to the **lease response**, not the stored dispatch timestamp. Validate the dispatch `deadline` and work `expires_at`, endpoint binding, direction and lease metadata.
  - `assessment_dispatch`: pass `work_ttl` from settings (`main.py` currently passes none).
  - `client.poll_work`: carry `server_time` and compute the offset.
  - Agent envelopes use the corrected time.
  - Heartbeat payload gains `clock_offset_ms`.
  - Protocol `1.1` (minor bump; still compatible with `1.0`).
- **Leave untouched:** replay guard and ±5 min validation for agent→server messages (with corrected clocks this becomes reliable); lease semantics.
- **Depends on:** none. It can ship before WS-07.
- **Tests:**
  - Dispatch at T, poll at T+8 h → executes.
  - Expired work is never delivered and is reported `expired` by the reconciler.
  - An agent with +20 min skew is accepted after one poll.
  - A replayed old `/work` response is rejected by lease-token checks.
  - Update `test_agent_runtime.py:117` to the new rule.
- **Migration risks:** none in the field, since no deployed agents exist. Keep `1.0` acceptance on the server.

### WS-07 Minimum viable Windows agent service (P0)
- **Why:** No deployable agent exists (§13.1 agent lifecycle and agent restart recovery).
- **Extend:**
  - `backend/agent/service.py`: run loop over the existing `RavenXAgent` and `HeartbeatScheduler` (heartbeat 60 s ±10%, poll per `next_poll_after`, no polling while busy, exponential backoff with jitter).
  - `DpapiCredentialStore` and `DpapiIdentityStore` (pywin32 `win32crypt`, machine scope) under `%ProgramData%\RAVEN-X\agent\` with a SYSTEM/Administrators ACL.
  - A durable outbox (small SQLite file) for ack, progress and result, with idempotent replay.
  - A `win32serviceutil` wrapper.
  - `HttpAgentTransport.enroll()` and `POST /api/v1/agent/enroll` → the existing `EnrollmentMessageProcessor`.
  - Service CWD is set to the data dir.
  - Fix F-15 with a behavior-preserving change to `scanner.py`: move the GUI/AI imports into the GUI/AI classes, and move `logging.basicConfig` into `main()`, guarded by the existing characterization tests. Alternatively, use an agent-side import shim (not recommended long-term).
  - `requirements-agent.txt`.
- **Leave untouched:** protocol envelope, processor pipeline, `LocalAssessmentOrchestrator`, adapters, `scanner.py` check logic.
- **Depends on:** WS-02, WS-06, and WS-08 (enrollment keys).
- **Tests:**
  - Fake clock and transport: network down → backoff; restart → same identity, no re-enroll; result buffered across a restart is delivered exactly once.
  - No listening socket is opened.
  - Nothing is written to the CWD.
  - DPAPI round-trip (Windows-marked test).
  - A manual pilot on 2–3 lab PCs.
- **Migration risks:**
  - Running as SYSTEM magnifies agent bugs. Keep the "no command channel" invariant enforced by tests.
  - Reboot-restore labs wipe `%ProgramData%`. Document the persistent-path option and rely on WS-09 re-enrollment policy.
  - Packaging: pilot with an offline PowerShell installer (embeddable Python plus wheels); MSI comes in P1.

### WS-08 Onboarding and administration API (P0 for bootstrap, enrollment keys and approval; P1 for full admin)
- **Why:** There's no production way to create the first admin, org or roles, to issue enrollment keys, or to approve endpoints. North Star: "A registered endpoint is not automatically trusted."
- **Extend:**
  - `python -m backend.cli bootstrap` using `HumanIdentityService.create_initial_user`, `OrganizationService`, `RoleService`, `RoleBindingService`, plus built-in **role templates**.
  - `EnrollmentAuthorization` becomes multi-use: `max_uses`, `use_count`, `target_group_id`, `approval_policy`, with an atomic conditional increment.
  - Human routes:
    - enrollment keys (create, list, revoke; the secret is shown once)
    - approve, reject, quarantine, decommission
    - credential rotate and revoke (`TenantEndpointService.revoke` and `EnrollmentService.rotate_credential` already exist)
  - P1: users, roles and bindings routes (GAP-6).
  - Split `human_control_plane.py` into per-area routers as routes are added (no behavior change).
- **Leave untouched:** context resolver; authorizer core; existing routes and response shapes.
- **Depends on:** WS-02, WS-04, WS-09 (trust state).
- **Tests:**
  - Every new route: cross-org 403/404, missing permission 403, audit with **human** attribution.
  - Concurrent enrollment against a key's last use: exactly one succeeds.
  - A pending endpoint gets no work and its results are rejected.
  - Key secrets are never logged or returned twice.
  - The bootstrap CLI is idempotent and refuses to run if users already exist.
- **Migration risks:** existing seeded endpoints map `NEW` → `active`. Multi-use keys raise the impact of a leak, mitigated by TTL, max uses, the approval queue and revocation.

### WS-09 Endpoint identity, trust state and inventory (P0 for trust state; P1 for inventory and fingerprint)
- **Why:** Status is stuck at `new`, there are three liveness models, inventory is frozen, and labs re-image PCs.
- **Extend:**
  - `domain/endpoint/models.py`: `trust_state` transition table; retire `EndpointStatus.OFFLINE`/`DEGRADED` in favor of presence.
  - Handlers persist agent version and protocol from heartbeats, and the capability/inventory report to `EndpointInventory`.
  - Fingerprint captured at enrollment.
  - Fleet filters by trust state, version and skew.
- **Leave untouched:** `EndpointId`, credential model, presence evaluator.
- **Depends on:** WS-04.
- **Tests:**
  - Transition table.
  - Inventory updates are idempotent and bounded.
  - Duplicate fingerprints are flagged but never merged automatically.
  - Revoked endpoints can't become present (already exists; keep it).
- **Migration risks:** enum change (`new` → `active` backfill). Cloned images without sysprep share `MachineGuid`, so include the SMBIOS UUID and treat fingerprints as hints only.

### WS-10 Ingestion unit of work and idempotency (P0 for idempotent results and claim ordering; P1 for full unit of work)
- **Why:** F-7. Partial failures leave inconsistent state, and retries get rejected.
- **Extend:**
  - `DatabaseManager.unit_of_work()`. Repositories on the ingest path (work, assessment, replay, audit and later findings) accept an optional `session`.
  - `AgentMessageProcessor` claims replay **inside** the same unit of work as the handler.
  - The result handler returns `accepted_duplicate` when the stored result digest matches.
- **Leave untouched:** domain, protocol shapes, other repositories (migrate them opportunistically).
- **Depends on:** WS-03, WS-04.
- **Tests:**
  - Fault injection after `work.complete` → nothing committed.
  - Retrying the same `message_id` after a failure succeeds.
  - A duplicate result → 200 duplicate.
  - Two different results race → exactly one terminal.
- **Migration risks:** threading sessions through repositories touches many files. Limit the change to the ingest path first.

### WS-11 Findings store and lifecycle (P1)
- **Why:** North Star Findings and Evidence; GAP-3; `EDITS.txt` items 1 and 6 (true/false-positive counts; don't re-flag the same vulnerability).
- **Extend:**
  - `finding_occurrences` and `findings` tables populated at ingest from the existing `materialize_finding_identity` and `derive_fingerprint` (`domain/reporting/finding_identity.py`).
  - Auto-resolve **only** with strong absence, reusing `ScannerCoverageContract` and lifecycle-eligibility logic.
  - Human transitions (acknowledge, risk-accept with expiry, false-positive) with RBAC and audit.
  - Backlog API with keyset pagination.
  - Backfill job from existing `result_json`.
- **Leave untouched:** `result_json` (kept as the raw evidence archive, retention-managed), detail, recurrence and coverage services (re-point them later), the compliance evaluator.
- **Depends on:** WS-10, WS-04.
- **Tests:**
  - Fingerprint stability.
  - No auto-resolve without strong absence.
  - Reopen semantics.
  - Exception expiry.
  - Tenant isolation.
  - Backfill is idempotent.
  - Pagination correctness under concurrent ingest.
- **Migration risks:** findings without a fingerprint stay occurrence-only; show them honestly as "unmatched". The backfill must be chunked to keep SQLite writer locks short.

### WS-12 Read-path scalability (P1; the assessments pagination part is P0)
- **Why:** F-9 and F-10.
- **Extend:**
  - Repositories gain projection methods that leave out `result_json`, and keyset pagination.
  - `EndpointPosture` and `LatestEvidence` summary tables maintained at ingest.
  - `TenantSecurityOverviewService` and `TenantComplianceService` read summaries.
  - Fleet query moves to SQL (filter, sort, `LIMIT`; presence computed by SQL `CASE` on `last_seen_at`).
  - Raise or remove the 100 and 200 caps once queries are bounded.
  - Composite indexes (§19.4).
- **Leave untouched:** read-model domain types; API shapes (pagination added with compatible defaults); frontend except the list views.
- **Depends on:** WS-04; WS-10 and WS-11 for the summaries.
- **Tests:**
  - Query-count assertions.
  - A synthetic volume test (1,000 endpoints × 365 assessments) with response-time budgets.
  - Unchanged contract tests.
- **Migration risks:** the list response shape changes from an array to `{items, next_cursor}`. Version the route or add `?paged=1` first, then update the SPA.

### WS-13 Scheduler correctness at fleet scale (P1)
- **Why:** The N+1 `list_for_schedule`, end-of-run outcome persistence, and burst dispatch.
- **Extend:**
  - `scheduling/runner.py`: indexed `exists_active(schedule_id, endpoint_id)`; outcomes persisted per chunk of 50; dispatch per chunk in one transaction; scheduled work TTL.
  - An optional `stagger_seconds` spreads the agents' poll pickup.
- **Leave untouched:** domain scheduling models, calculator and service.
- **Depends on:** WS-05, WS-10.
- **Tests:** 1,000 targets within a time budget; crash mid-run → resume without duplicates; a `timed_out` assessment doesn't block.
- **Migration risks:** low.

### WS-14 Audit integrity, volume and retention (P1)
- **Why:** F-12, no tamper evidence, and `SYSTEM` misattribution.
- **Extend:**
  - `SQLAlchemySecurityAuditRepository.append`: per-org `seq`, `prev_hash`, `entry_hash` in the **same transaction** as the action (via WS-10). Reuse the hash-chain *algorithm* idea from the legacy `core/security/audit_logger.py`, not the module itself.
  - Daily anchor rows plus an exported anchor file.
  - A verification CLI and route.
  - Retention by class with anchored segments.
  - Reclassify `credential.authentication_succeeded` as telemetry (failures stay audited).
  - The dispatch audit uses the requesting principal.
- **Leave untouched:** `domain/audit.py` projection and allow-list, and the feed API.
- **Depends on:** WS-10, WS-04.
- **Tests:**
  - Verification detects modified, deleted and reordered rows.
  - Retention keeps the chain verifiable.
  - Attribution test for a human-initiated dispatch.
  - Volume test: a poll writes 0 audit rows.
- **Migration risks:** historic rows have no chain, so start the chain at a genesis anchor. Per-org sequence contention is a non-issue with SQLite's single writer; Postgres needs a row lock.

### WS-15 RBAC completion (P1)
- **Why:** North Star RBAC; lab technicians need lab-scoped rights.
- **Extend:**
  - `RoleBinding.scope` (org or endpoint_group).
  - `OrganizationRbacAuthorizer._resource_scope` checks group membership for endpoint and assessment resources.
  - List queries filter by allowed groups.
  - Per-request permission cache.
  - Templates: Owner, Security Admin, Technician (group-scoped), Auditor (read plus `audit.read`), Viewer.
  - Admin UI.
- **Leave untouched:** deny and attribution logic; context resolver.
- **Depends on:** WS-08.
- **Tests:** a scoped technician can't see or assess other labs; no privilege escalation through binding; list filtering matches authorization.
- **Migration risks:** list filtering touches many queries. Add one shared repository filter helper.

### WS-16 Local AI advisory service (P2, optional)
- **Why:** North Star Local AI. It must stay advisory, opt-in and private.
- **Extend:**
  - `application/ai/` with a provider port.
  - An OpenAI-compatible adapter (reuse the `openai` SDK client pattern from `core/ai/llm_client.py`).
  - Context builder over **findings and compliance summaries** (requires WS-11).
  - Redaction policy (hostnames to aliases; usernames, IPs and serials masked).
  - Jobs run through the job host.
  - `AiAdvisory` records with provenance.
  - RBAC `ai.use`.
  - The frontend Analyst page (the contract is already drafted in GAP-2).
- **Leave untouched:** the legacy `llm_client.py` (stays behind legacy routes); every decision path.
- **Depends on:** WS-11, WS-05, WS-15.
- **Tests:**
  - Disabled by default.
  - A non-allow-listed URL is refused.
  - The redaction golden test.
  - An output with an injected "run this command" is stored as text only.
  - Timeouts.
  - Audit of AI requests.
- **Migration risks:** model availability varies, so the UI must degrade cleanly.

### WS-17 Remediation tracking, non-executing (P2); execution: SHOULD NOT BUILD YET
- **Why:** North Star Remediation, done safely; `EDITS.txt` items 2–5 (proposals, acceptance tracking).
- **Extend:** a `RemediationTask` linked to a finding (guidance from scanner metadata or AI advisory, assignee, due date, status), with verification by re-scan (finding auto-resolve).
- **Leave untouched:** the agent stays read-only; the legacy auto-fixer stays isolated.
- **Depends on:** WS-11.
- **Tests:** a task closes only through verification or a human with an audited justification.
- **Migration risks:** none.

### WS-18 Scanner and compliance content (P1–P2)
- **Why:** 4 checks and 4 controls aren't enough for a lab baseline.
- **Extend:**
  - Promote more legacy checks through `legacy_adapters.py`, each with a manifest, coverage contract and characterization test: Defender status, updates, RDP/NLA, guest account, password policy, autorun, PowerShell policy, open ports, services, audit policy.
  - Add matching `ComplianceControl`s.
  - Scanner discovery route (GAP-1).
  - Assessment profiles (P2).
- **Leave untouched:** the check implementations in `scanner.py`; the adapter-hardening pattern.
- **Depends on:** WS-07.
- **Tests:** adapter contract tests per scanner; compliance evaluation per new control.
- **Migration risks:** low.

### WS-19 Lab deployment profile (P1)
- **Why:** There's no TLS, packaging, SPA hosting or automated backups. `docker-compose` is broken.
- **Extend:**
  - FastAPI `StaticFiles` for `frontend/dist`.
  - Server Windows service (uvicorn programmatic, 1 worker).
  - `ravenx ca init` to generate a local CA and server certificate. The agent installer embeds the CA.
  - Data dir in `%ProgramData%\RAVEN-X\server`.
  - Nightly backup job with retention.
  - Split requirements: `requirements-server.txt`, `requirements-agent.txt`, `requirements-legacy-gui.txt`; retire the 1,105-line dump.
  - Pin frontend versions.
  - Replace or remove `docker-compose.yml`.
  - Validate Postgres at the 500+ tier.
- **Leave untouched:** application code.
- **Depends on:** WS-03, WS-05.
- **Tests:** a clean-machine install smoke test (scripted); restore-from-backup test; the agent connects with the pinned CA.
- **Migration risks:** low.

### WS-20 Frontend IA evolution and tests (P1–P2)
- **Why:** §20; no frontend tests.
- **Extend:**
  - New feature modules: Enrollment, Agents, Findings backlog, Users & Roles, System.
  - Vitest component tests for `AsyncSection`, severity mapping, lifecycle badges and pagination.
  - A wire-type contract check against backend `to_dict()` fixtures.
- **Leave untouched:** design system, hooks, existing screens' behavior.
- **Depends on:** the matching backend workstreams.
- **Tests:** component tests, plus one Playwright smoke test against a seeded server (P2).
- **Migration risks:** low.

---

## 22. Prioritized implementation plan

### P0: make the reference lab possible and safe. Exit criterion: a 3-PC pilot runs for a week unattended.

| Order | Item | Workstream | Size |
|---:|---|---|---|
| 1 | Commit the enterprise tree, untrack DB WAL/SHM, move the nested clone and zip out, enable CI | WS-00 | S |
| 2 | Legacy routes off by default, refused in production; same-origin CORS; remove or auth `/ws/realtime`; honor config `environment` | WS-01 | S |
| 3 | Per-thread SQLite connections plus `busy_timeout`; FK check then enable; threadpool offload in route handlers; `workers=1` guard | WS-03 | S–M |
| 4 | Alembic baseline folding both ad-hoc upgrade paths; backup before migrate | WS-04 | M |
| 5 | Indexed HMAC/SHA-256 lookup for sessions and agent credentials; session purge; drop per-contact auth-success audit rows | WS-02 (+WS-14 slice) | M |
| 6 | Job host with DB leases: scheduler, reconciler (+`timed_out`), presence, work expiry (off the poll path), purges; presence computed at read time | WS-05 | M |
| 7 | Offline-safe delivery: validate the lease, not envelope age; work TTLs; `server_time` and clock offset; `next_poll_after` | WS-06 | S–M |
| 8 | Bootstrap CLI with role templates; multi-use enrollment keys; `POST /agent/enroll`; endpoint trust state and approval queue; revoke and rotate routes | WS-08, WS-09 (trust slice) | M–L |
| 9 | Agent service: run loop, DPAPI stores, outbox, backoff; `scanner.py` lazy imports; offline installer script | WS-07 | L |
| 10 | Idempotent result acceptance; replay claim inside the handler transaction | WS-10 (slice) | M |
| 11 | Paginate `GET …/assessments` without `result_json`; overview stops loading results | WS-12 (slice) | S–M |
| 12 | Minimal UI: Enrollment keys, Approval queue, Agents list (version, last contact, skew) | WS-20 (slice) | M |

**P0 dependency chain:** (1) → (2, 3) → 4 → (5, 6, 7) → 8 → 9. Items 10–12 run in parallel once 4 is done.

### P1: production quality for 70–300 endpoints

1. Findings store, lifecycle, exceptions and backlog, with backfill (WS-11).
2. Full ingestion unit of work, summary tables, SQL fleet paging, removal of the 100/200 caps, composite indexes (WS-10, WS-12).
3. Scheduler chunking, overlap index, staggering (WS-13).
4. Audit hash chain, anchors, verification, retention, correct attribution (WS-14).
5. RBAC admin API and UI, group-scoped bindings, permission cache (WS-15, WS-08 remainder).
6. Inventory and fingerprint duplicate detection (WS-09 remainder).
7. Promote 6–10 more scanners and controls; scanner discovery route (WS-18).
8. Lab deployment profile: SPA hosting, server service, local CA, nightly backups, split requirements, pinned frontend dependencies, MSI for the agent (WS-19).
9. Frontend: Findings backlog, Users & Roles, System page, Vitest (WS-20).

### P2: growth and differentiation

1. Local AI advisory service (WS-16).
2. Remediation tracking, non-executing (WS-17).
3. Assessment profiles and group policies (WS-18).
4. TOTP MFA.
5. Validated PostgreSQL plus `--role api|jobs` split for 500–1,000+ endpoints.
6. Per-agent mTLS.
7. Signed agent packages.
8. Encrypted backups.
9. Report exports beyond compliance (findings and fleet PDF/CSV).
10. Playwright smoke test.

### Still out of scope after P2

Microservices, Kubernetes, message brokers, an async ORM rewrite, HA clustering, agent-side remediation execution, generic command channels, autonomous AI actions, SSO/SCIM, self-updating agents.

---

## 23. Decisions needed from the product owner

1. **Endpoint approval default.** Should enrollment keys default to manual approval (safer) or auto-approve within a target group (faster for 70 PCs)? *Recommendation:* manual by default, with a per-key auto-approve switch.
2. **Late results after timeout.** Accept and upgrade `timed_out` → `completed`? *Recommendation:* yes; the data is real.
3. **Reboot-restore (Deep Freeze) in the target lab?** This decides whether agent state lives on a persistent path or relies on policy-based auto re-enrollment.
4. **Git history containing `data/raven_x.db-wal`.** Rewrite history, or rotate any credentials it captured?
5. **`scanner.py` change for the agent.** Is the behavior-preserving lazy-import change acceptable (recommended), or must the agent use an import shim?
