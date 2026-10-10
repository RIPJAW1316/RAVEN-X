# RAVEN-X Current Enterprise Implementation Status

> **Generated**: 2026-09-14  
> **Repository branch**: `main`  
> **Inspection method**: Full repository audit — file tree, git diff, code reading, test inventory, documentation cross-reference  
> **Scope**: Everything on disk including unstaged and untracked work

---

## 1. Executive Summary

RAVEN-X has transformed from a monolithic Windows personal security scanner into
a modular, tenant-aware enterprise security platform. The transformation
preserves the original personal scanner (`scanner.py`) as the legacy/personal
mode source of truth while layering a clean-architecture enterprise control plane
on top.

**What RAVEN-X is now:**

- A **preserved personal Windows scanner** (`scanner.py`, 1,740 lines) with
  Tkinter/CustomTkinter desktop GUI, direct Windows inspection via PowerShell /
  registry / WMI / psutil / pywin32, local SQLite persistence, and
  OpenAI-compatible AI analysis.

- An **enterprise control plane** (18,341 lines of backend Python) built on
  FastAPI, SQLAlchemy, and a layered domain/application/infrastructure
  architecture with explicit ports and adapters.

- An **endpoint-agent architecture** where remote Windows agents make
  authenticated outbound HTTPS requests to poll work and submit assessment
  results — no inbound listener, no generic command execution, no remote
  remediation.

- A **tenant-aware RBAC and organization model** with human authentication
  (server-side sessions), organization context resolution, role-based access
  control, and tenant-scoped data isolation across endpoints, assessments,
  schedules, groups, and compliance.

- A **distributed assessment pipeline** with durable work leasing, remote
  assessment state management, cancellation, and security audit events.

- **Scheduling, fleet management, compliance, and reporting foundations**
  including assessment schedules with dynamic group/scope targeting, fleet
  filtering/sorting, endpoint groups and saved fleet scopes, compliance framework
  evaluation with historical snapshots and trends, and tenant security overview
  reporting.

- A **dark SOC-style React/TypeScript frontend** with login, organization
  switching, command center, fleet view, compliance view, and honest
  unavailable/deferred states for unimplemented screens.

- **Production hardening** including health/readiness endpoints, request
  correlation IDs, structured logging with secret redaction, login rate limiting,
  operational metrics abstraction, and configuration validation.

- **275 passing tests** across 61 test files (40 unit, 21 integration)
  protecting domain contracts, persistence boundaries, security boundaries,
  protocol safety, and legacy scanner behavior.

- **115+ architecture and security documentation files** documenting every
  implemented boundary.

**Remaining gaps before production enterprise deployment:**

- No MFA or SSO/OIDC
- No production Postgres validation
- No mTLS or protocol signing
- No agent installer or auto-update
- No generic command execution or remote remediation (deliberately deferred)
- No PDF/CSV report exports beyond compliance JSON/CSV snapshots
- No SIEM integration
- No fleet-scale performance validation
- Single-instance scheduler coordination only
- In-memory rate limiting only (not distributed)

---

## 2. Earlier Architecture / Personal Edition Baseline

The previous version of RAVEN-X was a monolithic Windows security scanner
designed for single-machine personal use.

| Component | Description | Status |
|---|---|---|
| `scanner.py` monolith | 1,740-line scanner with 20+ security checks (firewall, antivirus, UAC, BitLocker, SMBv1, RDP, updates, services, network, authentication, PowerShell policy, etc.), direct Windows inspection via PowerShell / registry / WMI / psutil / pywin32, CVSS scoring, compliance mapping (CIS, NIST, ISO 27001, PCI-DSS), local SQLite history, HTML/CSV report generation, email alerting, and AI-powered remediation script generation via OpenAI-compatible LLM | **LEGACY — PRESERVED** |
| Tkinter / CustomTkinter desktop GUI | Full desktop application with tabbed interface, scan controls, vulnerability display, report generation, settings management, and scheduled scanning | **LEGACY — PRESERVED** |
| Direct Windows inspection | PowerShell subprocess calls, `winreg` access, `psutil` process/service enumeration, `pywin32` COM interfaces, `ctypes` admin checks | **LEGACY — PRESERVED** |
| Direct remediation paths | AI-generated PowerShell remediation scripts with safe-mode guards, subprocess execution, restore-point creation | **LEGACY — PRESERVED** |
| Local SQLite persistence | Direct `sqlite3` module usage for scan history, vulnerability records, configuration | **LEGACY — PRESERVED** |
| Partial FastAPI backend | REST routes for scanning, analysis, remediation, reporting, and system monitoring — all operating on local machine only | **PARTIAL — LEGACY** |
| AI / learning engine | OpenAI-compatible LLM client via LM Studio, learning engine with feedback loop, behavioral monitoring | **PARTIAL — LEGACY** |
| Enhanced scanner (`enhanced_scanner.py`) | Backend scanner module with subset of checks from `scanner.py`, module status tracking | **PARTIAL — LEGACY** |
| Remediation module (`auto_fixer.py`) | Auto-fix with safety routing — original hyphenated file deleted, replaced with underscore version | **PARTIAL — LEGACY** |
| Dependency manifest (`requirements.txt`) | 1,105 packages — uncurated dump of an entire Kali/pentest environment, not the project's actual dependencies | **BROKEN — LEGACY** |
| Automated regression tests | None existed before enterprise transformation | **NOT PRESENT** |
| Endpoint-agent architecture | Did not exist | **NOT PRESENT** |
| Multi-tenant / organization model | Did not exist | **NOT PRESENT** |

**Important**: `scanner.py` remains the personal-mode source of truth. It has
not been rewritten or removed. Legacy scanner behavior is characterized and
regression-protected by the enterprise test suite.

---

## 3. Current High-Level Architecture

### 3.1 Local Personal Mode

```
┌─────────────────────────────────────────────────────┐
│  scanner.py (Tkinter/CustomTkinter desktop app)     │
│  ┌───────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Windows   │  │ AI/LLM   │  │ Reports/Email    │  │
│  │ Checks    │  │ Analysis │  │ Generation       │  │
│  │ (direct)  │  │ (OpenAI) │  │ (HTML/CSV)       │  │
│  └─────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
│        │              │                 │            │
│  ┌─────▼──────────────▼─────────────────▼─────────┐  │
│  │           Local SQLite (sqlite3)               │  │
│  └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### 3.2 Enterprise Control Plane

```
┌─────────────────────────────────────────────────────────────────────┐
│                     HUMAN OPERATORS (Browser)                       │
│  React/TypeScript UI → /api/v1/auth/* → /api/v1/organizations/*    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Bearer token (server-side session)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   FastAPI Application (main.py)                     │
│  ┌──────────────┐  ┌──────────────────┐  ┌─────────────────────┐   │
│  │ Human Auth   │  │ Organization     │  │ Agent Transport     │   │
│  │ /auth/*      │  │ Context          │  │ /api/v1/agent/*     │   │
│  │ Rate-limited │  │ Resolution       │  │ Credential-based    │   │
│  └──────┬───────┘  └────────┬─────────┘  └──────────┬──────────┘   │
│         │                   │                       │              │
│  ┌──────▼───────────────────▼───────────────────────▼──────────┐   │
│  │              Application Services Layer                     │   │
│  │  Assessment · Fleet · Scheduling · Compliance · Reporting   │   │
│  │  Enrollment · RBAC Authorizer · Presence · Groups/Scopes   │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                              │                                     │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                    Domain Layer                              │   │
│  │  Assessment · Scanner · Endpoint · Enrollment · Credentials │   │
│  │  Protocol · Organization · RBAC · Fleet · Scheduling        │   │
│  │  Compliance · Reporting · Audit/Security · Presence         │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                              │                                     │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │              Infrastructure Layer                            │   │
│  │  SQLAlchemy repos · HTTP transport · In-process transport   │   │
│  │  Replay guard · Work outbox · Audit persistence             │   │
│  │  Password hasher · Secret verifiers · Rate limiter · Metrics│   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Endpoint Agent Protocol Path

```
┌──────────────────────┐        ┌─────────────────────────────┐
│  WINDOWS ENDPOINT    │        │  CONTROL PLANE              │
│  ┌────────────────┐  │        │  ┌────────────────────────┐ │
│  │ RavenXAgent    │  │  HTTPS │  │ Agent HTTP Ingress     │ │
│  │ runtime.py     │──┼────────┼─>│ /api/v1/agent/message  │ │
│  │                │  │ (out)  │  │ /api/v1/agent/work     │ │
│  │ - heartbeat    │  │        │  │ /api/v1/agent/enroll   │ │
│  │ - work poll    │  │        │  │ /api/v1/agent/ack      │ │
│  │ - result sub   │  │        │  │ /api/v1/agent/fail     │ │
│  └────────────────┘  │        │  └──────────┬─────────────┘ │
│                      │        │             │               │
│  No inbound listener │        │  ┌──────────▼─────────────┐ │
│  No command execution│        │  │ Message Processor      │ │
│  No remediation      │        │  │ - Credential auth      │ │
└──────────────────────┘        │  │ - Replay guard         │ │
                                │  │ - Freshness check      │ │
                                │  │ - Direction validation  │ │
                                │  │ - Typed message router  │ │
                                │  └──────────┬─────────────┘ │
                                │             │               │
                                │  ┌──────────▼─────────────┐ │
                                │  │ Control Plane Handlers  │ │
                                │  │ - Session registry      │ │
                                │  │ - Work delivery/lease   │ │
                                │  │ - Assessment tracking   │ │
                                │  │ - Audit events          │ │
                                │  └────────────────────────┘ │
                                └─────────────────────────────┘
```

### 3.4 Tenant-Scoped Data Flow

```
Human Request → Bearer Token → Session Lookup → Principal
  → Organization ID (path param) → Context Resolution
  → Membership Verification → RBAC Authorization
  → Tenant-Scoped Service Call (organization_id filter)
  → Audit Event → Response
```

---

## 4. Current Technology Stack

### 4.1 Frontend

| Aspect | Detail |
|---|---|
| Framework | React (latest) with TypeScript |
| Build tooling | Vite (latest) |
| Styling | Inline CSS in `styles.css` — dark SOC/command-center aesthetic |
| Icons | lucide-react |
| Animation | framer-motion |
| API integration | Typed `fetch` wrapper in `api/client.ts` with Bearer token auth |
| Auth/session storage | `sessionStorage` keyed as `ravenx.session` |
| Dev dependencies | `@types/react`, `@types/react-dom` |

**Implemented screens:**

| Screen | Status | API-backed |
|---|---|---|
| Login | Implemented | Yes — `POST /api/v1/auth/login` |
| Command Center | Implemented | Yes — security overview, fleet constellation |
| Fleet | Implemented | Yes — endpoint list, detail, presence |
| Compliance | Implemented | Yes — framework listing |
| Assessments | Placeholder | Shows "not yet mapped" |
| Groups & Scopes | Placeholder | Shows "not yet mapped" |
| Schedules | Placeholder | Shows "not yet mapped" |
| Reports | Placeholder | Shows "not yet mapped" |
| Settings | Placeholder | Shows "not yet mapped" |

**Frontend design principles:**
- Never fabricates backend capabilities — deferred screens say so honestly
- Organization switching via dropdown
- Command palette (Ctrl/Cmd+K)
- Accessible — keyboard navigation, ARIA labels
- Respects `prefers-reduced-motion`
- Displays X-Request-ID on errors for operator correlation

### 4.2 Backend API

| Component | Detail |
|---|---|
| Framework | FastAPI 0.118.0 |
| Server | Uvicorn 0.38.0 |
| ORM | SQLAlchemy 2.0.45 (async via aiosqlite 0.21.0) |
| Validation | Pydantic 2.12.5 |
| HTTP client | httpx 0.28.1 |
| Config | PyYAML 6.0.3, env vars (`RAVENX_*`) |

**Route families mounted in `main.py`:**

| Route family | Prefix | Auth | Status |
|---|---|---|---|
| Health/readiness | `/health`, `/ready` | None | **PRODUCTION** |
| Root / stats | `/`, `/api/v1/stats` | None / legacy | **PRODUCTION / LEGACY** |
| Human auth | `/api/v1/auth/*` | Rate-limited login | **PRODUCTION** |
| Organization admin | `/api/v1/organizations/{id}/*` | Human + org context | **PRODUCTION** |
| Tenant endpoints | `/api/v1/organizations/{id}/endpoints/*` | Human + org + RBAC | **PRODUCTION** |
| Fleet query | `/api/v1/organizations/{id}/fleet/*` | Human + org + RBAC | **PRODUCTION** |
| Endpoint groups | `/api/v1/organizations/{id}/endpoint-groups/*` | Human + org + RBAC | **PRODUCTION** |
| Fleet scopes | `/api/v1/organizations/{id}/fleet-scopes/*` | Human + org + RBAC | **PRODUCTION** |
| Tenant assessments | `/api/v1/organizations/{id}/assessments/*` | Human + org + RBAC | **PRODUCTION** |
| Assessment schedules | `/api/v1/organizations/{id}/assessment-schedules/*` | Human + org + RBAC | **PRODUCTION** |
| Security reporting | `/api/v1/organizations/{id}/security/*` | Human + org + RBAC | **PRODUCTION** |
| Compliance | `/api/v1/organizations/{id}/compliance/*` | Human + org + RBAC | **PRODUCTION** |
| Agent transport | `/api/v1/agent/*` | Endpoint credential | **PRODUCTION** |
| Legacy scan | `/api/v1/scan/*` | None (optional mount) | **LEGACY** |
| Legacy analysis | `/api/v1/analysis/*` | None (optional mount) | **LEGACY** |
| Legacy remediation | `/api/v1/remediation/*` | None (optional mount) | **LEGACY** |
| Legacy reports | `/api/v1/reports/*` | None (optional mount) | **LEGACY** |
| Legacy system | `/api/v1/system/*` | None (optional mount) | **LEGACY** |

Legacy routes are conditionally mounted via `RAVENX_ENABLE_LEGACY_ROUTES` and
gracefully degrade if their AI/monitoring dependencies are missing.

### 4.3 Application Layer

| Area | Key modules | Notes |
|---|---|---|
| Assessment | `runner.py`, `normalizer.py`, `local_runner.py`, `local_orchestrator.py`, `run_local_assessment.py`, `tenant_service.py`, `options.py` | Full local + remote assessment pipeline |
| Scanner | `registry.py`, `compatibility.py`, `local_capabilities.py`, `legacy_adapters.py` | Scanner manifest, capability matching, hardened adapters |
| Enrollment | `service.py` | Enrollment token generation, credential issuance, verification |
| Agent processing | `processor.py` | Message acceptance, credential auth, replay guard, typed routing |
| Control plane | `sessions.py`, `transport.py`, `handlers.py`, `reconciliation.py`, `assessment_dispatch.py`, `cancellation.py` | Agent session registry, work delivery, remote assessment lifecycle |
| Identity | `service.py` | Human authentication, session management |
| Organization | `service.py`, `context.py`, `admin_service.py` | Org CRUD, context resolution, tenant administration |
| RBAC | `service.py`, `authorizer.py` | Role/binding management, permission evaluation |
| Endpoint | `registry.py`, `tenant_service.py`, `presence_service.py`, `presence_maintenance.py`, `fleet_presence.py` | Endpoint lifecycle, tenant-scoped access, presence tracking |
| Fleet | `service.py`, `groups.py` | Fleet query, endpoint groups, saved fleet scopes |
| Scheduling | `service.py`, `runner.py`, `worker.py` | Schedule CRUD, execution runner, background worker |
| Reporting | `security_overview.py`, `detail.py`, `recurrence.py`, `coverage.py` | Tenant security overview, finding detail, recurrence, coverage |
| Compliance | `service.py`, `snapshot_service.py`, `retention.py` | Framework evaluation, snapshot lifecycle, retention policy |
| Ports | 15+ port interfaces in `application/ports/` | Repository, transport, authorization abstractions |

### 4.4 Domain Layer

| Module | Key types | Lines |
|---|---|---|
| `assessment/` | `AssessmentTarget`, `AssessmentStatus`, `AssessmentResult`, `FindingSeverity`, `Finding`, `Evidence` | ~350 |
| `scanner/` | `ScannerManifest`, `ScannerId`, `ScannerCapability`, `TargetCapability`, `ScannerExecutionResult` | ~200 |
| `endpoint/` | `Endpoint`, `EndpointId`, `EndpointStatus`, `PlatformMetadata`, `AgentMetadata` | ~250 |
| `enrollment/` | `EnrollmentRecord`, `EnrollmentToken`, `EndpointCredential`, `CredentialStatus` | ~200 |
| `agent_work/` | `AgentWorkItem`, `WorkItemStatus`, `WorkItemId` | ~150 |
| `user/` | `HumanUser`, `UserSession`, `UserStatus` | ~100 |
| `security/` | `SecurityPrincipal`, `SecurityAuditEvent`, `SecurityAuditEventType`, `SecurityAuditOutcome` | ~200 |
| `identity/` | Identity abstractions | ~50 |
| `organization/` | `Organization`, `OrganizationId`, `OrganizationStatus`, `OrganizationMembership`, `MembershipStatus`, `OrganizationContext` | ~200 |
| `rbac/` | `Role`, `RoleBinding`, `Permission`, `RbacAction` | ~200 |
| `presence.py` | `EndpointPresence`, `PresenceState`, `PresencePolicy`, `EndpointPresenceEvaluator` | 87 |
| `reporting/` | `OrganizationSecurityOverview`, `FindingFingerprint`, `FindingRecurrenceSummary`, `FindingCoverageHistory`, `ScannerCoverageContract` | ~350 |
| `fleet.py` | `FleetQuery`, `FleetPage`, `FleetEndpointSummary`, `FleetSortField`, `SortDirection` | 77 |
| `group_scope.py` | `EndpointGroup`, `EndpointGroupId`, `SavedFleetScope`, `SavedFleetScopeId` | 87 |
| `scheduling/` | `AssessmentSchedule`, `AssessmentScheduleRun`, `AssessmentRecurrence`, `ScheduleFrequency`, `AssessmentScheduleCalculator` | ~200 |
| `compliance.py` | `ComplianceFramework`, `ComplianceControl`, `ControlEvaluation`, `CompliancePostureSummary`, `ComplianceFrameworkRegistry` | ~200 |
| `compliance_snapshot.py` | `ComplianceSnapshot`, `ComplianceSnapshotDelta`, `ComplianceEndpointSnapshot`, `ComplianceControlSnapshot` | 112 |

**Total domain layer**: ~2,868 lines of pure business contracts.

### 4.5 Infrastructure Layer

| Area | Implementations |
|---|---|
| **SQLAlchemy repositories** | Assessment, endpoint, enrollment, replay guard, agent work, remote assessment, security audit, user, organization, membership, RBAC (role + role binding), presence, schedule, schedule run, endpoint group, saved fleet scope, compliance snapshot |
| **In-memory repositories** | Enrollment, remote assessment, organization, membership, security audit, RBAC, agent work, user, presence, schedule, endpoint, group/scope, compliance snapshot — used for testing |
| **Persistence mappers** | `mappers.py` (assessment), `endpoint_mappers.py`, `enrollment_mappers.py` — domain ↔ ORM translation |
| **HTTP transport** | `server.py` (FastAPI agent ingress), `client.py` (outbound agent HTTP client), `outbox.py` (pending work queue) |
| **In-process transport** | Via `application/control_plane/transport.py` |
| **Security** | `password_hasher.py` (bcrypt-based), `secret_verifiers.py` (salted scrypt token verifiers) |
| **Operational** | `settings.py` (ApplicationSettings from env), `rate_limiter.py` (InMemoryRateLimiter), `metrics.py` (MetricsCollector) |

### 4.6 Protocol and Agent

| Module | Contents |
|---|---|
| `protocol/agent/models.py` | `AgentMessageEnvelope`, `MessageId`, `CorrelationId`, `ProtocolDirection`, `ProtocolValidationPolicy`, `ProtocolError`, typed message payloads (heartbeat, capability, status, assessment, progress, result), freshness/replay/direction validation, JSON-safe serialization |
| `agent/runtime.py` | `RavenXAgent` — agent runtime loop, work polling, result submission |
| `agent/heartbeat.py` | Heartbeat generation and scheduling |

### 4.7 Testing

| Aspect | Detail |
|---|---|
| Framework | pytest 9.0.2 |
| Test count | **275 passing tests** across **61 files** |
| Unit tests | 40 files in `tests/unit/` |
| Integration tests | 21 files in `tests/integration/` |
| Total test lines | 5,665 |
| Config | `pytest.ini` — testpaths=tests, norecursedirs excludes .git/.tox/.venv/Raven-x-enterprise |
| Fixtures | `tests/conftest.py` + `tests/fixtures/` |
| Python requirement | 3.11 (CI on `windows-latest`) |

### 4.8 Deployment / Operations

| Aspect | Detail |
|---|---|
| Supported runtime | Python 3.11.x (validated; 3.14 not supported) |
| Dev dependencies | `requirements-dev.txt` — 23 curated packages |
| CI | GitHub Actions: `windows-latest`, Python 3.11, `compileall -q backend`, `pytest -q` |
| Production docs | `docs/deployment/production.md` |
| Operations docs | Database backup/restore, control-plane recovery, scheduler ops, compliance retention, upgrade |
| Health endpoint | `GET /health` — liveness |
| Readiness endpoint | `GET /ready` — database connectivity check |
| Rate limiting | In-memory per-instance (not distributed) |
| Logging | Structured, with secret redaction, request correlation IDs |
| Metrics | `MetricsCollector` abstraction — in-memory counters |
| Configuration | `ApplicationSettings` from env vars with validation |
| Multi-instance | Single scheduler instance via `RAVENX_ASSESSMENT_SCHEDULER_ENABLED`; no distributed lock |

---

## 5. Implemented Capabilities

### 5.1 Assessment

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Assessment domain contracts | **PASS** | `domain/assessment/` | AssessmentTarget, AssessmentStatus, AssessmentResult, FindingSeverity, Finding, Evidence |
| Legacy finding normalization | **PASS** | `application/assessment/normalizer.py` | Deterministic mapping from legacy finding dicts |
| LocalAssessmentRunner | **PASS** | `application/assessment/local_runner.py` | Runs scanner checks and produces AssessmentResult |
| Local assessment orchestration | **PASS** | `application/assessment/local_orchestrator.py` | Selected-scanner orchestration |
| Run local assessment use case | **PASS** | `application/assessment/run_local_assessment.py` | Domain→persistence path |
| Assessment persistence | **PASS** | `infrastructure/persistence/sqlalchemy_assessment_repository.py`, `mappers.py` | Domain↔ORM mapping |
| Tenant assessment service | **PASS** | `application/assessment/tenant_service.py` | Tenant-scoped CRUD + dispatch |
| Remote assessment dispatch | **PASS** | `application/control_plane/assessment_dispatch.py` | Human→agent assessment creation |
| Remote assessment cancellation | **PASS** | `application/control_plane/cancellation.py` | Lifecycle-safe cancellation |
| Legacy `scan_all()` compatibility | **PASS** | `application/assessment/options.py` | Preserved compatibility path |

### 5.2 Scanner Runtime

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Scanner manifests and stable IDs | **PASS** | `domain/scanner/models.py` | ScannerManifest, ScannerId, capabilities |
| Scanner registry | **PASS** | `application/scanner/registry.py` | Registry with capability matching |
| Compatibility evaluation | **PASS** | `application/scanner/compatibility.py` | Target↔scanner capability check |
| Local capabilities | **PASS** | `application/scanner/local_capabilities.py` | Local machine capability detection |
| Legacy scanner adapters | **PASS** | `application/scanner/legacy_adapters.py` | Hardened wrappers for legacy checks |
| Scanner adapter hardening | **PASS** | Tests in `test_scanner_adapter_hardening.py` | Timeout, error isolation |
| Scanner execution evidence | **PASS** | `domain/reporting/` | Expanded evidence model |
| Scanner coverage contracts | **PASS** | `domain/reporting/coverage.py` | Coverage observation semantics |

### 5.3 Endpoint Identity

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Stable EndpointId | **PASS** | `domain/endpoint/` | Raven-X-managed UUID-based identity |
| Endpoint lifecycle/status | **PASS** | `domain/endpoint/models.py` | Active/suspended/revoked states |
| Platform metadata | **PASS** | `domain/endpoint/models.py` | OS, architecture, hostname |
| Agent metadata | **PASS** | `domain/endpoint/models.py` | Agent version tracking |
| Endpoint capabilities | **PASS** | `domain/endpoint/models.py` | Uses existing capability model |
| Endpoint→AssessmentTarget mapping | **PASS** | `domain/endpoint/` | Conversion for assessment pipeline |
| Endpoint registry | **PASS** | `application/endpoint/registry.py` | CRUD + persistence |
| Endpoint persistence | **PASS** | `infrastructure/persistence/sqlalchemy_endpoint_repository.py` | SQLAlchemy + mappers |

### 5.4 Enrollment and Credentials

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Enrollment authorization | **PASS** | `application/enrollment/service.py` | Secure random tokens |
| Salted scrypt token verifiers | **PASS** | `infrastructure/security/secret_verifiers.py` | Credential hashing |
| Single-use enrollment | **PASS** | `domain/enrollment/models.py` | Consumed on use |
| Credential validation | **PASS** | `application/enrollment/service.py` | Bearer token verification |
| Credential rotation | **PASS** | `application/enrollment/service.py` | New credential issuance |
| Credential revocation | **PASS** | `domain/enrollment/models.py` | Status lifecycle |
| Revocation enforcement | **PASS** | `application/enrollment/service.py` | Checked on every auth |
| Enrollment persistence | **PASS** | `infrastructure/persistence/sqlalchemy_enrollment_repository.py` | Durable storage |

### 5.5 Protocol

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Message envelope | **PASS** | `protocol/agent/models.py` | MessageId, CorrelationId, endpoint binding |
| Freshness validation | **PASS** | `protocol/agent/models.py` | Timestamp bounds checking |
| Replay protection | **PASS** | `infrastructure/persistence/sqlalchemy_replay_guard.py` | Durable nonce storage |
| Direction validation | **PASS** | `protocol/agent/models.py` | Agent→CP vs CP→Agent |
| Typed messages | **PASS** | `protocol/agent/models.py` | Heartbeat, capability, status, assessment, progress, result |
| Protocol error contracts | **PASS** | `protocol/agent/models.py` | ProtocolError hierarchy |
| JSON-safe serialization | **PASS** | `protocol/agent/models.py` | Safe round-trip |

### 5.6 Agent Runtime

| Capability | Status | Main files | Notes |
|---|---|---|---|
| RavenXAgent runtime | **PASS** | `agent/runtime.py` | Agent loop, work polling, result submission |
| Agent heartbeat | **PASS** | `agent/heartbeat.py` | Periodic heartbeat generation |
| Control-plane AgentSession | **PASS** | `application/control_plane/sessions.py` | Session registry, isolation |
| Authenticated message acceptance | **PASS** | `application/agent/processor.py` | Full auth/replay/freshness pipeline |

### 5.7 HTTP Transport

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Agent HTTP ingress | **PASS** | `infrastructure/transport/http/server.py` | FastAPI router for agent messages |
| Agent work polling | **PASS** | `infrastructure/transport/http/server.py` | GET /api/v1/agent/work |
| Agent message submission | **PASS** | `infrastructure/transport/http/server.py` | POST /api/v1/agent/message |
| Outbound HTTP client | **PASS** | `infrastructure/transport/http/client.py` | Agent-side HTTP transport |
| Pending work outbox | **PASS** | `infrastructure/transport/http/outbox.py` | In-memory + durable work queue |

### 5.8 Work Delivery

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Durable work items | **PASS** | `domain/agent_work/`, `infrastructure/persistence/sqlalchemy_agent_work_repository.py` | Persistent work queue |
| Work leasing | **PASS** | SQLAlchemy agent work repo | Lease duration, max attempts |
| Work acknowledgement | **PASS** | HTTP transport routes | POST /api/v1/agent/ack |
| Work failure semantics | **PASS** | HTTP transport routes | POST /api/v1/agent/fail with retry |
| Remote assessment state | **PASS** | `infrastructure/persistence/sqlalchemy_remote_assessment_repository.py` | Durable lifecycle tracking |

### 5.9 Human Authentication

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Human identity domain | **PASS** | `domain/user/models.py` | HumanUser, UserSession |
| Password hashing | **PASS** | `infrastructure/security/password_hasher.py` | bcrypt-based |
| Server-side sessions | **PASS** | `application/identity/service.py` | Opaque session tokens |
| Login rate limiting | **PASS** | `infrastructure/operational/rate_limiter.py` | Per-IP+email, configurable |
| Session revocation | **PASS** | Human control plane `/auth/logout` | Immediate invalidation |
| Human/agent credential separation | **PASS** | Separate auth paths | Completely distinct pipelines |

### 5.10 Organization / Membership

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Organization domain | **PASS** | `domain/organization/models.py` | Organization, OrganizationId, OrganizationStatus |
| Organization memberships | **PASS** | `domain/organization/models.py` | Membership lifecycle |
| OrganizationContext | **PASS** | `application/organization/context.py` | Resolved on every tenant request |
| Tenant-safe administration | **PASS** | `application/organization/admin_service.py` | Create/suspend/revoke memberships |
| Organization persistence | **PASS** | SQLAlchemy repos | Durable storage |

### 5.11 RBAC

| Capability | Status | Main files | Notes |
|---|---|---|---|
| RBAC domain | **PASS** | `domain/rbac/models.py` | Role, RoleBinding, Permission |
| Policy enforcement | **PASS** | `application/rbac/authorizer.py` | OrganizationRbacAuthorizer |
| Authorization actions | **PASS** | `domain/rbac/` | Typed action catalog |
| Tenant-scoped enforcement | **PASS** | All tenant service calls | Consistent permission checks |
| Audit integration | **PASS** | Via security audit repository | Authorization decisions logged |

### 5.12 Fleet Management

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Fleet query (filter/sort/paginate) | **PASS** | `application/fleet/service.py` | Multi-field filtering |
| Endpoint groups | **PASS** | `application/fleet/groups.py` | CRUD, membership, lifecycle |
| Saved fleet scopes | **PASS** | `application/fleet/groups.py` | Dynamic criteria, resolution |
| Endpoint presence | **PASS** | `application/endpoint/presence_service.py` | Online/stale/offline state |
| Presence maintenance | **PASS** | `application/endpoint/presence_maintenance.py` | Background batch evaluation |
| Fleet presence summary | **PASS** | `application/endpoint/fleet_presence.py` | Organization-wide presence stats |

### 5.13 Scheduling

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Assessment schedules | **PASS** | `application/scheduling/service.py` | CRUD with RBAC |
| Recurrence calculation | **PASS** | `domain/scheduling/calculator.py` | Frequency computation |
| Dynamic targeting (groups/scopes) | **PASS** | `application/scheduling/runner.py` | Resolve targets at run time |
| Schedule runner | **PASS** | `application/scheduling/runner.py` | Batch execution |
| Background worker | **PASS** | `application/scheduling/worker.py` | Poll loop, configurable interval |
| Schedule pause/resume/revoke | **PASS** | `application/scheduling/service.py` | Lifecycle management |
| Schedule run history | **PASS** | SQLAlchemy schedule run repo | Per-run tracking |
| **Limitation** | **BOUNDED** | Single instance only | No distributed lock; exactly one `RAVENX_ASSESSMENT_SCHEDULER_ENABLED=true` instance |

### 5.14 Compliance

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Compliance framework domain | **PASS** | `domain/compliance.py` | Framework, Control, ControlEvidenceRequirement |
| Built-in Windows baseline | **PASS** | `domain/compliance.py` | `ravenx_windows_baseline_registry()` |
| Control evaluation | **PASS** | `application/compliance/service.py` | Evidence-based evaluation |
| Organization-wide compliance summary | **PASS** | Compliance API routes | Framework + per-endpoint posture |
| Compliance snapshots | **PASS** | `application/compliance/snapshot_service.py` | Immutable point-in-time captures |
| Snapshot comparison/delta | **PASS** | `domain/compliance_snapshot.py` | Drift detection |
| Compliance timeline | **PASS** | Human control plane API | Historical posture trend |
| Control trends | **PASS** | Human control plane API | Per-control historical data |
| Endpoint compliance history | **PASS** | Human control plane API | Per-endpoint compliance over time |
| Snapshot export (JSON/CSV) | **PASS** | Human control plane API | Download attachment |
| Retention policy | **PASS** | `application/compliance/retention.py` | Age/count-based cleanup |
| **Limitation** | **BOUNDED** | Max endpoints configurable | `compliance_evaluation_max_endpoints` default 100 |

### 5.15 Reporting

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Tenant security overview | **PASS** | `application/reporting/security_overview.py` | Endpoint/finding/presence counts |
| Assessment finding detail | **PASS** | `application/reporting/detail.py` | Per-assessment finding breakdown |
| Finding recurrence comparison | **PASS** | `application/reporting/recurrence.py` | Cross-assessment fingerprint matching |
| Finding coverage history | **PASS** | `application/reporting/coverage.py` | Scanner observation tracking |
| Finding identity / fingerprinting | **PASS** | `domain/reporting/finding_identity.py` | Deterministic finding fingerprints |
| **Limitation** | **DEFERRED** | No PDF/CSV report exports | Beyond compliance snapshot export |
| **Limitation** | **DEFERRED** | No human activity read route | Audit events stored but not exposed |

### 5.16 Audit and Observability

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Durable security audit events | **PASS** | `infrastructure/persistence/sqlalchemy_security_audit_repository.py` | All security-relevant actions logged |
| Request correlation IDs | **PASS** | `main.py` middleware | X-Request-ID header propagation |
| Structured logging | **PASS** | `main.py` middleware | Method, path, status, duration |
| Secret redaction | **PASS** | Logging avoids credential text | Error types only, not values |
| Metrics abstraction | **PASS** | `infrastructure/operational/metrics.py` | MetricsCollector with increment counters |
| **Limitation** | **PARTIAL** | In-memory metrics only | No Prometheus/StatsD export |

### 5.17 UI

| Capability | Status | Main files | Notes |
|---|---|---|---|
| Login flow | **PASS** | `frontend/src/app/App.tsx` | Email/password with rate-limit handling |
| Organization switching | **PASS** | `frontend/src/app/App.tsx` | Dropdown selector |
| Command center | **PASS** | `frontend/src/app/App.tsx` | Overview with presence/severity stats |
| Fleet view | **PASS** | `frontend/src/app/App.tsx` | Endpoint list, search, detail |
| Compliance view | **PASS** | `frontend/src/app/App.tsx` | Framework listing |
| Command palette | **PASS** | `frontend/src/app/App.tsx` | Ctrl+K search |
| Unavailable states | **PASS** | `frontend/src/app/App.tsx` | Honest "not yet mapped" for deferred screens |
| **Limitation** | **PARTIAL** | Single-file UI | All components in one App.tsx (~650 lines) |

---

## 6. Security Model

### 6.1 Human Authentication

- Server-side opaque session tokens issued on login
- Password hashing via bcrypt (`infrastructure/security/password_hasher.py`)
- Login rate limiting: per-IP+email-hash, configurable window (default 5 attempts / 60 seconds)
- Session revocation on logout
- Rate-limit audit events recorded durably
- No MFA (deferred)
- No SSO/OIDC (deferred)

### 6.2 Endpoint Authentication

- Enrollment tokens: secure random, single-use, salted scrypt verification
- Endpoint credentials: separate from human credentials, rotatable, revocable
- Credential verification on every agent message
- Revocation enforcement: revoked endpoints cannot submit messages or poll work

### 6.3 Credential Separation

Human and agent authentication pipelines are completely independent:
- Different token formats
- Different verification code paths
- Different session/credential storage
- No shared authentication state

### 6.4 Identity vs Authentication vs Authorization

| Concern | Implementation |
|---|---|
| **Identity** | EndpointId (stable UUID), HumanUser (user_id + email), SecurityPrincipal |
| **Authentication** | Bearer token → session lookup (human), credential verification (agent) |
| **Authorization** | RBAC policy evaluation after authentication, tenant context required |

### 6.5 Tenant Isolation

- Every tenant-scoped query filters by `organization_id`
- Organization context resolved and verified on every request
- RBAC authorization checked before data access
- Endpoints are organization-owned; cross-tenant access is blocked at the service layer
- Assessments, schedules, groups, scopes, and compliance are all organization-scoped

### 6.6 Protocol Safety

- Replay protection via durable nonce storage (SQLAlchemy replay guard)
- Message freshness validation (configurable time window)
- Direction validation (agent→CP vs CP→agent)
- Typed message routing — no arbitrary command execution
- No inbound endpoint listener
- No generic command transport
- No remote remediation transport

### 6.7 Audit Events

Security-significant actions are recorded as durable `SecurityAuditEvent` records:
- Authentication success/failure
- Rate limiting
- Authorization decisions
- Enrollment lifecycle
- Credential operations
- Assessment operations
- Administrative actions

### 6.8 Remaining Security Gaps

| Gap | Severity | Notes |
|---|---|---|
| No MFA | High | Single-factor password only |
| No SSO/OIDC | High | No enterprise identity federation |
| No mTLS | Medium | Agent transport relies on TLS + bearer token |
| No protocol signing | Medium | Envelope integrity not cryptographically verified |
| In-memory rate limiting | Medium | Not shared across instances |
| No production secret management | Medium | Env vars only; no Vault/KMS integration |
| No SIEM integration | Medium | Audit events stored but not forwarded |
| No advanced authorization review | Low | No permission audit/export tool |
| No browser security headers beyond basics | Low | X-Content-Type-Options and Referrer-Policy set; no full CSP |

---

## 7. Data / Persistence Model

### 7.1 Durable Entities

| Entity | Storage | Notes |
|---|---|---|
| Legacy scans | SQLAlchemy `Scan` model | Via `backend/core/database/models.py` |
| Legacy vulnerabilities | SQLAlchemy `Vulnerability` model | Linked to scans |
| Endpoints | SQLAlchemy endpoint tables | Organization-scoped |
| Endpoint credentials | SQLAlchemy enrollment tables | Hashed, rotatable |
| Enrollment records | SQLAlchemy enrollment tables | Token verification, single-use |
| Agent replay records | SQLAlchemy replay guard | Nonce-based deduplication |
| Work items | SQLAlchemy agent work tables | Lease-based delivery |
| Remote assessments | SQLAlchemy remote assessment tables | Full lifecycle tracking |
| Organizations | SQLAlchemy organization tables | Name, status, timestamps |
| Memberships | SQLAlchemy membership tables | User↔organization links |
| Roles / bindings | SQLAlchemy RBAC tables | Permission model |
| Human users | SQLAlchemy user tables | Email, password hash, status |
| Human sessions | SQLAlchemy user/session tables | Server-side, expirable |
| Audit events | SQLAlchemy security audit tables | Append-only log |
| Assessment schedules | SQLAlchemy schedule tables | Recurrence, targeting |
| Schedule runs | SQLAlchemy schedule run tables | Execution history |
| Endpoint groups | SQLAlchemy group tables | Membership tracking |
| Saved fleet scopes | SQLAlchemy scope tables | Dynamic criteria |
| Compliance snapshots | SQLAlchemy compliance snapshot tables | Immutable point-in-time |
| Endpoint presence | SQLAlchemy presence tables | Last-seen timestamps |

### 7.2 Database

- **Current supported database**: SQLite via `aiosqlite` (development and small single-node deployments)
- **PostgreSQL**: Not validated in this environment. Must be tested separately before being advertised as supported.
- **Migrations**: No Alembic migration chain exists. Schema is created from SQLAlchemy models via `create_tables()`. Destructive migrations should not be assumed safe without review.
- **Backup/restore**: Documented in `docs/operations/database-backup.md` and `docs/operations/database-restore.md`

---

## 8. API Surface

### 8.1 Production / Current Enterprise Routes

**Health and readiness** (no auth):
- `GET /health` — liveness check
- `GET /ready` — database readiness check

**Human authentication** (rate-limited):
- `POST /api/v1/auth/login` — issue session token
- `POST /api/v1/auth/logout` — revoke session
- `GET /api/v1/auth/me` — current user info
- `GET /api/v1/auth/organizations` — selectable organizations

**Organization administration** (human auth + org context):
- `GET /api/v1/organizations/{id}` — organization details
- `GET /api/v1/organizations/{id}/memberships` — list memberships
- `POST /api/v1/organizations/{id}/memberships` — create membership
- `POST /api/v1/organizations/{id}/memberships/{mid}/suspend` — suspend
- `POST /api/v1/organizations/{id}/memberships/{mid}/revoke` — revoke

**Tenant endpoints** (human auth + org context + RBAC):
- `GET /api/v1/organizations/{id}/endpoints` — list endpoints
- `GET /api/v1/organizations/{id}/endpoints/{eid}` — get endpoint
- `GET /api/v1/organizations/{id}/endpoints/{eid}/presence` — endpoint presence

**Fleet** (human auth + org context + RBAC):
- `GET /api/v1/organizations/{id}/fleet/endpoints` — query with filter/sort/paginate
- `GET /api/v1/organizations/{id}/fleet/presence` — fleet-wide presence summary

**Endpoint groups** (human auth + org context + RBAC):
- `POST /api/v1/organizations/{id}/endpoint-groups` — create
- `GET /api/v1/organizations/{id}/endpoint-groups` — list
- `GET /api/v1/organizations/{id}/endpoint-groups/{gid}` — get
- `PATCH /api/v1/organizations/{id}/endpoint-groups/{gid}` — update
- `POST /api/v1/organizations/{id}/endpoint-groups/{gid}/members` — add members
- `POST /api/v1/organizations/{id}/endpoint-groups/{gid}/members/remove` — remove members
- `GET /api/v1/organizations/{id}/endpoint-groups/{gid}/members` — list members
- `POST /api/v1/organizations/{id}/endpoint-groups/{gid}/revoke` — revoke group

**Fleet scopes** (human auth + org context + RBAC):
- `POST /api/v1/organizations/{id}/fleet-scopes` — create
- `GET /api/v1/organizations/{id}/fleet-scopes` — list
- `GET /api/v1/organizations/{id}/fleet-scopes/{sid}` — get
- `PATCH /api/v1/organizations/{id}/fleet-scopes/{sid}` — update
- `POST /api/v1/organizations/{id}/fleet-scopes/{sid}/revoke` — revoke
- `GET /api/v1/organizations/{id}/fleet-scopes/{sid}/endpoints` — resolve scope

**Tenant assessments** (human auth + org context + RBAC):
- `POST /api/v1/organizations/{id}/assessments` — create (dispatch to agent)
- `GET /api/v1/organizations/{id}/assessments` — list
- `GET /api/v1/organizations/{id}/assessments/{aid}` — get
- `POST /api/v1/organizations/{id}/assessments/{aid}/cancel` — cancel
- `GET /api/v1/organizations/{id}/assessments/{aid}/details` — finding details
- `GET /api/v1/organizations/{id}/assessments/{aid}/findings/{fid}` — finding detail
- `GET /api/v1/organizations/{id}/assessments/{aid}/findings/{fid}/recurrence` — recurrence
- `GET /api/v1/organizations/{id}/assessments/{aid}/findings/{fid}/coverage` — coverage

**Assessment schedules** (human auth + org context + RBAC):
- `POST /api/v1/organizations/{id}/assessment-schedules` — create
- `GET /api/v1/organizations/{id}/assessment-schedules` — list
- `GET /api/v1/organizations/{id}/assessment-schedules/{sid}` — get
- `PATCH /api/v1/organizations/{id}/assessment-schedules/{sid}` — update
- `POST /api/v1/organizations/{id}/assessment-schedules/{sid}/pause` — pause
- `POST /api/v1/organizations/{id}/assessment-schedules/{sid}/resume` — resume
- `POST /api/v1/organizations/{id}/assessment-schedules/{sid}/revoke` — revoke
- `GET /api/v1/organizations/{id}/assessment-schedules/{sid}/runs` — run history

**Security reporting** (human auth + org context + RBAC):
- `GET /api/v1/organizations/{id}/security/overview` — tenant security overview

**Compliance** (human auth + org context + RBAC):
- `GET /api/v1/organizations/{id}/compliance/frameworks` — list frameworks
- `GET /api/v1/organizations/{id}/compliance/frameworks/{fid}` — framework detail
- `GET /api/v1/organizations/{id}/compliance/{fid}/summary` — compliance summary
- `GET /api/v1/organizations/{id}/endpoints/{eid}/compliance/{fid}` — endpoint compliance
- `POST /api/v1/organizations/{id}/compliance/{fid}/snapshots` — create snapshot
- `GET /api/v1/organizations/{id}/compliance/{fid}/snapshots` — list snapshots
- `GET /api/v1/organizations/{id}/compliance/{fid}/snapshots/{sid}` — get snapshot
- `GET /api/v1/organizations/{id}/compliance/{fid}/snapshots/{sid}/compare` — compare
- `GET /api/v1/organizations/{id}/compliance/{fid}/snapshots/{sid}/export` — export
- `GET /api/v1/organizations/{id}/compliance/{fid}/timeline` — historical timeline
- `GET /api/v1/organizations/{id}/compliance/{fid}/controls/{cid}/trend` — control trend
- `GET /api/v1/organizations/{id}/endpoints/{eid}/compliance/{fid}/history` — endpoint history

**Agent transport** (endpoint credential auth):
- `POST /api/v1/agent/message` — submit protocol message
- `GET /api/v1/agent/work` — poll for work
- `POST /api/v1/agent/enroll` — enrollment
- `POST /api/v1/agent/ack` — acknowledge work
- `POST /api/v1/agent/fail` — report work failure

### 8.2 Legacy Routes (conditionally mounted)

- `/api/v1/scan/*` — local scanning
- `/api/v1/analysis/*` — AI analysis
- `/api/v1/remediation/*` — auto-fix
- `/api/v1/reports/*` — report generation
- `/api/v1/system/*` — system monitoring

Controlled by `RAVENX_ENABLE_LEGACY_ROUTES` (default: true). Gracefully
unavailable when AI/monitoring dependencies are missing.

---

## 9. Frontend Status

### 9.1 Implemented Screens

| Screen | API integration | Notes |
|---|---|---|
| **Login** | `POST /api/v1/auth/login` | Rate-limit error display with Retry-After |
| **Command Center** | `GET .../security/overview`, `GET .../fleet/endpoints` | Posture stats, severity counts, constellation visualization |
| **Fleet** | `GET .../fleet/endpoints` | Searchable table, endpoint detail drill-down, presence status |
| **Compliance** | `GET .../compliance/frameworks` | Framework listing, data display |

### 9.2 Placeholder / Deferred Screens

| Screen | UI text |
|---|---|
| Assessments | "not yet mapped" |
| Groups & Scopes | "not yet mapped" |
| Schedules | "not yet mapped" |
| Reports | "not yet mapped" |
| Settings | "not yet mapped" |

The backend APIs for assessments, groups, scopes, and schedules are **fully
implemented** — the frontend screens just have not been wired up yet.

### 9.3 Design Approach

- Dark command-center SOC aesthetic
- CSS custom properties for theming
- Framer Motion for page transitions
- Lucide icons throughout
- Command palette (Ctrl/Cmd+K)
- `prefers-reduced-motion` respected
- Session stored in `sessionStorage` (not `localStorage`)

### 9.4 Running the Frontend

```bash
cd frontend && npm install && npm run dev
```

Requires the backend running on `localhost:8000` (Vite proxy or CORS).

---

## 10. Testing Baseline

### 10.1 Test Inventory

**275 passing tests** across **61 test files** (5,665 total lines):

**Unit tests (40 files):**
- `test_assessment_domain.py` (5) — domain contracts
- `test_assessment_persistence_mappers.py` (2) — ORM mapping
- `test_sqlalchemy_assessment_repository.py` (2) — repository
- `test_legacy_normalizer.py` (5) — finding normalization
- `test_local_assessment_runner.py` (4) — runner
- `test_local_assessment_orchestrator.py` (7) — orchestration
- `test_run_local_assessment.py` (5) — use case
- `test_scanner_runtime.py` (8) — manifests, registry, capabilities
- `test_local_capabilities.py` (7) — capability detection
- `test_promoted_legacy_adapters.py` (3) — adapter promotion
- `test_scanner_adapter_hardening.py` (5) — timeout, error isolation
- `test_endpoint_domain.py` (9) — endpoint lifecycle
- `test_endpoint_persistence_mappers.py` (2) — ORM mapping
- `test_endpoint_registry.py` (2) — registry
- `test_enrollment_trust.py` (5) — enrollment security
- `test_agent_protocol.py` — protocol contracts
- `test_agent_message_processor.py` — message acceptance pipeline
- `test_agent_runtime.py` — agent runtime
- `test_control_plane_sessions.py` (3) — session registry
- `test_control_plane_transport.py` (1) — transport
- `test_control_plane_authorization_and_audit.py` (5) — auth + audit
- `test_http_agent_transport_client.py` (5) — HTTP client
- `test_agent_work_repository.py` (2) — work item repo
- `test_human_identity.py` (6) — human auth
- `test_organization_membership.py` (4) — org/membership
- `test_organization_context.py` (6) — context resolution
- `test_rbac.py` (5) — role-based access
- `test_tenant_endpoints.py` (3) — tenant scoping
- `test_tenant_assessments.py` (4) — tenant assessments
- `test_human_control_plane.py` (5) — HTTP boundary
- `test_operational_hardening.py` (4) — config, rate limiting, metrics
- `test_endpoint_presence.py` (5) — presence evaluation
- `test_presence_maintenance_and_fleet.py` (2) — maintenance + fleet
- `test_tenant_security_overview.py` (2) — reporting
- `test_finding_identity_and_detail.py` (2) — fingerprinting
- `test_finding_recurrence.py` (2) — recurrence
- `test_finding_coverage.py` (10) — coverage semantics
- `test_fleet_query.py` (2) — fleet filtering
- `test_endpoint_groups_scopes.py` (1) — groups + scopes
- `test_assessment_scheduling.py` (1) — scheduling
- `test_scheduler_worker.py` (4) — worker
- `test_compliance.py` — compliance evaluation
- `test_compliance_snapshots.py` — snapshot lifecycle
- `test_compliance_retention_and_trends.py` — retention + trends
- `test_compliance_snapshot_integrity.py` — immutability
- `test_database_backup_restore.py` (1) — backup safety
- `test_legacy_scanner.py` (2) — legacy scanner shape protection
- `test_enhanced_scanner.py` (3) — enhanced scanner
- `test_remediation_safety.py` (3) — remediation guards
- `test_imports.py` (1) — import smoke test
- `test_database.py` (1) — database lifecycle
- `test_ai_boundary.py` — AI isolation
- `test_configuration.py` — config validation

**Integration tests (21 files):**
- `test_api_health.py` (1) — health endpoint
- `test_domain_scan_api.py` (4) — scan API path
- `test_background_workflows.py` (3) — background tasks
- `test_agent_runtime_in_process.py` (2) — full agent loop
- `test_distributed_assessment.py` (3) — end-to-end assessment
- `test_http_agent_transport.py` (5) — HTTP transport
- `test_remote_assessment_durability.py` (9) — durable state
- `test_sqlalchemy_endpoint_repository.py` (2) — endpoint persistence
- `test_sqlalchemy_enrollment.py` (2) — enrollment persistence
- `test_sqlalchemy_replay_guard.py` (1) — replay guard
- `test_sqlalchemy_agent_work_repository.py` (2) — work persistence
- `test_sqlalchemy_security_audit_repository.py` (1) — audit persistence
- `test_sqlalchemy_user_repository.py` (1) — user persistence
- `test_sqlalchemy_organization_membership_repository.py` (2) — org persistence
- `test_sqlalchemy_rbac_repository.py` (1) — RBAC persistence
- `test_sqlalchemy_tenant_endpoints.py` (2) — tenant endpoint isolation
- `test_sqlalchemy_tenant_assessments.py` (1) — tenant assessment isolation
- `test_sqlalchemy_presence_repository.py` (1) — presence persistence
- `test_operational_endpoints.py` (1) — operational routes
- `test_main_control_plane_composition.py` (1) — app wiring

### 10.2 Running Tests

```bash
# Requires Python 3.11
pip install -r requirements-dev.txt
python -m pytest -q
```

CI configuration (`.github/workflows/test.yml`):
- `windows-latest`, Python 3.11
- `python -m compileall -q backend`
- `python -m pytest -q`

### 10.3 Important Test Boundaries

- **No live AI/network/destructive scanner dependency in tests** — AI and Windows-specific checks are mocked or skipped
- **Security boundary tests** — enrollment trust, credential separation, tenant isolation, RBAC enforcement, replay protection
- **Legacy scanner behavior tests** — finding shape compatibility, compliance inputs
- **Python 3.14 is not supported** until all optional native dependencies are validated

---

## 11. What Is Still Deferred

| Item | Category | Notes |
|---|---|---|
| **MFA** | Authentication | Single-factor password only |
| **SSO / OIDC** | Authentication | No enterprise identity federation |
| **SCIM / directory sync** | Identity | No automated user provisioning |
| **Public RBAC administration API** | Authorization | Roles/permissions managed internally; no tenant-facing admin UI |
| **Production Postgres validation** | Database | SQLite only; Postgres path exists but untested |
| **Alembic migration chain** | Database | Schema created from models; no versioned migrations |
| **Distributed rate limiting** | Security | In-memory only; not shared across instances |
| **mTLS** | Security | Agent transport uses TLS + bearer token |
| **Protocol signing** | Security | Message envelopes not cryptographically signed |
| **Agent installer** | Deployment | No Windows service packaging or MSI |
| **Agent auto-update** | Deployment | No update channel |
| **Agent local credential storage** | Agent | No secure credential vault on endpoint |
| **Generic command execution** | Safety | Deliberately excluded — no arbitrary command transport |
| **Remote remediation** | Safety | Deliberately excluded — requires separate phase with approval workflow |
| **PDF/CSV report exports** | Reporting | Beyond compliance JSON/CSV snapshot export |
| **Signed reports** | Reporting | No cryptographic report integrity |
| **Report legal hold** | Compliance | No retention lock mechanism beyond snapshots |
| **SIEM integration** | Observability | Audit events stored but not forwarded |
| **Prometheus/StatsD metrics export** | Observability | In-memory counters only |
| **Fleet-scale performance validation** | Operations | No load testing at 1,000+ endpoints |
| **Multi-instance scheduler coordination** | Operations | Single scheduler instance only |
| **Production secret management** | Security | Env vars only; no Vault/KMS |
| **Browser security hardening (CSP)** | Security | Basic headers set; no Content-Security-Policy |
| **Frontend screens: assessments, groups, schedules, reports, settings** | UI | Backend APIs exist; frontend not wired |
| **Human activity feed** | UI | Audit events stored server-side but no read route exposed |

---

## 12. Recommended Next Phases

### Phase 4A — Production Deployment Profile
- Validated PostgreSQL path with connection pooling
- Alembic migration chain for schema versioning
- Environment variable contract documentation
- Production secret management (Vault/KMS integration or documented patterns)
- Backup/restore validation for Postgres
- Reverse proxy configuration examples (nginx/Caddy)
- Deployment smoke test suite
- Container image and docker-compose for production topology

### Phase 4B — Agent Installer and Local Identity Storage
- Windows service packaging (MSI or NSIS installer)
- Secure credential storage on endpoint (DPAPI or similar)
- Enrollment bootstrap UX (token-based, one-command)
- Agent upgrade story (version check + download)
- Controlled polling loop with exponential backoff
- Agent health self-reporting

### Phase 4C — MFA / SSO / Enterprise Identity
- TOTP-based MFA for human authentication
- SSO/OIDC integration (Azure AD, Okta, Google Workspace)
- SCIM or directory sync for automated user provisioning
- Session policy (concurrent session limits, idle timeout)
- Password policy enforcement

### Phase 4D — Production Authorization Administration
- Tenant-facing role management API
- Permission templates for common roles (viewer, operator, admin)
- Role assignment UI in frontend
- Authorization audit review/export
- Tenant admin UX for membership and access management

### Phase 4E — Reporting and Compliance Exports
- PDF report generation with branding
- CSV export for all report types
- Signed/timestamped reports
- Retention policy with legal hold capability
- Evidence packaging for external auditors
- Scheduled report generation and email delivery

### Phase 4F — Production Security Hardening
- mTLS or request signing for agent transport
- Distributed rate limiting (Redis-backed)
- SIEM integration (syslog, webhook, or API forwarding)
- Content-Security-Policy headers
- Alerting framework (critical finding thresholds)
- Penetration-test readiness review
- Bug bounty preparation

### Phase 4G — Safe Remediation Design
- Policy-gated remediation proposals
- Human approval workflow (two-person rule option)
- Dry-run mode with preview
- Rollback model (restore point before remediation)
- Structured action vocabulary (not arbitrary commands)
- AI-assisted remediation suggestion with human validation
- No arbitrary command execution — ever

### Phase 4H — Frontend Completion
- Wire assessments screen to existing backend APIs
- Wire groups & scopes screen to existing backend APIs
- Wire schedules screen to existing backend APIs
- Reports screen with export capabilities
- Settings screen for user preferences
- Activity feed (requires backend audit read route)
- Component extraction from monolithic App.tsx

---

## 13. Risk Register

| Risk | Severity | Area | Current Mitigation | Remaining Work |
|---|---|---|---|---|
| Single-factor authentication | **HIGH** | Security | Password hashing + rate limiting | MFA, SSO/OIDC |
| SQLite write concurrency limits | **HIGH** | Database | Suitable for dev/small deployment | Postgres validation |
| No schema migrations | **MEDIUM** | Database | Schema from models | Alembic chain |
| In-memory rate limiting | **MEDIUM** | Security | Per-instance limiting works for single instance | Distributed limiter |
| No agent installer | **MEDIUM** | Deployment | Manual agent deployment | MSI/service packaging |
| Single-instance scheduler | **MEDIUM** | Operations | Document single-instance constraint | Distributed lock |
| No mTLS / protocol signing | **MEDIUM** | Security | TLS + bearer tokens | mTLS or request signing |
| No production secret management | **MEDIUM** | Security | Env vars | Vault/KMS integration |
| Uncurated `requirements.txt` | **MEDIUM** | Dependencies | `requirements-dev.txt` is curated (23 packages) | Clean up main requirements.txt |
| No SIEM integration | **LOW** | Observability | Durable audit events stored | Forwarding mechanism |
| No fleet-scale performance testing | **LOW** | Operations | Configurable bounds | Load testing |
| Frontend screens incomplete | **LOW** | UI | Backend APIs complete; honest placeholders | Wire remaining screens |
| No browser CSP | **LOW** | Security | Basic headers set | Full Content-Security-Policy |
| Legacy dependency sprawl | **LOW** | Dependencies | Legacy routes conditionally loaded | Separate legacy from enterprise deps |

---

## 14. File / Module Map

```
Raven-x-enterprise/
├── scanner.py                    # Legacy personal scanner (1,740 lines, Tkinter GUI)
├── run.py                        # Master launcher (backend + GUI modes)
├── raven_x_config.json           # Legacy scanner config
├── requirements.txt              # Uncurated legacy dependency dump (1,105 packages)
├── requirements-dev.txt          # Curated enterprise dev deps (23 packages)
├── pytest.ini                    # Test configuration
│
├── backend/
│   ├── api/
│   │   ├── main.py               # FastAPI app composition, middleware, service wiring
│   │   ├── human_control_plane.py # All human-facing tenant-scoped routes (~665 lines)
│   │   ├── system.py             # Legacy system monitoring routes
│   │   └── v1/
│   │       ├── scan.py           # Legacy scan routes
│   │       ├── analysis.py       # Legacy AI analysis routes
│   │       ├── remediation.py    # Legacy remediation routes
│   │       └── reports.py        # Legacy report routes
│   │
│   ├── domain/                   # Pure business contracts (~2,868 lines)
│   │   ├── assessment/           # AssessmentTarget, Finding, Evidence
│   │   ├── scanner/              # ScannerManifest, capabilities
│   │   ├── endpoint/             # Endpoint, EndpointId, lifecycle
│   │   ├── enrollment/           # Enrollment, credentials
│   │   ├── agent_work/           # Work items, delivery
│   │   ├── user/                 # HumanUser, UserSession
│   │   ├── security/             # SecurityPrincipal, AuditEvent
│   │   ├── identity/             # Identity abstractions
│   │   ├── organization/         # Organization, Membership
│   │   ├── rbac/                 # Role, RoleBinding, Permission
│   │   ├── reporting/            # Overview, FindingFingerprint, Coverage
│   │   ├── scheduling/           # Schedule, Recurrence, Calculator
│   │   ├── presence.py           # Presence state, policy
│   │   ├── fleet.py              # Fleet query, sorting
│   │   ├── group_scope.py        # Groups, saved scopes
│   │   ├── compliance.py         # Framework, Control, Evaluation
│   │   └── compliance_snapshot.py # Snapshots, deltas
│   │
│   ├── application/              # Use cases, services, ports (~70 files)
│   │   ├── assessment/           # Local + remote assessment pipeline
│   │   ├── scanner/              # Registry, compatibility, adapters
│   │   ├── enrollment/           # Enrollment service
│   │   ├── agent/                # Message processor
│   │   ├── control_plane/        # Sessions, handlers, dispatch, cancellation
│   │   ├── identity/             # Human auth service
│   │   ├── organization/         # Org service, context, admin
│   │   ├── rbac/                 # Authorizer, service
│   │   ├── endpoint/             # Registry, tenant service, presence
│   │   ├── fleet/                # Fleet query, groups, scopes
│   │   ├── scheduling/           # Service, runner, worker
│   │   ├── reporting/            # Overview, detail, recurrence, coverage
│   │   ├── compliance/           # Service, snapshots, retention
│   │   └── ports/                # 15+ repository/transport port interfaces
│   │
│   ├── infrastructure/           # Adapters (~50 files)
│   │   ├── persistence/          # SQLAlchemy repos + in-memory repos + mappers
│   │   ├── transport/http/       # Agent HTTP ingress, client, outbox
│   │   ├── security/             # Password hasher, secret verifiers
│   │   └── operational/          # Settings, rate limiter, metrics
│   │
│   ├── protocol/
│   │   └── agent/                # Message envelope, typed payloads, validation
│   │
│   ├── agent/
│   │   ├── runtime.py            # RavenXAgent runtime loop
│   │   └── heartbeat.py          # Heartbeat generation
│   │
│   └── core/                     # Legacy backend modules
│       ├── database/             # SQLAlchemy models, db_manager
│       ├── scanner/              # Enhanced scanner, compliance engine
│       ├── remediation/          # Auto-fixer
│       ├── ai/                   # LLM client, learning engine
│       └── monitoring/           # Behavioral monitor
│
├── frontend/
│   ├── package.json              # React + Vite + TypeScript + lucide + framer-motion
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx              # React entry point
│       ├── app/App.tsx           # All screens (~650 lines)
│       └── api/client.ts         # Typed API client
│
├── tests/                        # 250 test functions, 61 files
│   ├── conftest.py               # Shared fixtures
│   ├── fixtures/                 # Test data
│   ├── unit/                     # 40 unit test files
│   └── integration/              # 21 integration test files
│
├── docs/                         # 115+ architecture/security/operations docs
│   ├── architecture/             # ~55 architecture documents
│   ├── security/                 # ~30 security documents
│   ├── deployment/               # Production deployment guide
│   ├── development/              # Environment, CI, scheduling guides
│   ├── operations/               # Backup, restore, recovery, scheduler, retention, upgrade
│   ├── frontend/                 # Frontend documentation
│   └── funding/                  # Funding/milestone documents
│
├── .github/workflows/test.yml    # CI: Python 3.11, windows-latest
├── config/config.yaml            # Backend configuration
└── data/                         # SQLite database files
```

---

## 15. Final Summary

### What RAVEN-X Has Become

RAVEN-X is a **modular, tenant-aware enterprise security assessment platform**
with a preserved personal Windows scanner. It implements a complete
domain-driven control plane with human authentication, organization-scoped RBAC,
an authenticated outbound agent protocol, durable distributed assessment
delivery, fleet management, assessment scheduling, compliance evaluation with
historical snapshots, and security reporting — all backed by 250 regression
tests and 115+ architecture/security documents.

### What Is Safe to Test Now

- Human login → organization selection → command center → fleet view → compliance view
- Agent enrollment → credential issuance → heartbeat → work polling → assessment result submission
- Assessment scheduling with group/scope-based dynamic targeting
- Compliance framework evaluation and snapshot lifecycle
- The complete test suite (`python -m pytest -q` on Python 3.11)
- Legacy personal scanner (`python scanner.py` on Windows with dependencies)

### What Should Not Be Considered Production-Ready Yet

- **Authentication**: No MFA or SSO — unacceptable for production enterprise deployment
- **Database**: SQLite only — Postgres must be validated for concurrent multi-user workloads
- **Deployment**: No agent installer, no container images, no migration chain
- **Rate limiting**: In-memory only — not suitable for multi-instance deployments
- **Secret management**: Env vars only — no Vault/KMS integration
- **Frontend**: Five screens are placeholder — backend APIs exist but UI is not wired

### Next Engineering Milestone

**Phase 4A: Production Deployment Profile** — validate PostgreSQL, establish
Alembic migrations, document the environment variable contract, create container
images, and produce reverse proxy configuration examples. This is the minimum
gate before any external deployment.
