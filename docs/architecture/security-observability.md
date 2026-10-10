# Security observability

Where Raven-X keeps high-volume security telemetry, how it turns that into
signals, and why none of it lives in the audit trail.

Companion to [`audit-event-policy.md`](audit-event-policy.md), which removed
per-permission-check audit rows. This document is the other half: the telemetry
those rows were being misused for now has a proper home.

---

## 1. Audit versus telemetry

| | Audit trail | Telemetry |
|---|---|---|
| **Question** | What happened, who did it, when? | How much is happening, and is it normal? |
| **Granularity** | One row per security-significant event | Aggregate counts per minute |
| **Durability** | Durable, append-only, survives restart | Process-local, lost on restart |
| **Retention** | Long, exportable, evidentiary | Rolling 60 minutes |
| **Cardinality** | One row per event | Bounded counter series |
| **Home** | `security_audit_events` (SQLAlchemy) | `SecurityTelemetry` (in memory) |

### Why successful permission checks are not audit records

A single operator action performs several permission checks, and every
authenticated page load performs more. Persisting each one produced a trail
that was **97.8% `authorization.allowed`** on the verification tenant, burying
six real operator actions under 263 rows of noise.

Those rows were never being read as history. They were being read — when they
were read at all — as *volume*: is authorization busy, are denials rising. That
is a metrics question, and metrics answer it at a fraction of the cost:

- 40 authenticated read requests → **0 audit rows**, but a counter incremented
  41 times.
- A counter costs a dictionary increment. An audit row costs an INSERT, index
  maintenance, disk, backup, retention and export.

Removing them lost no record of what anyone *did*, because every mutating
operation already writes its own event (`endpoint_group.create`,
`assessment.created`, `compliance.snapshot.create`, …).

### What still goes to the audit trail

Unchanged by this work:

- every security-significant **operation**;
- every **denial** — `authorization.denied` is both audited *and* counted,
  because a denial is simultaneously a historical fact and an operational
  signal.

---

## 2. Components

```
OrganizationRbacAuthorizer ─┐
HumanAuthenticationService ─┼─► SecurityTelemetry ─► MetricsCollector (flat, global)
                            │         │
                            │         └─► TenantSecurityObservabilityService
                            │                      │
                            │                      ├─► evaluate_signals()  (pure, deterministic)
                            │                      └─► GET .../security/metrics
                            │
                            └─► SecurityAuditRepository (denials + operations only)
```

| Component | File | Role |
|---|---|---|
| `SecurityTelemetry` | `infrastructure/operational/security_telemetry.py` | Tenant-scoped, windowed, bounded counters |
| `MetricsCollector` | `infrastructure/operational/metrics.py` | Existing flat process counters — **unchanged**, still fed |
| `evaluate_signals` | `domain/security_signals.py` | Pure deterministic detection rules |
| `TenantSecurityObservabilityService` | `application/observability/service.py` | RBAC + tenant scope + snapshot assembly |

`MetricsCollector` was kept rather than replaced. It has no windows and no
dimensions, so it cannot answer rate questions, but 32 existing metric names
depend on it. `SecurityTelemetry` adds windows and dimensions alongside it and
forwards to it, so both views stay correct.

---

## 3. Metric taxonomy

### Flat process counters (via `MetricsCollector`)

```
authorization_attempts_total
authorization_allowed_total
authorization_denied_total
authentication_success_total
authentication_failure_total
operation_<name>_total
security_observability.requests
security_observability.signals_returned
```

### Windowed dimensional series (via `SecurityTelemetry`)

Keyed by **verified organization**, bucketed per minute:

```
authz.attempts
authz.allowed                     authz.allowed.action.<action>
authz.denied                      authz.denied.action.<action>
                                  authz.denied.reason.<reason_code>
authn.success
authn.failure
operation.<name>
```

### Cardinality strategy

High-cardinality labels are the standard way a metrics system becomes an
outage. Four controls:

1. **Closed sets only.** `action` comes from the `AuthorizationAction` enum (59
   values); `reason_code` from the authorizer's fixed deny reasons (8 values).
   Neither is ever caller-supplied text.
2. **Sanitisation backstop.** `_safe_label` lower-cases, restricts to
   `[a-z0-9._-]`, and truncates to 64 characters, so a stray caller cannot
   inject newlines or unbounded strings into a series name.
3. **Per-bucket ceiling.** `max_series_per_bucket` (400) drops *new* series once
   reached rather than growing. Drops are counted and readable via
   `dropped_series()`.
4. **Tenant ceiling.** `max_organizations` (500) evicts least-recently-used
   tenants rather than growing.

Deliberately **never** used as labels: email, user ID, session ID, credential
ID, endpoint hostname, file hash, or any request input.

### Retention

Sixty one-minute buckets per tenant. Older buckets are pruned on write. Memory
is bounded by `500 tenants × 60 buckets × 400 series`, and in practice far
smaller because most tenants use a handful of series.

---

## 4. Tenant isolation

The same rule as the audit policy: **attribution must be earned**.

- `record_authorization` is called with an organization **only when the
  authorizer has verified the membership** against the repository. Denials that
  fail before verification (`organization_context_required`,
  `principal_context_mismatch`, `membership_context_mismatch`) are recorded
  against the `__unattributed__` bucket.
- `__unattributed__` is a reserved key that no tenant query can reach, so an
  outsider probing a tenant cannot inflate that tenant's denial numbers and
  fabricate a signal against it.
- `TenantSecurityObservabilityService` takes the organization from the resolved
  `OrganizationContext`, never from the request.
- Reading another tenant's metrics returns `403`.

Verified live: 15 probes of a non-member tenant moved neither tenant's counters.

### Authentication is process-wide

Sign-in happens before an organization is chosen, so authentication telemetry
is not attributed to a tenant. The API reports it as process-wide and the UI
says so. Attributing it would require guessing a tenant from an unauthenticated
request — exactly the spoofing vector the rest of this design avoids.

---

## 5. Detection

Rule-based and deterministic. **No machine learning, no statistical model, no
LLM.** Every signal is reproducible from its inputs and carries the numbers
that produced it.

Each rule requires **two** conditions, which is what keeps false positives down:

* an **absolute floor** — one denial out of one attempt is a 100% rate but is
  not an incident;
* a **rate threshold** — raw volume is not abnormal for a large busy tenant.

| Signal | Fires when | Severity |
|---|---|---|
| `authorization.denial_spike` | ≥20 denials **and** denial rate ≥40% | Warning; **critical** at ≥60 denials |
| `authentication.repeated_failure` | ≥10 failed sign-ins in the window | Warning; **critical** at ≥30 |
| `authorization.cross_tenant_probing` | ≥5 denials with a boundary reason code | **Critical** |
| `authorization.sensitive_action_denials` | ≥15 denials against a single action | Warning |

Boundary reason codes are `resource_organization_mismatch`,
`membership_context_mismatch`, `principal_context_mismatch` — a caller reaching
*outside* its tenant rather than merely lacking a permission inside it.

Thresholds live on `SignalThresholds`, are validated on construction, and are
injectable so a deployment can tune them without editing rules.

### Signal shape

```json
{
  "signal_type": "authorization.denial_spike",
  "severity": "critical",
  "detected_at": "2026-09-15T...+00:00",
  "window_minutes": 15,
  "scope": "organization",
  "reason": "60 of 122 authorization attempts were denied (49.2%) in the last 15 minutes, above the 40% threshold.",
  "evidence": { "denied": 60, "attempts": 122, "denial_rate": 0.4918,
                "threshold_rate": 0.4, "threshold_floor": 20 }
}
```

`reason` is plain language; `evidence` carries the inputs so an operator can
check the arithmetic rather than trust a score.

### What this is not

This is a foundation for alerting, not a SIEM. There is no correlation across
signal types, no historical baselining, no per-user behavioural profile, and no
persistence of signals. A signal exists only while the window that produced it
does.

---

## 6. API

```
GET /api/v1/organizations/{organization_id}/security/metrics?window_minutes=15
```

Requires a human session and **`audit.read`**.

**Why `audit.read` rather than a new permission:** this view is an aggregate
over exactly the data that `audit.read` already grants row-level access to, so
it exposes strictly less. A separate permission would add another fail-closed
rollout for no security gain.

| Parameter | Default | Bounds |
|---|---|---|
| `window_minutes` | 15 | 1–60; anything else is `422` |

| Code | Meaning |
|---|---|
| `200` | Snapshot returned |
| `401` | No/invalid session |
| `403` | Not a member, or missing `audit.read` |
| `422` | Invalid `window_minutes` |
| `503` | Observability not composed in this deployment |

Response carries `organization_id`, `generated_at`, `window_minutes`,
`authorization`, `authentication`, `operations` and `signals`. It contains no
user identifiers, email addresses, session data or secrets — asserted by test.

---

## 7. UI

A compact **Security Observability** panel on the Command Center, above the
activity feed. Existing visual language; no redesign.

Ordered so the state reads in about five seconds:

1. **Signals first** — they are the exception. Critical gets a red rail and
   tint, warning amber, each with a glyph (`!!`, `!`) as well as colour, the
   plain-language reason, and the scope when it is action-specific.
2. **Counters second** — Authorization (attempts / allowed / denied / denial
   rate) and Authentication (successes / failures), colour-coded by state.
3. **Denials by action** — the top offenders, when there are any.
4. A note stating that this telemetry is not written to the audit trail.

When nothing is wrong the panel says so in one green line rather than showing
an empty region. Polls every 30 s, paused while the tab is hidden. Mobile
stacks without horizontal overflow.

---

## 8. Configuration

| Setting | Env var | Default |
|---|---|---|
| Diagnostic audit of successful authorizations | `RAVENX_AUDIT_AUTHORIZATION_SUCCESS` | `false` |

Telemetry itself has no feature flag: it is always on, because it is cheap and
because switching it off would blind the signals. Bounds
(`buckets`, `max_organizations`, `max_series_per_bucket`) are constructor
arguments with conservative defaults.

---

## 9. Failure behaviour

Telemetry must never affect a security decision. Both call sites wrap the
recording in a `try/except` that swallows errors, so a telemetry fault degrades
observability and nothing else. An authorization decision is computed and
returned identically whether or not telemetry is attached — asserted by test.

`SecurityTelemetry` is guarded by an `RLock` throughout, matching
`MetricsCollector` and `InMemoryRateLimiter`. A concurrency test drives 8
threads × 100 records and asserts no counts are lost.

---

## 10. Measured effect

| Activity | Audit rows | Telemetry |
|---|---|---|
| 30 authenticated read requests | **0** | 41 attempts counted |
| 1 endpoint-group creation | **1** | counted |
| 60 forbidden requests (real 403s) | **60** (denials are audited) | 60 denials counted |
| 15 probes of a non-member tenant | 0 into that tenant | 0 into either tenant |

With a real denial spike (60 denials / 122 attempts / 49.2%), two signals fired:
a **critical** denial spike and a **warning** for repeated denials against
`endpoint.read`.

---

## 11. Known limitations

1. **Process-local.** Counters are not shared across workers or hosts. With
   multiple API instances each sees only its own traffic, so a distributed
   spike may not reach a threshold on any single instance. A shared store
   (Redis) or an exporter scraped centrally is the fix.
2. **Lost on restart.** Acceptable for an operational view; the audit trail
   remains the durable record.
3. **No metrics export endpoint.** Nothing exposes `MetricsCollector.snapshot()`
   over HTTP in Prometheus or any other format. Adding `/metrics` is the
   natural next step and is what makes these counters useful to infrastructure
   monitoring.
4. **Signals are not persisted.** A signal disappears when its window rolls
   past. There is no signal history, acknowledgement, or alert delivery.
5. **Authentication signals interact with rate limiting.** Login rate limiting
   (5/minute/IP) rejects requests *before* authentication runs, so those
   attempts are never counted. A distributed credential-stuffing attempt from
   many IPs would register; a single-IP burst is throttled first and may not
   reach the failure floor. This is a safe interaction — the attack is blocked
   either way — but it means the counter under-reports blocked attempts.
6. **Authentication is process-wide, not per tenant** (§4).
7. **No alert delivery.** Signals are visible in the UI and API only; no email,
   webhook or SIEM forwarding.
8. **Thresholds are global**, not per tenant. A tenant with unusual traffic
   cannot yet be tuned independently.

---

## 12. Tests

| File | Count | Covers |
|---|---|---|
| `tests/unit/test_security_telemetry.py` | 31 | Counting; action/reason breakdowns; flat counters still fed; window inclusion/exclusion; bucket pruning; window validation; tenant isolation; unattributed separation; label sanitisation; per-bucket and per-tenant cardinality caps; thread safety; all four detection rules with positive and negative cases; threshold validation; determinism |
| `tests/integration/test_security_observability_api.py` | 15 | Snapshot shape; reads produce telemetry but no audit rows; denials in both; `401`/`403`/`503`; cross-tenant read denied; probing does not attribute to the victim; `window_minutes` bounds; no signals on normal traffic; spike produces a signal from real authorizer traffic; evidence present; no identifiers or secrets in the response |
