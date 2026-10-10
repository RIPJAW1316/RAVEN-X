# Audit event policy

What Raven-X persists to the security audit trail, and why. Companion to
[`security-activity-feed.md`](security-activity-feed.md), which covers how that
trail is read.

---

## 1. The problem this policy solves

`OrganizationRbacAuthorizer` used to write an `authorization.allowed` record on
every successful permission check. Because one operator action performs several
checks, and because every authenticated page load performs more, the audit
table filled with them.

Measured on the verification tenant immediately before this change:

| | Rows | Share |
|---|---|---|
| `authorization.allowed` | 263 | **97.8%** |
| Everything an operator would care about | 6 | 2.2% |
| **Total** | **269** | |

The read API mitigated this by hiding those rows by default, but that treated
the symptom. Storage, retention, export and any future SIEM forwarding all
still carried 98% noise.

---

## 2. The distinction

> A successful **permission check** is an implementation detail.
> A successful **security-sensitive operation** is an audit event.

| Class | Meaning | Persisted |
|---|---|---|
| **OPERATIONAL** | An action a tenant performed, or that happened to their estate: enrollment, assessment, group/scope change, schedule change, compliance snapshot or export, membership or role change, credential lifecycle. | Always |
| **SECURITY** | A control rejecting something: `authorization.denied`, `human.authentication_failed`, `credential.authentication_failed`, `agent.message_replay_rejected`, `enrollment.consumption_failed`, `organization.context_denied`. | Always — cannot be configured off |
| **DIAGNOSTIC** | Internal authorization telemetry: `authorization.allowed`. | **No**, by default |

Classification lives in `backend/domain/audit.py` (`AuditEventClass`,
`classify`) so retention and display agree on one definition.

### Why suppressing successful checks loses nothing

Every mutating operation already writes its own event from the service that
performs it — `TenantEndpointService`, `TenantEndpointGroupService`,
`RemoteAssessmentDispatcher`, `TenantComplianceSnapshotService`,
`AssessmentScheduleRunner`, `EnrollmentService`, and so on. The permission
check that preceded the operation adds no information the operation event does
not already carry, and carries it at worse granularity.

For *read* operations the check was the only record — and a read of a fleet list
is not an audit event. Reads that genuinely need auditing (export, evidence
retrieval) should emit their own operation event at the point of export, not
rely on a permission-check trace.

### This is not a new policy

`AuthorizationService` in
`application/ports/control_plane_authorization.py` has always audited only
denials:

```python
if self.audit_sink is not None and not decision.allowed:
```

`OrganizationRbacAuthorizer` was the sole outlier. This change makes it
consistent.

---

## 3. Why denials are never suppressed

A denial is evidence that a control did its job. A burst of them can indicate:

- privilege escalation attempts
- a compromised credential exercising permissions the legitimate user lacks
- tenant-boundary probing
- malicious automation enumerating endpoints

`AuthorizationAuditPolicy` therefore has **no** flag for denials. The only
tunable concerns successful authorizations:

```python
@dataclass(frozen=True)
class AuthorizationAuditPolicy:
    record_successful_authorizations: bool = False   # diagnostic opt-in
    always_recorded_actions: FrozenSet[str] = frozenset()
```

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `record_successful_authorizations` | `RAVENX_AUDIT_AUTHORIZATION_SUCCESS` | `false` | Short-lived diagnostic during an authorization investigation. Restores the full trace. |
| `always_recorded_actions` | — | empty | Actions whose successful authorization is always recorded. Reserved for grants with no operation-level event of their own that are infrequent enough not to flood the trail. |

`always_recorded_actions` is empty today: every action reaching this authorizer
either has its own operation event or is a high-frequency read. It exists so a
compliance regime that demands "successful access to X must be logged" can be
satisfied without re-enabling the whole trace.

---

## 4. Audit integrity: attribution must be earned

Two defects were found during live verification of this change. Both allowed an
event to be attributed to an organization the actor had not proven membership
of — an **audit-injection** vector: an authenticated user could pollute another
tenant's audit feed simply by naming that tenant in a URL.

### Rule

> An audit event may name an organization only after a membership linking the
> acting principal to that organization has been read back from the repository
> and validated.

### Applied in `OrganizationRbacAuthorizer._deny`

| Deny reason | Attributed | Why |
|---|---|---|
| `organization_context_required` | No | No context at all |
| `invalid_organization_context` | No | Context malformed |
| `principal_context_mismatch` | No | Principal does not match the claimed user |
| `membership_context_mismatch` | No | Membership claim unverified |
| `membership_inactive` | **Yes** | Membership read back and matched |
| `organization_inactive` | **Yes** | Organization read back |
| `resource_organization_mismatch` | **Yes** | Verified member probing across the boundary — exactly what the tenant should see |
| `permission_not_granted` | **Yes** | Fully verified member |

### Applied in `OrganizationContextResolver._deny`

Previously this attributed **every** denial to the *requested* organization,
including `ORGANIZATION_NOT_FOUND` and `MEMBERSHIP_NOT_FOUND`. It now passes
`verified=True` only after a membership for this user and organization has been
found: `PRINCIPAL_MEMBERSHIP_MISMATCH`, `MEMBERSHIP_SUSPENDED`,
`MEMBERSHIP_REVOKED`.

Attribution is always built from server-side repository reads. Caller-supplied
resource metadata is never used as the source of `organization_id`, `user_id`
or `membership_id`.

### Consequence: denials are now visible to the tenant

Because denials previously carried no `organization_id`, and the feed excludes
unattributed rows, `authorization.denied` was **invisible in every tenant
feed**. The most security-significant event type could not be seen by the
tenant whose boundary was being probed. Verified denials now reach the feed and
render as `critical`.

---

## 5. Outcome correctness

`HumanAuthenticationService._audit` derived its outcome as:

```python
SUCCESS if event_type is HUMAN_AUTHENTICATION_SUCCEEDED else DENIED
```

so `session.issued` — a success — was stored with `outcome="denied"`. Since
`derive_severity` maps `denied` to `critical`, **every successful sign-in was
recorded and rendered as a critical security event**. Inverted to test for the
failure type instead, and the acting `user_id` is now attached.

---

## 6. Measured effect

Live, against the QA tenant, after the change:

| Activity | Audit rows written |
|---|---|
| 40 authenticated read requests (overview, fleet, endpoints, audit feed × 10) | **0** |
| 1 endpoint-group creation | **1** |
| 1 cross-tenant probe (denied) | **1** |
| 20 probes of a non-member tenant | **0 injected into it** |

Steady-state write volume for a browsing operator drops from roughly one row
per permission check to **zero**. On the measured sample the reduction is
**97.8%** of rows, and every remaining row is an operator-meaningful action or
a security event.

---

## 7. Compatibility

- **Historical rows are untouched.** No `authorization.allowed` record was
  deleted or rewritten. They remain readable via
  `include_permission_checks=true`.
- **The read API is unchanged.** `excluded_event_types` still reports the
  suppression, and the `include_permission_checks` parameter still works. It
  now surfaces historical rows and rows captured while diagnostic auditing was
  on, rather than a constant stream.
- **Authorization behaviour is unchanged.** The policy governs auditing only;
  tests assert allow/deny decisions are identical under every policy.
- **The UI toggle is retained** because it remains useful for reading history
  and for diagnostic sessions. Its tooltip and the feed disclosure were
  reworded to state that routine checks are no longer recorded.

---

## 8. Where diagnostic telemetry belongs

Authorization tracing is an **observability** concern, not an audit concern. The
right home is the structured request log, which already carries a request ID,
method, path, status and duration per request, correlated via `X-Request-ID`.

If per-check tracing is needed in production, the options in preference order
are:

1. Structured logs at debug level, sampled, with the request-ID correlation
   that already exists.
2. **Implemented** — `SecurityTelemetry` counts every authorization evaluation
   by action and outcome in rolling per-minute windows, and deterministic rules
   raise signals from it. See
   [`security-observability.md`](security-observability.md).
3. `RAVENX_AUDIT_AUTHORIZATION_SUCCESS=true` for a bounded window when a
   specific authorization question needs per-event detail.

---

## 9. Tests

| File | Covers |
|---|---|
| `tests/unit/test_authorization_audit_policy.py` (17) | Routine checks write nothing; diagnostic mode restores the trace; `always_recorded_actions`; denials always recorded and never configurable off; verified vs unverified denial attribution; forged context cannot reach the target tenant; attribution not taken from caller metadata; allow/deny decisions unchanged; taxonomy |
| `tests/unit/test_audit_attribution_integrity.py` (7) | Non-member cannot inject into a tenant feed; unattributed denials for unknown org / non-member; verified suspension is attributed; successful login is not a denial; failed login still is; login events carry the actor |
| `tests/integration/test_audit_signal_quality.py` (8) | Read-only navigation writes nothing through the real HTTP stack; one operation → one event; signal ratio; denials visible in the default feed; diagnostic mode; historical rows preserved; audit polling does not feed itself |

---

## 10. Known limitations

1. **Login events have no organization context**, so successful and failed
   sign-ins do not appear in any tenant feed. Correct for isolation — a user
   can belong to several organizations and the tenant is not known at
   authentication time — but it means a tenant cannot see failed sign-ins
   against its own members. Surfacing those safely needs a deliberate decision
   about which organizations a failed login should be visible to.
2. **`always_recorded_actions` is empty**, so the mechanism is untested in
   production use.
3. **No sampling.** The diagnostic flag is all-or-nothing; a sample rate would
   be gentler for long-running investigations.
4. ~~**Metrics counters for authorization outcomes are not yet emitted.**~~
   **Done** — see [`security-observability.md`](security-observability.md).
