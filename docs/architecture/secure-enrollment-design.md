# Secure endpoint enrollment — implementation plan (Phase B design)

**Status: DESIGN ONLY. Not implemented. Awaiting independent review.**

Scope: how a Windows endpoint becomes a trusted, credentialed member of an
organization. Covers token issuance, redemption, credential provisioning,
Windows-side storage, revocation and replay.

---

## 1. Investigation findings

### 1.1 The service layer already exists and is sound

`backend/application/enrollment/service.py` implements the full lifecycle:

| Capability | Status |
|---|---|
| `create_enrollment_authorization(ttl, organization_id, metadata)` | Present. Gated on `ENROLLMENT_CREATE`. Default TTL 1 h. |
| Single-use semantics | Present. `PENDING → CONSUMED`; re-use raises `EnrollmentAlreadyUsedError`. |
| Expiry | Present. Checked on redemption and transitions to `EXPIRED`. |
| Revocation | Present — `revoke_authorization`, `revoke_credential`. |
| Credential issue / rotate / revoke | Present. |
| Verification | Present — `verify_credential`, `verify_presented_credential`. |
| Audit | Present — `ENROLLMENT_CREATED/CONSUMED/CONSUMPTION_FAILED/REVOKED`, `CREDENTIAL_ISSUED/ROTATED/REVOKED`. |

Secret handling is correct today:

- `generate_secret()` → `secrets.token_urlsafe(32)` (256 bits).
- `hash_secret()` → scrypt N=2¹⁴, r=8, p=1, 16-byte random salt, 32-byte digest.
  **Only the verifier is persisted**; the plaintext is unrecoverable.
- `IssuedSecret` wraps the one-time plaintext and overrides `__repr__`,
  `__str__` and `to_dict()` to emit `<redacted>`, so an accidental log line or
  error payload cannot leak it.
- `accept_enrollment` creates the endpoint with `EndpointStatus.NEW` and
  `metadata["capabilities_trust"] = "unverified"` — consistent with the North
  Star rule that *a registered endpoint is not automatically trusted*.

### 1.2 The gap: no HTTP surface in either direction

A cold start exposes exactly two agent routes:

```
/api/v1/agent/messages
/api/v1/agent/work
```

There is **no enrollment route at all** — not for administrators to mint a
token, and not for agents to redeem one. `create_enrollment_authorization` and
`accept_enrollment` are reachable only from in-process code and tests.

Two consequences:

1. **Good news:** there is no anonymous-enrollment exposure to close. The
   dangerous default does not exist.
2. **Blocking:** an agent cannot enroll at all. This is the gating dependency
   for WS-07 (Windows agent service).

> **Correction to prior documentation.** Earlier status documents in this
> repository list `/api/v1/agent/enroll`, `/ack` and `/fail` as existing routes.
> They do not exist. Acknowledgement and failure are carried as typed protocol
> messages through `/messages`. Those documents should be corrected.

### 1.3 Weaknesses to address in the design

| # | Finding | Severity |
|---|---|---|
| E-1 | `organization_id` is `Optional` on `create_enrollment_authorization`. A token minted without one produces an endpoint owned by no tenant. | High |
| E-2 | Default TTL is 1 h — reasonable for a token, but there is no cap, so a caller may request an arbitrarily long TTL. | Med |
| E-3 | No binding between a token and the machine that redeems it. Any holder may redeem. | Med |
| E-4 | No single-use enforcement *at the transport layer* — a concurrent double-redeem depends on repository atomicity, which has not been verified under concurrency. | High |
| E-5 | No rate limiting or lockout on redemption attempts; token guessing is bounded only by 256-bit entropy (acceptable) but failures are unthrottled (noisy, and a DoS vector given scrypt cost). | Med |
| E-6 | Enrollment verification uses scrypt (~38 ms). That is correct for a bootstrap secret but must **not** be reused for per-request agent credential checks (that is WS-02's concern). | Med |
| E-7 | `EndpointStatus.NEW` is never advanced — there is no approval step, so "registered ≠ trusted" is stated but not enforced downstream. | High |

---

## 2. Design principles

1. **Two distinct secrets, two distinct lifetimes.** A short-lived, single-use
   *enrollment token* is exchanged exactly once for a long-lived, rotatable
   *agent credential*. The token never authenticates ongoing traffic.
2. **An administrator mints; an agent redeems.** Token creation is an
   authenticated, organization-scoped, RBAC-gated human action. There is no
   unauthenticated path that creates trust.
3. **Tenancy is bound at mint time, never claimed at redeem time.** The agent
   never sends an `organization_id`; it is read from the authorization record.
   This mirrors the earned-attribution rule the audit and telemetry layers use.
4. **Registration is not trust.** Enrollment produces a `PENDING_APPROVAL`
   endpoint that can heartbeat and report inventory but receives no assessment
   work until an administrator approves it.
5. **Plaintext exists once, in one direction, in memory.** It is returned in a
   single response body and never logged, audited, persisted, or re-displayed.

---

## 3. Proposed API contracts

### 3.1 Mint an enrollment token (human, authenticated)

```
POST /api/v1/organizations/{organization_id}/enrollment-tokens
Authorization: Bearer <human session>
Permission: enrollment.create
```

Request:
```json
{ "ttl_minutes": 60, "label": "lab-rollout-batch-3", "max_uses": 1 }
```

Response `201`:
```json
{
  "enrollment_id": "uuid",
  "organization_id": "uuid",
  "expires_at": "2026-10-10T12:00:00+00:00",
  "label": "lab-rollout-batch-3",
  "status": "pending",
  "enrollment_token": "<256-bit urlsafe token — shown exactly once>"
}
```

- `ttl_minutes` bounded to **1–1440**, default 60 (closes E-2).
- `organization_id` comes from the resolved `OrganizationContext`, never the
  body (closes E-1).
- `enrollment_token` appears in this response and nowhere else, ever.
- `max_uses` is accepted but **must be 1** in this phase; the field exists so a
  future batch-provisioning mode is a value change, not a schema change.

```
GET    /api/v1/organizations/{organization_id}/enrollment-tokens        # list, never returns the token
DELETE /api/v1/organizations/{organization_id}/enrollment-tokens/{id}   # revoke
```

The list response returns `enrollment_id`, `label`, `status`, `created_at`,
`expires_at`, `consumed_at`, `consumed_by_endpoint_id` — never the secret, and
never the verifier.

### 3.2 Redeem a token (agent, unauthenticated-but-token-bearing)

```
POST /api/v1/agent/enroll
Authorization: Bearer <enrollment token>
X-Raven-Enrollment-Id: <enrollment_id>
```

Request:
```json
{
  "hostname": "LAB-PC-014",
  "platform": { "name": "Windows 11 Pro", "version": "10.0.26200", "architecture": "x64" },
  "agent": { "agent_version": "1.5.0", "protocol_version": "1" },
  "capabilities": ["windows.firewall.read", "windows.registry.read", "windows.powershell"],
  "machine_fingerprint": "<stable machine id>"
}
```

Response `201`:
```json
{
  "endpoint_id": "uuid",
  "organization_id": "uuid",
  "status": "pending_approval",
  "agent_credential": "<256-bit urlsafe credential — shown exactly once>",
  "credential_id": "uuid",
  "credential_expires_at": "2027-10-10T00:00:00+00:00",
  "poll_interval_seconds": 60
}
```

Failure responses are deliberately uniform — `401 enrollment_rejected` for
unknown, expired, revoked, already-consumed, or invalid-token, so the endpoint
cannot be used as an oracle to enumerate valid enrollment IDs.

### 3.3 Approve an endpoint (human, authenticated)

```
POST /api/v1/organizations/{organization_id}/endpoints/{endpoint_id}/approve
Permission: endpoint.update
```

Transitions `PENDING_APPROVAL → ACTIVE`. **Until approved, the endpoint may
heartbeat and report inventory but is never issued assessment work** (closes
E-7). This is the enforcement behind "registered ≠ trusted".

---

## 4. Server-side implementation plan

### 4.1 Domain

- Add `EndpointStatus.PENDING_APPROVAL` between `NEW` and `ACTIVE`.
- Add `EnrollmentAuthorization.label`, `consumed_by_endpoint_id`,
  `created_by_user_id`, `machine_fingerprint` (nullable).
- Enforce `organization_id` as **required** on `create_enrollment_authorization`
  (E-1). Keep the parameter optional in the signature only long enough to
  migrate existing in-process callers, then make it mandatory.

### 4.2 Application

- `TenantEnrollmentService` — a new tenant-scoped wrapper, following the exact
  shape of `TenantAuditQueryService`: human principal check → `OrganizationContext`
  check → RBAC → delegate. The organization is taken from context, never the request.
- Cap `ttl` at 1440 minutes; reject outside 1–1440 (E-2).
- Make redemption atomic (E-4): the consume step must be a conditional update
  (`UPDATE ... WHERE status = 'pending'`) and treat zero affected rows as
  `EnrollmentAlreadyUsedError`. A concurrency test must drive N parallel
  redemptions of one token and assert exactly one succeeds.
- Optional fingerprint binding (E-3): if the mint request supplied a
  `machine_fingerprint`, redemption must present the same value.

### 4.3 Transport

- New `POST /enroll` on the agent router.
- Rate-limit redemption per source address using the existing
  `InMemoryRateLimiter` (E-5). Failures must be cheap — reject malformed or
  unknown `enrollment_id` **before** performing scrypt, so an attacker cannot
  force unbounded scrypt work.
- Uniform `401` for every rejection reason; the specific reason goes to the
  audit trail, not the response.

### 4.4 Audit and telemetry

Reuse the existing split established in `audit-event-policy.md`:

| Event | Destination |
|---|---|
| Token minted / revoked | Audit (operational), attributed to the verified organization |
| Redemption succeeded | Audit (operational) |
| Redemption rejected | Audit (security) **and** telemetry counter |
| Endpoint approved | Audit (operational) |

Add `enrollment_redemption_{attempts,rejected}_total` to `SecurityTelemetry`, and
a detection rule for repeated redemption failures — a burst of rejected
redemptions is a credible indicator of token brute-forcing or a leaked batch
token being probed.

**No audit or telemetry field may contain the token or the credential.**
`IssuedSecret` already guards accidental serialization; a test must assert the
plaintext appears in no audit row and no response other than the single mint and
redeem responses.

---

## 5. Windows credential storage

The agent must persist `endpoint_id` + `agent_credential` across reboots without
leaving the secret readable by a standard lab user.

**Mechanism: DPAPI at machine scope.**

```
CryptProtectData(credential, CRYPTPROTECT_LOCAL_MACHINE)
→ %ProgramData%\RavenX\agent\credential.bin
```

| Requirement | Decision |
|---|---|
| Encryption | DPAPI machine scope — bound to the machine, no key management needed, survives reboot and user logout |
| Location | `%ProgramData%\RavenX\agent\` — machine-wide, not per-user |
| ACL | `SYSTEM: Full`, `Administrators: Full`, **inheritance disabled**, no `Users` entry |
| Service account | `LocalSystem` initially; `NT SERVICE\RavenXAgent` once the service exists |
| File mode | Written to a temp file in the same directory, ACL applied, then atomically renamed |
| Plaintext on disk | Never. The enrollment token is held in memory only and zeroed after redemption |
| Logging | The agent log must never contain either secret. Enforce with a redacting formatter plus a test |

**Trade-off to accept explicitly:** DPAPI machine scope means any process running
as Administrator or SYSTEM on that host can decrypt the credential. That is the
correct bound — an attacker with SYSTEM on the endpoint has already won, and the
credential grants only that endpoint's own scope. Protecting against local
Administrator would require a TPM-backed key, which is out of scope here and
should be recorded as a future option.

**Reboot-restore labs** (the reference deployment is a college lab) wipe
`%ProgramData%` on reboot. Two supported paths:

1. Place the store on a persistent partition via a documented config override.
2. Accept re-enrollment on every boot, which requires a **reusable,
   fingerprint-bound** enrollment token and a server-side rule that a matching
   fingerprint re-binds to the existing `endpoint_id` instead of creating a
   duplicate. This is the main reason `machine_fingerprint` is in the design.

---

## 6. Threat model

| Threat | Mitigation |
|---|---|
| Anonymous enrollment | No unauthenticated mint path. Minting requires a human session plus `enrollment.create` in the target organization. |
| Token theft in transit | HTTPS required. Token is single-use and short-lived, so a replayed capture is already consumed. |
| Token theft at rest (server) | Only the scrypt verifier is stored. Plaintext is unrecoverable. |
| Token theft at rest (deployment script) | Short TTL limits the window. `label` plus the audit trail makes a leaked batch traceable. Revocation is immediate. |
| Replay of a redeemed token | Single-use; conditional update makes the race safe. |
| Token brute force | 256-bit entropy; rate-limited; pre-scrypt cheap rejection prevents CPU exhaustion. |
| Enumeration of enrollment IDs | Uniform `401` for every failure reason. |
| Cross-tenant enrollment | `organization_id` is read from the authorization record, never from the agent request. |
| Rogue endpoint joining the fleet | `PENDING_APPROVAL` — no assessment work until a human approves. |
| Credential theft on endpoint | DPAPI machine scope plus restrictive ACL; revocation and rotation available; scope limited to that endpoint. |
| Compromised endpoint pivoting | Credential authenticates only that `endpoint_id`; existing ownership checks reject cross-endpoint access. |

---

## 7. Test plan

1. Mint requires authentication, organization membership and `enrollment.create`.
2. Minted token is bound to the context organization; a body-supplied
   `organization_id` is ignored.
3. `ttl_minutes` outside 1–1440 is rejected.
4. The token appears in the mint response and in **no** audit row, log line, or
   list response.
5. Redemption succeeds exactly once; the second attempt returns `401`.
6. **Concurrency:** N parallel redemptions of one token produce exactly one
   endpoint and one credential.
7. Expired, revoked and unknown tokens all return an identical `401` body.
8. Redemption produces an endpoint in `PENDING_APPROVAL` owned by the minting
   organization.
9. An unapproved endpoint receives no work from `/work`.
10. Approval transitions to `ACTIVE` and work then flows.
11. Rejected redemptions are rate-limited and increment telemetry.
12. Unknown `enrollment_id` is rejected without performing scrypt.
13. Credential verification rejects revoked and expired credentials.
14. Rotation invalidates the previous credential.
15. Fingerprint mismatch is rejected when the token was fingerprint-bound.
16. Existing agent `/messages` and `/work` behaviour is unchanged.

---

## 8. Sequencing and dependencies

| Step | Depends on |
|---|---|
| 1. Domain: `PENDING_APPROVAL`, required `organization_id`, new fields | — |
| 2. Atomic consume + concurrency test (E-4) | 1 |
| 3. `TenantEnrollmentService` + admin routes (mint / list / revoke) | 1, 2 |
| 4. Agent `POST /enroll` + rate limiting | 3 |
| 5. Approval route + work gating (E-7) | 1 |
| 6. Telemetry counters and detection rule | 4 |
| 7. Windows credential store + agent bootstrap | 4 (this is WS-07) |

Steps 1–6 are server-side and independently testable. Step 7 is the agent and
should be a separate work stream.

---

## 9. Open questions for review

1. **Reusable batch tokens.** A 70-PC rollout with strictly single-use tokens
   means 70 mint operations. Should a `max_uses > 1` token be permitted, bounded
   by count *and* TTL *and* organization? It weakens the single-use property in
   exchange for operational practicality.
2. **Auto-approval policy.** Should an organization be able to opt into
   auto-approving endpoints that redeem a fingerprint-bound token, for
   reboot-restore labs? This trades the human approval gate for usability.
3. **Credential lifetime.** Proposed one year with rotation. Shorter is safer but
   requires the rotation path to be proven reliable first.
4. **Fingerprint source.** Machine GUID, TPM EK public hash, or a composite?
   Affects how re-imaged machines behave.
5. **Scope of `enrollment.create`.** Should it be a distinct permission from
   `endpoint.create`, and should it be grantable at group scope?

---

## 10. Explicitly out of scope

- Remote remediation or command execution. Unchanged: the agent collects
  evidence only.
- mTLS and protocol signing — separate hardening streams.
- Agent auto-update.
- TPM-backed credential sealing.
