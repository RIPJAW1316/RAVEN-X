# Agent protocol threat model

| Threat | Status | Current boundary |
|---|---|---|
| Duplicate message submission | MITIGATED NOW | In-memory replay guard rejects repeated message IDs. |
| Stale/future message replay | MITIGATED NOW | Configurable timestamp clock-skew validation. |
| Forged endpoint ID | DEFERRED TO TRANSPORT | Envelope carries identity, but no credential verification or transport exists. |
| Protocol downgrade/unknown major | MITIGATED NOW | Unsupported major versions are rejected. |
| Malformed payload | MITIGATED NOW | Typed constructors and envelope validation reject invalid structure. |
| Oversized payload | MITIGATED NOW | Configurable serialized payload limit. |
| Credential leakage | PARTIAL | Normal payloads exclude credentials; bootstrap wire serialization remains sensitive. |
| Enrollment-secret leakage | PARTIAL | Default repr/serialization redacts secrets; transport/log handling is deferred. |
| Forged assessment result | DEFERRED TO TRANSPORT | No authenticated message channel exists. |
| Forged capabilities | DEFERRED TO AUTHORIZATION | Capability reports remain claims until authenticated and validated. |
| Replay across process restarts | DEFERRED TO TRANSPORT | Replay state is intentionally in-memory in this phase. |

Protocol validity answers “is this message well formed and fresh?” It does not
answer whether the sender is the endpoint it claims to be, or whether that
endpoint is authorized to perform an operation.

## Phase 2E acceptance updates

- **Stolen credential — PARTIAL:** verifier checks, endpoint binding, expiry,
  rotation, and revocation are enforced; transport protection is deferred.
- **Authenticated replay — MITIGATED:** freshness validation and replay claims
  are integrated before routing. SQL claims survive process recreation.
- **Endpoint substitution — MITIGATED NOW:** credential identity must match
  the envelope endpoint ID.
- **Revoked endpoint/credential — MITIGATED NOW:** lifecycle state is checked
  before routing.
- **Credential stuffing — PARTIAL:** invalid proofs reveal no secret details;
  rate limiting is a future transport concern.
- **Authorization bypass — MITIGATED NOW (MINIMAL POLICY):** inbound agent
  messages are allow-listed and control-to-agent dispatch is rejected inbound.
- **Inbound control-plane spoofing — DEFERRED TO TRANSPORT:** no transport
  authentication or signing exists.
- **Replay storage DoS — PARTIAL:** only message IDs/timestamps are stored and
  expiry purge is available; distributed rate limiting is deferred.
- **False findings from a compromised endpoint — DEFERRED:** authenticated
  results identify the reporter but are not treated as verified truth.
