# Enrollment trust threat model

| Threat | Status | Current boundary |
|---|---|---|
| Stolen enrollment token | PARTIALLY MITIGATED | High-entropy token, verifier-only storage, expiry and single use; transport delivery is deferred. |
| Enrollment-token replay | PARTIALLY MITIGATED | Consumed state rejects sequential reuse; concurrent/database-specific guarantees remain deferred. |
| Database theft | PARTIALLY MITIGATED | Raw bootstrap and machine secrets are not stored; verifiers remain sensitive and require operational protection. |
| Credential theft or cloning | DEFERRED | No authenticated transport or machine-bound key protocol exists. |
| Credential replay | DEFERRED | Challenge/freshness protocol is not implemented. |
| Credential rotation failure | MITIGATED NOW | Rotation records history and marks the old credential `ROTATED`. |
| Revoked endpoint reconnect | MITIGATED NOW (MODEL) | Credential verification rejects every credential for `REVOKED` endpoints. |
| Forged machine metadata | DEFERRED | Enrollment claims are explicitly unverified. |
| Forged capability claims | DEFERRED | Claims are never used to authorize enrollment. |
| Log/repr secret leakage | MITIGATED NOW | Raw values use redacted representations and are absent from persisted records. |

This phase defines identity proof contracts, not authorization. A credential
does not authorize scans, remediation, commands, or access to any API.
