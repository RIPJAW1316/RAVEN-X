# Endpoint-agent runtime security boundary

| Concern | Status | Notes |
|---|---|---|
| Local credential theft | PARTIAL | In-memory store is test/local only; Windows DPAPI/Credential Manager integration is deferred. |
| Local identity tampering | PARTIAL | Explicit identity store boundary exists; OS-protected persistence is deferred. |
| Compromised endpoint | DEFERRED | An agent can submit false but authenticated claims. |
| Forged dispatch | MITIGATED | Endpoint targeting, protocol, freshness, direction, and typed payload validation are enforced locally. |
| Stale dispatch | MITIGATED | Configurable protocol clock-skew validation rejects stale messages. |
| Wrong-endpoint dispatch | MITIGATED | Local `EndpointId` must equal dispatch envelope and payload identity. |
| Malicious scanner ID | MITIGATED | IDs flow only through the existing registry/orchestrator; arbitrary method execution is impossible. |
| Agent process compromise | DEFERRED | No host hardening or secure service boundary exists. |
| Result fabrication | DEFERRED | Results are structured and correlated, but endpoint compromise is not solved. |
| Secret logging | MITIGATED | Credential store and sender representations redact secrets; no credential is placed in normal payloads. |
| Durable local secret storage | DEFERRED | Production OS-secure storage such as DPAPI/Credential Manager is required later. |

The runtime proves local behavior and message construction. It does not create
trust in a compromised machine, and it does not authorize remediation or
commands.
