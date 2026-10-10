# Distributed-assessment security notes

## Mitigated now

- Agent reports pass through the Phase 2E credential authenticator, protocol validator, direction authorizer, and replay guard.
- Envelopes carry endpoint and correlation identities; handlers reject mismatched endpoint ownership or correlation IDs.
- Revoked endpoints are rejected by dispatch and by credential authentication.
- Duplicate active sessions are rejected; duplicate terminal results are rejected.
- The in-process transport carries typed envelopes and never serializes credentials into message payloads.

## Partial

- A session is an ephemeral runtime observation and is not itself a trust decision.
- Capability reports are authenticated as originating from an endpoint but remain reported state; policy acceptance is not implemented.
- The in-process control-to-agent direction is trusted because there is no network boundary yet.

## Deferred to transport

TLS/mTLS, connection authentication, channel confidentiality, network replay resistance, rate limiting, denial-of-service controls, and clock synchronization.

## Deferred to authorization

Organizations, RBAC, assessment permissions, scanner policy, result authorization, and operator audit policy.

No remote command or remediation channel exists in this phase.
