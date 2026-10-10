# Durable security audit events (Phase 2K)

Security-relevant facts flow through an append-only boundary:

```text
SecurityAuditEvent
        ↓
Audit sink
        ↓
SecurityAuditRepository
        ↓
security_audit_events
```

Events have independent UUID identities and UTC timestamps. They retain principal,
action, resource, outcome, reason code, endpoint/assessment/work/message correlation,
and structured metadata. The repository exposes append, get, and filtered list only;
there is no normal update or delete operation.

The taxonomy covers credential authentication success/failure, replay and authorization
denials, endpoint lifecycle, enrollment and credential lifecycle, assessment creation,
queueing, acknowledgement, completion/failure, delivery failure, expiration, and the
distinct cancellation-requested/cancelled outcomes.

Metadata is recursively redacted for token, secret, credential, authorization,
password, verifier, bearer, and private-key fields. Raw endpoint credentials,
enrollment tokens, verifiers, bearer headers, and lease secrets are never persisted.

Audit write failures are surfaced. Current repository boundaries do not provide a
cross-repository transaction, so critical mutation plus audit atomicity remains a
documented limitation rather than an invented unit-of-work framework.
