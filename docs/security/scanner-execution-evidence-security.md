# Scanner execution evidence security

## Mitigated

Evidence is immutable, bounded, JSON-safe, and rejects secret/command-like
diagnostic text. Completed rules must be attempted; resource outcomes must
refer to discovered resources. Unknown rule/resource claims, malformed evidence,
partial enumeration, version drift, and missing legacy evidence cannot produce
strong absence. Coverage is validated against server-side contracts.

## Partial

Authenticated agents can still lie about valid evidence or scanner versions.
Evidence is explanatory control-plane data, not cryptographic proof. Empty
results remain ambiguous without explicit complete evidence, and legacy
methods do not expose complete failure semantics.

## Deferred

Signed result evidence, device/TPM attestation, durable evidence history,
cross-process contract distribution, and downstream lifecycle state remain
deferred. A false complete declaration could otherwise cause unsafe automatic
resolution, which is intentionally not implemented.
