# Scanner coverage contract security

## Mitigated

Contracts are immutable, validated, duplicate-resistant, and default-deny for
absence inference. Coverage is resolved from server-side occurrence identity,
not client-supplied fingerprints. Capability failures, malformed results,
partial execution, and legacy metadata cannot become strong absence. Output is
structured and excludes commands and sensitive evidence.

## Partial

The control plane relies on authenticated scanner execution metadata. A valid
but compromised agent can forge a successful result or scanner version;
coverage contracts are explainable policy, not cryptographic proof. In-memory
read-model computation is not a durable audit record.

## Deferred

Cryptographic/device attestation, signed result evidence, durable lifecycle
state, cross-process contract distribution, and stronger resource-enumeration
proof remain deferred. False strong declarations would create downstream false
resolution risk, so contract review and tests are required before promotion.
