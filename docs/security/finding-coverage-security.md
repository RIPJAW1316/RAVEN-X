# Finding coverage security notes

## Mitigated now

Coverage starts from a server-resolved finding occurrence. The service obtains
the assessment and endpoint through the existing human organization context,
assessment-read authorization, and organization-scoped repository query. A raw
client fingerprint cannot select another endpoint or tenant. History is bounded
and output contains no raw evidence, credentials, tokens, or remediation
commands.

## Partial

Coverage contracts are conservative but rely on the correctness of authenticated
scanner execution metadata and the existing protocol/replay pipeline. The
in-memory/service projection is not a durable snapshot and does not provide a
global consistency guarantee across concurrent writers.

## Deferred

Cryptographic result attestation, capability trust establishment, durable
coverage/lifecycle state, cross-process caching, broader rule-level coverage,
and operational rate limiting remain deferred. Coverage is informational and
must not itself authorize remediation or commands.
