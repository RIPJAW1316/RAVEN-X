# API operational hardening

Login attempts are protected by a thread-safe in-memory fixed-window limiter
keyed by direct peer address and a SHA-256 hash of the normalized identifier.
Successful login clears that bucket; failures consume attempts. Exceeded
limits return a generic `429` with `Retry-After`, without revealing whether an
account exists. Throttling events are audited without passwords, tokens, or
raw identifiers.

The limiter is single-process only. Distributed brute force, rate-limit
coordination across workers, MFA, and SSO remain deferred. Forwarded client
addresses are not trusted unless an explicit trusted-proxy policy is added.

`/health` performs no dependency work. `/ready` performs only a lightweight
`SELECT 1` against the configured database. Optional AI, scanner, monitoring,
and reporting modules are not required for core control-plane readiness.
