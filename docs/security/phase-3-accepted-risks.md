# Accepted Phase 3 risks

Accepted for the supported small/single-node deployment are one scheduler
instance, process-local metrics/rate limits, no MFA/SSO, no device attestation,
no signed snapshots, no legal hold, and no PostgreSQL support claim. Database
administrators can modify persisted data; a compromised valid agent can submit
false observations. These are documented boundaries, not hidden guarantees.
