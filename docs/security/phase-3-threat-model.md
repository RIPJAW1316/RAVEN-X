# Phase 3 residual threat model

Mitigations include tenant-context authorization, credential revocation,
replay/freshness checks, bounded payloads/exports, safe CSV encoding, audit
events, explicit scheduler topology, and production CORS/proxy validation.
Residual risks include compromised valid agents, database/backup compromise,
single-instance scheduler operation, absent MFA/SSO/device attestation, no
signed snapshots, no legal holds, and process-local metrics/rate limits.
Forwarded headers require an explicitly trusted proxy; TLS is terminated at a
trusted reverse proxy or configured directly for the agent HTTPS boundary.
