# Tenant context security

Mitigated now: explicit organization selection, UUID identity validation,
principal-to-user binding, membership-to-organization binding, active-state
checks, cross-organization rejection, and deny-first HUMAN authorization.
Context denials are auditable without storing credentials or session secrets.

Partial: internal application errors retain specific reason codes for tests and
operations. A future public API should generalize organization-not-found and
membership-denied responses to avoid information leakage.

Deferred: endpoint/assessment ownership checks, RBAC, organization switching
HTTP APIs, tenant-wide policy, and protections against a compromised control
plane. A valid human session remains globally authenticated after membership
revocation, but context resolution immediately fails.
