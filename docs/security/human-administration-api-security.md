# Human administration API security

## Mitigated

- Every operation requires bearer-session authentication, explicit organization
  context, and current organization RBAC.
- Membership resources are scoped to the selected organization before mutation,
  preventing cross-tenant membership IDOR.
- Creating a membership does not create a role binding or implicit permission.
- Membership revocation immediately prevents future organization context
  resolution while preserving unrelated organization memberships.
- Audit events use the existing durable security audit boundary and redact
  bearer tokens/passwords.

## Partial / deferred

- A membership creator can reference an existing opaque user ID; no public
  user-search endpoint is available, but authorization of user provisioning is
  intentionally still narrow.
- There is no last-admin invariant or public role-management API.
- Bearer-token theft depends on TLS, expiry, and revocation controls.
- Login rate limiting, MFA, SSO/OIDC, audit-outbox atomicity, organization
  suspend/recovery, reporting, and fleet analytics are deferred.
