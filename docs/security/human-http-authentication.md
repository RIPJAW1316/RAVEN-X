# Human HTTP Authentication Security Notes

## Implemented

- Opaque revocable server-side sessions are presented only as
  `Authorization: Bearer ...`.
- Passwords are verified by the existing hasher and never returned or stored
  in session/API data.
- Expiry, revocation, and disabled-user checks run on every request.
- Organization context and current RBAC bindings resolve on every request, so
  membership and role revocations take effect without cache delay.
- Tenant misses use conservative errors to prevent endpoint/assessment IDOR
  disclosure; agent and human authentication remain separate.
- Audit metadata is redacted and never receives bearer tokens or passwords.

## Partial / deferred

Bearer tokens remain replayable if stolen until expiry or logout; production
transport must use TLS. Login brute-force rate limiting, MFA, SSO/OIDC,
refresh-token rotation, and cookie/CSRF design are deferred. CORS is not an
authentication control and must be reviewed separately for deployment.
