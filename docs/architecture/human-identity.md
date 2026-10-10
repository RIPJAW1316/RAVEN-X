# Human control-plane identity

Phase 2L adds a transport-neutral human identity boundary:

```text
User → password credential → HumanAuthenticationService → expiring session
     → HUMAN SecurityPrincipal → existing ControlPlaneAuthorizer
```

`UserId` is an opaque UUID independent of email, organization, or role. Email is
canonicalized by trimming and Unicode case-folding and is unique in persistence.
User status is `ACTIVE`, `DISABLED`, or `REVOKED`; inactive users cannot issue or
validate sessions. Passwords and session tokens are never persisted, only scrypt
verifiers. Sessions are opaque, server-side, expiring, and explicitly revocable.

Authentication does not grant permissions. The default authorizer deliberately
denies HUMAN principals until a later membership/RBAC phase. There is no
organization, tenancy, role, public login route, or UI in this phase.

Bootstrap is an internal operation that succeeds only while the user repository
is empty and is normally invoked with the SYSTEM principal. Authentication is
local today; OIDC/SSO, MFA, recovery, throttling, and transport presentation are
deferred.
