# Control-plane authorization boundary (Phase 2K)

Sensitive application operations now have an explicit, replaceable authorization
boundary:

```text
SecurityPrincipal
       ↓
AuthorizationAction + AuthorizationResource
       ↓
ControlPlaneAuthorizer
       ↓
AuthorizationDecision
       ↓
Application operation
```

The initial policy is deny-first. `SYSTEM` and explicitly named `INTERNAL`
principals may perform only the configured lifecycle actions. `ENDPOINT` principals
may submit heartbeat, capability, status, ACK, progress, and result messages for
their own endpoint scope only. They cannot create/cancel assessments, revoke
endpoints, or rotate arbitrary credentials.

`HUMAN` principals are now represented for authentication, but organizations,
tenants, RBAC roles, and permission APIs are not implemented. The deny-first
policy intentionally grants no sensitive permissions to a human merely because
their session is valid.

Authentication remains credential verification. Authorization is a separate policy
decision. Audit is a separate historical record.

Phase 3B adds a validated `OrganizationContext` for HUMAN operations. It proves
that the selected organization, authenticated user, and active membership agree;
it does not grant authorization. The default HUMAN policy remains deny-first.
Authentication establishes identity only; organization membership and RBAC policy
are deferred.
