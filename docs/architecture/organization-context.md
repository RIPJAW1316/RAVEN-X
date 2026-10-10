# Organization context

Phase 3B resolves an explicit tenant context after human authentication:

```text
HUMAN SecurityPrincipal
        ↓ selected OrganizationId
User lookup
        ↓
Active membership lookup
        ↓
Active organization lookup
        ↓
OrganizationContext
        ↓ future RBAC policy
```

`OrganizationContext` contains only `user_id`, `organization_id`,
`membership_id`, and a resolution timestamp. It is derived state and has no
database table. The resolver never trusts a caller-supplied membership without
checking that it belongs to the authenticated user and selected organization.

Disabled/revoked users, suspended/revoked memberships, and suspended/revoked
organizations are rejected. A user with multiple organizations must select one
explicitly; no default organization is inferred. Membership is not authorization:
the default HUMAN policy remains deny-first and RBAC is deferred.

Endpoint and assessment tenancy are deliberately not implemented.
