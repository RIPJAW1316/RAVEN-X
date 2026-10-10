# Organization-scoped RBAC

Phase 3C evaluates human authorization through explicit organization-scoped
bindings:

```text
User → Membership → OrganizationContext → RoleBinding → Role → Permission
                                                     ↓
                                          ControlPlaneAuthorizer
```

Roles belong to exactly one organization. Bindings attach a role to a
`MembershipId`, never directly to a user. Active roles on active bindings are
unioned; disabled/revoked roles or bindings contribute nothing. Membership and
organization status are checked on every decision, so revocation takes effect
without cache invalidation.

Permissions reuse the existing `AuthorizationAction` identifiers. Unknown or
wildcard permissions are rejected. Role names are labels only and never grant
authority. The default is deny. SYSTEM/INTERNAL/ENDPOINT policy remains on the
existing explicit authorizer; HUMAN decisions require a validated
`OrganizationContext`.

No HTTP role-management API, endpoint tenancy, assessment tenancy, permission
cache, or hidden superadmin bypass exists in this phase.
