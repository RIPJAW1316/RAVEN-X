# Human organization administration API

```text
Human bearer session
       ↓
HUMAN SecurityPrincipal
       ↓
explicit /organizations/{organization_id} context
       ↓
OrganizationContextResolver
       ↓
RBAC
       ↓
TenantOrganizationAdministrationService
       ↓
OrganizationService / OrganizationMembershipService
       ↓
audit
```

Implemented routes: authenticated organization selection discovery, selected
organization self-read, membership list/create/suspend/revoke. Each request
resolves the organization context and permissions anew. Membership creation
uses an existing `user_id` only; it does not perform invitations, signup, or
global user search. A created membership receives no role binding and therefore
no tenant permissions by default.

Organization suspension/revocation, organization update, role/permission
management, endpoint/assessment transfer, reporting, and fleet APIs remain
deferred. Cross-organization membership resources are shaped as `404`.
