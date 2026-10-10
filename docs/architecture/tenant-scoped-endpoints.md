# Tenant-scoped endpoints (Phase 3D)

Organizations own enterprise endpoints. `Endpoint.organization_id` is an
explicit Raven-X `OrganizationId`; `NULL` means a legacy/unassigned record,
not a default tenant. Ownership is immutable in this phase.

Human access follows:

```text
Human principal → OrganizationContext → RBAC permission
               → tenant-scoped endpoint lookup → operation
```

The endpoint repository provides `get_for_organization` and
`list_for_organization`; human application code uses those operations and
does not filter a global lookup after the fact. Cross-tenant and unassigned
records resolve as not found to tenant services. The raw `get` is retained for
endpoint credential authentication and explicit SYSTEM/INTERNAL processing.

Agent authentication remains `credential → EndpointId → endpoint record`.
Agents do not submit organization claims and cannot change ownership. Endpoint
revocation preserves the owning organization. Organization suspension/revocation
blocks human contexts without deleting endpoint history.

Enrollment can carry an explicit organization scope; unscoped legacy enrollment
continues to produce an unassigned endpoint for compatibility. New enterprise
registration through `TenantEndpointService` rejects missing ownership.

Implemented: ownership, scoped persistence queries, human service, RBAC/resource
checks, immutable ownership, and a narrow additive SQLite upgrade.

Deferred: endpoint transfer/adoption, assessment/work tenancy, fleet HTTP APIs,
pagination, and a general migration framework.
