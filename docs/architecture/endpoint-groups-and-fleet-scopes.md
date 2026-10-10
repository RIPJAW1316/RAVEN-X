# Endpoint groups and saved fleet scopes

Phase 3T introduces two deliberately distinct tenant-owned resources:

```text
STATIC GROUP: EndpointGroup → durable endpoint_group_memberships → endpoints
DYNAMIC SCOPE: SavedFleetScope → validated FleetQuery → current FleetPage
```

Groups contain explicit endpoint IDs and change only through explicit bounded
member add/remove operations. Existing memberships remain visible when an
endpoint later becomes revoked, although new revoked memberships are rejected.
Groups cannot nest and have no query language.

Saved scopes persist versioned structured FleetQuery criteria (version 1). They
do not persist organization IDs, page offsets, or materialized memberships.
Resolution calls the Phase 3S `TenantFleetQueryService`, so hostname, presence,
tenant, sorting, and pagination semantics have one authority and reflect live
endpoint state.

Implemented: domain models, SQL/in-memory persistence, tenant-safe services,
RBAC actions, CRUD/member/preview HTTP routes, and redacted DTOs.

Deferred: dynamic schedule targeting, groups of groups, scope composition,
saved filters, exports, compliance/remediation targeting, and distributed
synchronization.
