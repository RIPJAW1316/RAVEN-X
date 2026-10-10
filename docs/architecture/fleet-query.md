# Tenant fleet query

```text
OrganizationContext → FleetQuery → TenantFleetQueryService
                   → organization-scoped repository query → FleetPage
```

The new `GET /api/v1/organizations/{organization_id}/fleet/endpoints` route
uses offset pagination (default 50, maximum 200), deterministic sorting, and
explicit filters. The existing `/endpoints` bare-list route is unchanged.

Hostname search is a case-insensitive bounded substring. Filter categories are
combined with AND; multiple values in one category use OR. Presence is separate
from endpoint lifecycle, and missing or ownership-inconsistent presence rows
are `UNKNOWN`. Revoked endpoints remain visible when inventory is queried and
retain `lifecycle_status=revoked`.

Sort fields are allowlisted and always use endpoint ID as a deterministic tie
breaker. SQL applies organization ownership before other predicates; unassigned
legacy endpoints never appear. No regex, wildcard language, arbitrary SQL,
metadata blob, dynamic schedule targeting, cache, or global fleet route exists.
