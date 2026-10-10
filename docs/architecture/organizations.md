# Organization and membership boundary

Phase 3A establishes durable organization identity and human membership:

```text
Organization ← OrganizationMembership ← User
```

`OrganizationId` and `MembershipId` are opaque UUID identities. Organization
names are mutable display values and need not be unique. A membership records
only that one User belongs to one Organization; the `(user_id, organization_id)`
pair is unique, while one user may have memberships in multiple organizations.

Organization and membership lifecycles are `ACTIVE`, `SUSPENDED`, and `REVOKED`.
Records are retained instead of being cascade-deleted. Membership is neither
authentication nor authorization: an authenticated HUMAN with an active
membership remains denied by the default control-plane policy until RBAC exists.

No endpoint or assessment carries organization ownership in this phase.
