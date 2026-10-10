# Organization membership security

Mitigated now: opaque organization and membership IDs, durable pair uniqueness,
explicit lifecycle transitions, deny-first HUMAN authorization, and secret-safe
audit events for lifecycle actions.

Partial: application services can validate referenced users and organizations
when repositories are composed, but database tampering remains an infrastructure
threat outside this domain boundary.

Deferred: RBAC, tenant-scoped resources, cross-organization authorization,
human HTTP login, membership approval workflows, and operational controls for
SYSTEM-principal use. Membership forgery or an active membership alone must
never be treated as a permission grant.
