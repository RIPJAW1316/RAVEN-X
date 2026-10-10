# RBAC security boundary

Mitigated now: organization-scoped role identities, membership-bound role
bindings, scoped role-name uniqueness, cross-organization binding rejection,
explicit permission validation, default deny, active-state checks, immediate
revocation effects, multi-role union, and audit events for role/binding changes
and authorization decisions.

Partial: application validation enforces organization consistency in addition to
database foreign keys; SQLite foreign-key enforcement depends on existing
connection configuration. Authorization resources are scope-checked where the
repository can resolve their organization.

Deferred: endpoint and assessment ownership, tenant-wide resource filtering,
public role APIs, RBAC administration UI, policy caching, MFA/SSO, and defenses
against a compromised control plane or database.
