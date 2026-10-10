# Authorization action catalog

Permissions are the existing stable `AuthorizationAction` values; RBAC does not
create a second namespace.

- Endpoint: `endpoint.create`, `endpoint.read`, `endpoint.update`, `endpoint.revoke`
- Organization: `organization.create`, `organization.read`, `organization.update`, `organization.suspend`, `organization.revoke`
- Membership: `membership.create`, `membership.read`, `membership.update`, `membership.suspend`, `membership.revoke`
- Roles: `role.create`, `role.read`, `role.update`, `role.disable`, `role.revoke`
- Role bindings: `role_binding.create`, `role_binding.read`, `role_binding.update`, `role_binding.revoke`
- Assessment: `assessment.create`, `assessment.read`, `assessment.cancel`
- Credentials/enrollment: existing explicit credential and enrollment actions
- Agent messages: existing endpoint-scoped submit actions

Unknown strings, wildcard permissions, and role-name-based authority are not
accepted. New actions added later are denied for existing roles until explicitly
assigned.

Endpoint actions grant capability only inside the active `OrganizationContext`
and never provide global endpoint access.
