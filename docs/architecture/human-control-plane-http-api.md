# Human Control-Plane HTTP API (Phase 3F)

```text
Authorization: Bearer <opaque session token>
        ↓
HumanSessionAuthenticator → HUMAN SecurityPrincipal
        ↓
/organizations/{organization_id}/...
        ↓
OrganizationContextResolver (per request) → current RBAC
        ↓
TenantEndpointService / TenantAssessmentService
```

Implemented routes are login, logout, `auth/me`, tenant-scoped endpoint
list/get, and tenant-scoped assessment create/list/get/cancel. Organization
selection is explicit in the URL and is not stored as session state. Routes
never perform global endpoint or assessment lookups.

`/api/v1/agent/...` remains a separate machine-credential boundary. No public
signup, organization/RBAC administration, fleet reporting, remediation,
command execution, or scheduling API is exposed here. Responses are JSON-safe
and exclude authentication material. Cross-tenant resource misses are shaped
as `404`; unavailable organization context is shaped as `403`.

Bearer tokens must only be sent over HTTPS in production. Login has no rate
limiting or MFA yet and is not internet-production-ready. Narrow human API:
IMPLEMENTED; administration, reporting, MFA, and rate limiting: DEFERRED.
