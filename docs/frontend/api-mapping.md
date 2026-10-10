# Frontend API mapping

| Screen | Backend routes |
|---|---|
| Login | `POST /api/v1/auth/login` |
| Organization context | `GET /api/v1/auth/organizations` |
| Command Center | `GET /api/v1/organizations/{id}/security/overview`, fleet endpoints |
| Fleet | `GET /api/v1/organizations/{id}/fleet/endpoints` |
| Endpoint detail | `GET /api/v1/organizations/{id}/endpoints/{endpoint_id}` |
| Compliance | `GET /api/v1/organizations/{id}/compliance/frameworks` and summary |

Assessment, group, scope, schedule, audit, and detailed compliance workflows
remain intentionally honest empty states until their complete UI forms are
mapped to existing API contracts.
