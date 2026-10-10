# Tenant-scoped distributed assessments (Phase 3E)

Tenant ownership is derived, never caller-selected:

```text
Organization → Endpoint → RemoteAssessment → AgentWorkItem → result/findings
```

`TenantAssessmentService` resolves the endpoint through the organization-scoped
repository and requires `assessment.create` in the active context. The
dispatcher copies the endpoint organization to the assessment and queued work.
Agents poll by credential and EndpointId; they never submit organization IDs.
Authenticated ACK, progress, and result handlers validate the persisted
endpoint/assessment/work ownership chain.

Human reads, lists, result access, and cancellation use tenant-scoped
assessment repository operations. Raw assessment lookup remains for internal
reconciliation and agent processing only.

Implemented: assessment/work ownership, scoped repositories, HUMAN service,
immutable ownership, result consistency checks, and additive SQLite upgrades.

Deferred: assessment transfer, public fleet APIs, finding search, reporting
aggregation, scheduling, and remediation.
