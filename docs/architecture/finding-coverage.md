# Finding coverage and observation semantics

Phase 3N adds a conservative, read-only coverage projection for one tenant-safe
finding occurrence. The flow is:

`source occurrence → authorized assessment/endpoint → bounded endpoint history → scanner execution metadata → coverage observation`.

## Implemented

`CoverageStatus` is `covered`, `not_covered`, or `indeterminate`. Observation
status is `observed`, `not_observed`, `not_evaluated`, or `unknown`.
An observed matching occurrence is always factual. `not_observed` is emitted
only when an explicitly declared strong-coverage scanner completed successfully
and did not return the matching candidate. The initial strong contract is the
independent `windows.firewall` adapter at resource granularity.

Skipped/incompatible/not-selected or incomplete delivery is `NOT_EVALUATED`;
failed, legacy-without-execution-metadata, and undeclared scanner coverage are
`UNKNOWN`. No absence is inferred from those states.

Coverage history is bounded, endpoint- and organization-scoped, ordered
chronologically, and includes the requested source occurrence even when it is
outside the recent bound. It reports whether the bound is complete and exposes
only safe observation metadata.

## Lifecycle foundation

The projection reports `lifecycle_eligibility` only. It does not mark findings
resolved, reopened, current, or historically open. No deduplication, state
machine, or lifecycle persistence is introduced.

## API

`GET /api/v1/organizations/{organization_id}/assessments/{assessment_id}/findings/{occurrence_id}/coverage`
requires the existing human session, organization context, and assessment-read
authorization. Cross-tenant and cross-endpoint lookups are denied by the
existing detail/repository boundaries.

## Partial / deferred

Legacy `scan_all()` results without scanner execution metadata remain unknown.
Rule-level guarantees, broader scanner contracts, durable coverage snapshots,
search, scoring, and lifecycle transitions are deferred.
