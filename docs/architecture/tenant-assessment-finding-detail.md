# Tenant assessment and finding detail

Human detail access follows:

`OrganizationContext → tenant assessment → tenant endpoint → finding occurrence`.

The detail routes are:

* `GET /api/v1/organizations/{organization_id}/assessments/{assessment_id}/details`
* `GET /api/v1/organizations/{organization_id}/assessments/{assessment_id}/findings/{occurrence_id}`

Both require `assessment.read`. There is no global finding lookup. Results are
bounded, ordered by severity and occurrence ID, and expose scanner attribution,
candidate fingerprint data, and bounded evidence summaries only.
