# Fleet query security

* **MITIGATED:** human authentication, active organization context, and
  `endpoint.read` are required. SQL and in-memory queries scope by
  `organization_id` before filtering. Counts and pages are tenant-scoped.
* **MITIGATED:** limits bound page size, offsets, search length, and filter
  values; sort fields are an explicit enum; regex, SQL, wildcard, and arbitrary
  query expressions are not accepted. Fleet DTOs contain no credentials or raw
  endpoint metadata.
* **PARTIAL:** offset pagination and simple substring search can become costly
  for very large fleets; no cache or dedicated search index is used.
* **DEFERRED:** endpoint groups, saved filters, dynamic schedule targeting,
  full-text search, exports, and distributed query infrastructure.

Presence rows with a mismatched organization are treated as unknown rather than
trusted, and role/membership revocation takes effect on the next request.
