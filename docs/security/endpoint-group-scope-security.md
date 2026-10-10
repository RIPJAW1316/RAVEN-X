# Endpoint group and saved scope security

* **MITIGATED:** all human operations require organization context and
  dedicated RBAC actions. Group membership validates endpoint ownership before
  persistence and rejects revoked/new cross-tenant endpoints atomically.
  Queries never contain organization IDs; scope resolution applies the owning
  tenant through the existing fleet-query service.
* **MITIGATED:** no nested groups, Boolean scope DSL, regex, arbitrary SQL,
  dynamic schedule targeting, commands, remediation, or AI. DTOs exclude raw
  endpoint metadata and credentials. Presence/endpoint ownership mismatches are
  handled conservatively.
* **PARTIAL:** group and scope lists are bounded by service/page limits, while
  very large fleets still use ordinary offset pagination.
* **DEFERRED:** dynamic scheduler integration, scope composition, materialized
  snapshots, endpoint groups beyond explicit membership, and distributed
  synchronization.
