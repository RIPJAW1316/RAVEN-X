# Assessment scheduling security

* **Mitigated:** organization context and RBAC guard schedule CRUD; endpoint
  ownership is checked on create/update and again before dispatch; revoked
  endpoints and suspended organizations are blocked; target and batch limits
  bound fan-out; no schedule contains commands, PowerShell, remediation or AI.
* **Partial:** a unique `(schedule_id, scheduled_for)` run marker and
  `SKIP_IF_ACTIVE` policy reduce duplicate/overlapping execution. Separate
  processes are not coordinated by a leader election mechanism.
* **Deferred:** distributed scheduler coordination, durable queue-level
  scheduling guarantees, dynamic fleet targeting, and operational rate limits.

Schedule names and recurrence are validated, IANA timezones are used, and
missed runs coalesce to avoid restart amplification. Audit events contain
schedule identifiers and bounded metadata only; credentials and tokens are
not part of schedule payloads.
