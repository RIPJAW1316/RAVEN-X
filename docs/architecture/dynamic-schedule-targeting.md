# Dynamic schedule targeting

```text
AssessmentSchedule target reference → execution-time resolution
→ immutable ScheduleRun target snapshot → RemoteAssessment → AgentWorkItem
```

Schedules can reference explicit endpoints, one static endpoint group, or one
saved fleet scope. A schedule never embeds an ad-hoc FleetQuery. Group/scope
ownership and active status are validated when attached and again when a run is
resolved.

The runner persists resolved endpoint IDs before creating assessments. Restart
recovery reuses that snapshot rather than re-evaluating a changed group or
scope. Endpoint lifecycle is still rechecked just before dispatch. Empty,
revoked, invalid, and over-limit targets produce explicit skipped reasons;
targets are never silently truncated.

Dynamic schedules still run only through `AssessmentScheduleRunner.run_once()`.
They do not target remediation, commands, compliance, or AI workflows.
