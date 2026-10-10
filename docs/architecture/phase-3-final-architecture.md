# Phase 3 final architecture

Phase 3 freezes Raven-X as a modular control plane: human authentication and
organization-scoped RBAC protect fleet, endpoint, assessment, scheduling,
compliance, and reporting APIs; enrolled Windows agents use authenticated
outbound HTTPS for work and results; SQLAlchemy persists tenancy, work,
assessments, audit, schedules, and compliance snapshots. Personal Tkinter
scanning remains separate. Human, agent, and system principals are distinct.
Generic command execution/remediation is explicitly outside Phase 3.

Phase 3 is now feature-frozen. Further work is operational enhancement or the
separately authorized Phase 4 remediation boundary: Finding → proposal →
validation → authorization/approval → structured action → agent execution →
verification → audit. AI must never supply arbitrary shell commands.
