# Tenant compliance foundation

```text
Tenant context → ComplianceFrameworkRegistry → ComplianceControlEvaluator
→ current assessment evidence → endpoint evaluations → posture counts
```

Raven-X exposes the internal, versioned `ravenx.windows.baseline` framework.
It reports observed technical control posture, not certification or legal
compliance. Definitions are immutable code-owned values; no organization
policy DSL or user-authored rules are evaluated.

The current source is the latest qualifying endpoint assessment. Observed
matching findings are non-compliant. Absence becomes compliant only for the
full-capability firewall control with complete recent execution evidence.
UAC, SMBv1, and BitLocker controls are detection-only: absence remains unknown.
Posture reports endpoint-control counts and preserves unknown values; it does
not produce a compliance score.
