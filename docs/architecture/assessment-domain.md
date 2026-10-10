# Assessment-domain boundary (Phase 1B)

## Implemented

Phase 1B adds pure Python assessment contracts under `backend/domain`:

- `AssessmentTarget`
- `AssessmentStatus`
- `AssessmentResult`
- `FindingSeverity`
- `Finding`
- `Evidence`

The domain has no dependency on FastAPI, SQLAlchemy, Tkinter, Windows APIs,
subprocess, networking, AI clients, or remediation execution.

The local adapter lives in `backend/application/assessment`:

```text
VulnerabilityScanner.scan_all()
        ↓
LocalAssessmentRunner
        ↓
legacy finding normalizer
        ↓
AssessmentResult / Finding / Evidence
```

`LocalAssessmentRunner` is deliberately thin: it invokes the existing legacy
scanner and returns data. It does not persist results, call AI, render a UI,
execute remediation, or make network requests.

## Legacy compatibility

The normalized `Finding` preserves the existing finding fields:

```text
severity, category, title, details, component, remediation, powershell_command
```

`powershell_command` is retained only in `legacy_metadata`; it is not an
executable domain behavior. Extra legacy fields remain in finding metadata.
Malformed non-mapping findings become explicit normalization issues rather than
silently disappearing.

## Partial

`EnhancedScanner` remains a separate, incomplete backend scanner. The new
normalizer can accept findings of the same dictionary shape, but it does not
merge or expand that scanner.

The existing FastAPI scan route still uses its current persistence flow. Wiring
the runner into that route would require an explicit domain-to-persistence
mapping and is deferred to avoid changing API behavior in Phase 1B.

## Deferred

No endpoint agents, enrollment, organizations, tenancy, RBAC, agent transport,
distributed assessment, scheduling, central finding persistence, or enterprise
remediation has been implemented.
