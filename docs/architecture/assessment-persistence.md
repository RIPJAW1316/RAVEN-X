# Assessment persistence boundary (Phase 1C)

## Implemented

The default full local scan API workflow now follows this path:

```text
FastAPI /api/v1/scan/start
        ↓
RunLocalAssessment
        ↓
LocalAssessmentRunner
        ↓
AssessmentResult
        ↓
AssessmentRepository port
        ↓
SQLAlchemyAssessmentRepository
        ↓
existing Scan / Vulnerability tables
```

The domain remains persistence-independent. Mapping is explicit in
`backend/infrastructure/persistence/mappers.py`.

- `AssessmentTarget` maps to the existing `Scan.system_info` JSON snapshot.
- Completed/failed domain results update the current `Scan` lifecycle fields.
- Domain findings map to existing `Vulnerability` rows.
- Legacy PowerShell text is persisted in the existing text field only; no
  executable ORM or domain behavior has been added.
- Risk scoring preserves the current severity weights: critical 10, high 7,
  medium 4, low 1.

## Partial

The default `full` request with no target categories and `deep_scan=true` uses
the new legacy-scanner domain path. `quick`, `targeted`, category-filtered, and
`deep_scan=false` requests retain the existing `EnhancedScanner` route because
the legacy scanner does not provide equivalent controls.

The current request and response schema is unchanged. The local domain path
does not automatically invoke AI learning or remediation; AI analysis remains
a separate route.

The current schema has no general evidence/metadata column. Finding detail and
legacy PowerShell text are persisted where supported; arbitrary normalized
metadata remains in the in-memory domain result. Normalization issue count and
reasons are saved in the existing `Scan.system_info` JSON field.

## Legacy

`scanner.py` remains unchanged and is still the source of local Windows checks.
Personal-mode Tkinter continues to call it directly.

## Deferred

No database migration, endpoint agent, tenant, organization, RBAC, enrollment,
transport, scheduling, centralized fleet findings, or enterprise remediation is
part of this implementation.
