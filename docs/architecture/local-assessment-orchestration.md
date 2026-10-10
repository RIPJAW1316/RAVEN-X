# Local assessment orchestration (Phase 1E)

## Implemented

RAVEN-X now supports an additive local scanner-selection path.

```text
Requested scanner IDs
        ↓
ScannerRegistry
        ↓
Compatibility evaluation
        ↓
Scanner execution result per requested ID
        ↓
AssessmentResult
```

`AssessmentOptions.scanner_ids` defines the behavior:

- `None`: use the unchanged legacy `VulnerabilityScanner.scan_all()` path.
- `()`: complete successfully without executing scanners.
- one or more IDs: resolve each ID from the local registry in request order.

Each selected scanner produces a `ScannerExecutionResult`, attached to the
in-memory `AssessmentResult.scanner_results`. Findings from successful scanner
results are aggregated into `AssessmentResult.findings`. Scanner result data is
not persisted because the existing Scan/Vulnerability schema has no suitable
field for it.

Compatibility is evaluated before execution. An incompatible scanner produces
`INCOMPATIBLE` with its reason and is never executed. Unknown IDs produce
`SKIPPED` with `scanner is not registered`. UAC, BitLocker, and SMB are now
narrow executable adapters; each calls its existing legacy check directly.

An individual scanner failure is preserved as `FAILED` at scanner level while
the overall assessment is `COMPLETED`, because orchestration finished and other
requested scanners may still have run. Only an orchestration-level failure
(such as capability resolution failure) makes the assessment `FAILED`.

The `/api/v1/scan/start` request accepts an optional additive `scanner_ids`
array for the default full local scan. Existing requests omit it and retain the
previous behavior. Combining `scanner_ids` with quick, targeted, category, or
non-deep options returns HTTP 422 rather than guessing semantics.

## Partial

The local capability provider performs conservative, read-only availability
discovery for the modeled command/module dependencies. Discovery failures are
retained as unknown capabilities and prevent scanner execution.

## Legacy

With no scanner selection, `LocalAssessmentRunner` continues to call
`VulnerabilityScanner.scan_all()` unchanged. Personal-mode Tkinter continues
to use the same scanner directly.

## Deferred

No scanner-result database schema, endpoint agent, remote dispatch, network
capability negotiation, scheduling, queue, tenant model, or remediation path
has been introduced.
