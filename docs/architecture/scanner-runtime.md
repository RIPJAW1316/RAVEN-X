# Local scanner runtime (Phase 1D)

## Implemented

Phase 1D introduces a local, in-memory scanner runtime alongside the existing
assessment flow:

```text
ScannerRegistry
      ↓
ScannerManifest
      ↓
TargetCapabilities
      ↓
Compatibility evaluation
      ↓
Legacy scanner adapter
      ↓
Phase 1B normalizer
      ↓
ScannerExecutionResult
```

The pure scanner contracts are under `backend/domain/scanner` and define:

- stable scanner IDs and manifests;
- technical capability requirements and target capability sets;
- technical compatibility results;
- implementation state (`AVAILABLE`, `LEGACY_ONLY`, `EXPERIMENTAL`,
  `UNAVAILABLE`); and
- execution outcomes distinct from assessment outcomes.

The initial manifest catalog is intentionally small:

| Scanner ID | Status | Required capability | Execution |
| --- | --- | --- | --- |
| `windows.firewall` | `AVAILABLE` | `windows.firewall.read` | Narrow legacy adapter |
| `windows.uac` | `AVAILABLE` | `windows.registry.read` | Narrow legacy adapter |
| `windows.bitlocker` | `AVAILABLE` | `windows.powershell` | Narrow legacy adapter |
| `windows.smb` | `AVAILABLE` | `windows.powershell` | Narrow legacy adapter |

The firewall adapter calls the existing `VulnerabilityScanner.check_firewall`
method. It neither copies Windows collection logic nor changes firewall state.
Its legacy dictionaries pass through the existing normalizer before appearing
in a `ScannerExecutionResult`.

## Partial

The registry currently describes and filters local scanner runtimes only. It is
not yet used to select checks for `LocalAssessmentRunner`; the working full-scan
path continues to call `VulnerabilityScanner.scan_all()` unchanged.

`EnhancedScanner` has its own partial registry from Phase 1A. It is not merged
with this catalog and does not become the source of truth.

## Legacy

The runtime adapters call the corresponding existing `VulnerabilityScanner`
methods. Their collection logic remains in `scanner.py`; only the adapter and
normalization boundary is new.

## Deferred

No endpoint capability advertisement, agent protocol, endpoint registry,
network dispatch, scheduling, persistence for manifests, remote remediation,
or distributed assessment has been implemented.
