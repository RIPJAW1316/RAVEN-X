# Local capabilities (Phase 1F)

## Implemented

The selected local assessment path now obtains capabilities through
`LocalTargetCapabilityProvider`:

```text
Local Windows target
        ↓
Read-only command/module availability probes
        ↓
TargetCapabilities + CapabilityObservation[]
        ↓
Scanner compatibility
        ↓
Scanner execution
```

Only capabilities required by the current local scanner catalog are discovered:

| Capability | Read-only probe | Provenance source |
| --- | --- | --- |
| `windows.firewall.read` | `netsh` availability | `command:netsh` |
| `windows.registry.read` | `winreg` module availability | `module:winreg` |
| `windows.powershell` | `powershell.exe` availability | `command:powershell.exe` |

Each `CapabilityObservation` records supported, unsupported, or unknown state,
its source, and a reason. A failed availability lookup is `UNKNOWN`, never
treated as supported. Unknown required capabilities produce an explicit
compatibility result and prevent execution.

The provider only identifies the target platform and checks command/module
availability. It does not launch PowerShell, query or write registry values,
inspect firewall state, change services, or invoke remediation.

The scanner catalog is now:

| Scanner ID | Implementation status | Required capabilities | Independent execution | Legacy method |
| --- | --- | --- | --- | --- |
| `windows.firewall` | `AVAILABLE` | `windows.firewall.read` | Yes | `check_firewall` |
| `windows.uac` | `AVAILABLE` | `windows.registry.read` | Yes | `check_uac` |
| `windows.bitlocker` | `AVAILABLE` | `windows.powershell` | Yes | `check_bitlocker_status` |
| `windows.smb` | `AVAILABLE` | `windows.powershell` | Yes | `check_smb_protocol` |

Each promoted check is independently callable, has no UI, persistence, or AI
dependency, does not invoke remediation, and is invoked only through
`LegacyMethodScannerAdapter`.
The existing Phase 1B normalizer converts its legacy finding dictionaries.

## Partial

`StaticTargetCapabilityProvider` remains available only as an explicit,
injectable controlled-environment/test fallback. It is never selected when
discovery fails in the application path.

`AssessmentResult.scanner_results` remains in memory. No scanner execution or
capability observations are persisted because the existing schema has no
dedicated runtime metadata model.

## Legacy

No selection still takes the compatibility path:

```text
LocalAssessmentRunner
        ↓
VulnerabilityScanner.scan_all()
```

The original Windows collection logic remains in `scanner.py` and was not
copied or reorganized.

## Final local runtime architecture

```text
FastAPI
    ↓
RunLocalAssessment
    ↓
AssessmentOptions
    ├── no scanner IDs
    │      ↓
    │   Legacy scan_all()
    │
    └── scanner IDs
           ↓
       Capability Provider
           ↓
       Scanner Registry
           ↓
       Compatibility
           ↓
       Scanner Adapters
           ↓
       ScannerExecutionResult[]
           ↓
       AssessmentResult
           ↓
       Repository
           ↓
       SQLAlchemy
```

## Deferred

Endpoint-advertised capabilities, identity, enrollment, networking, remote
dispatch, scheduling, scanner-result persistence, and remediation orchestration
remain outside the local runtime foundation.
