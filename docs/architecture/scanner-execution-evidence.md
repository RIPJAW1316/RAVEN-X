# Scanner execution evidence

Phase 3P separates adapter return status from proof of what was evaluated:

`Scanner Adapter → ScannerExecutionEvidence → ScannerCoverageContract → CoverageAttestation → FindingCoverageObservation`.

`ScannerExecutionStatus.SUCCESS` only means the adapter returned normally.
`ScannerExecutionEvidence` records bounded completeness, attempted/completed
rules, resource enumeration, per-resource outcomes, normalization state, and
scanner version. Rule completion must be a subset of attempted rules; resource
results must refer to discovered resources. Complete evidence cannot carry a
partial reason.

The firewall adapter reports all three deterministic profiles (`domain`,
`private`, `public`) and the declared `firewall.profile` rule. UAC, SMB, and
BitLocker legacy methods report unknown evidence because their current methods
do not expose enough failure/enumeration detail to prove complete coverage.
The hardened adapter now distinguishes UAC registry-read failure, SMB command
failure, and BitLocker parse failure while retaining conservative classifications.
No raw command output, PowerShell, credentials, or secrets are part of execution
evidence.

Old protocol results without evidence continue to deserialize; their absence
observations remain `UNKNOWN`. Evidence is additive and does not require a
protocol major-version change.
