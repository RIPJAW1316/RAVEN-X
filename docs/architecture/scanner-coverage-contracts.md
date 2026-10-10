# Scanner coverage contracts

Phase 3O makes absence guarantees explicit, versioned, and explainable. A
`ScannerCoverageContract` is code/domain metadata, not hardware or cryptographic
attestation. A derived `CoverageAttestation` records the contract, execution
status, scope, and reason used for a read-only coverage observation.

## Coverage matrix

| Scanner | Granularity | Strong absence inference | Contracted scope |
| --- | --- | --- | --- |
| `windows.firewall` | RESOURCE | YES, only with COMPLETE version-compatible execution evidence | `firewall.profile` over `domain`, `private`, and `public`; all profiles enumerated/evaluated |
| `windows.uac` | UNKNOWN | NO | `uac.configuration` evidence is explicit, but contract promotion remains deferred pending full secure/default semantics |
| `windows.bitlocker` | UNKNOWN | NO | `bitlocker.os_volume` is C: evidence only; global volume enumeration is not proven |
| `windows.smb` | UNKNOWN | NO | `smb.smb1_enabled` evidence is explicit, but the contract remains conservative |

The four rows correspond to existing local adapters. No scanner behavior was
rewritten and no future/non-executable scanner was added.

## Contract rules

Contracts have an independent positive `contract_version`, explicit granularity,
optional rule/resource scopes, and optional scanner-version compatibility. Strong
contracts require a documented guarantee and cannot be registered with empty or
contradictory declarations. Unknown scanners default to a conservative contract
that denies absence inference. Duplicate IDs are rejected.

`NOT_OBSERVED` therefore requires a matching fingerprint, successful complete
execution evidence, a compatible contract/version, matching completed rule and
resource claims, and no partial-execution signal.
Observed findings remain factual even when the contract is weak. Skipped,
incompatible, failed, malformed, legacy, or version-mismatched results never
produce strong absence.

## Limitations

Legacy historical results may not contain scanner version or structured rule /
resource metadata. Those results remain conservative unless their persisted
identity and execution evidence satisfy a declared contract. Coverage
attestations are computed read-model data and are not persisted.
