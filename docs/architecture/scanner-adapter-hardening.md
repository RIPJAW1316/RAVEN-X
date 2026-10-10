# Legacy scanner adapter hardening

Phase 3Q preserves the personal-mode `VulnerabilityScanner` while making the
enterprise adapter boundary explicit about inspection failure.

## UAC

The adapter instruments the existing two registry reads used by `check_uac`.
Both reads succeeding produce rule `uac.configuration` with complete evidence;
secure configuration produces no finding and insecure configuration produces a
finding. Any read failure produces `REGISTRY_READ_FAILED` and partial evidence,
never a secure empty result.

## SMB

The existing adapter checks only SMBv1. A structured read result produces rule
`smb.smb1_enabled` with complete evidence. A missing/failed structured result is
`COMMAND_FAILED`; no additional SMB checks were introduced.

## BitLocker

The existing adapter checks only the `C:` OS volume. A parsed result produces
rule `bitlocker.os_volume` and resource `c:` as evaluated. Missing or malformed
output produces `COMMAND_FAILED` or `OUTPUT_PARSE_FAILED`. This does not claim
all volumes were enumerated.

## Compatibility

Fake/legacy callers remain supported. When an object does not expose the
instrumentable read boundary, the adapter returns successful findings with
unknown evidence rather than manufacturing completeness. No raw command,
PowerShell output, or exception trace is persisted.
