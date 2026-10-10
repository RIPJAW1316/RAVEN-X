# Scanner adapter hardening security

## Mitigated

The enterprise adapter distinguishes registry/API failure, command failure,
parse failure, and partial execution from secure empty results. Evidence is
bounded and contains no raw PowerShell, command output, credentials, or traces.
Stable rule/resource identity is added as metadata without changing the
personal-mode scanner.

## Partial

The underlying legacy UAC/SMB/BitLocker methods may still swallow failures or
expose limited enumeration semantics. Instrumentation improves the adapter
boundary but cannot prove facts the legacy implementation does not provide.
Authenticated agents can still fabricate result metadata.

## Deferred

Broader scanner contracts, complete BitLocker volume discovery, signed/device
attestation, durable lifecycle state, and automatic downstream resolution remain
deferred. Treating exception-as-empty as secure remains prohibited.
