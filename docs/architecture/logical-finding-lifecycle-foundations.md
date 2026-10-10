# Logical finding lifecycle foundations

Phase 3N deliberately does not implement a finding lifecycle. Coverage is a
prerequisite signal only: an occurrence can be observed, strongly covered and
absent (`not_observed`), not evaluated, or unknown. A lifecycle consumer may
consider a finding eligible for future resolution only when bounded history
contains strong successful absence; otherwise eligibility is insufficient.

No status such as resolved, reopened, current, or open is stored or returned.
There is no automatic deduplication and no implicit transition based on time.
Future lifecycle work must retain tenant/endpoint authorization and treat
unknown or incomplete history as uncertainty.

Currently only the declared `windows.firewall` resource contract can make a
source finding lifecycle-eligible for future reasoning. UAC, BitLocker, and SMB
now expose more accurate execution outcomes, but remain insufficient-data/unknown
for absence claims because their contracts do not yet prove the required scope.
This is eligibility evidence only, not a finding lifecycle state.
