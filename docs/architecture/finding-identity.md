# Finding identity

Raven-X distinguishes a concrete `FindingOccurrenceId` from a
`FindingFingerprint`.

* An occurrence is one item observed in one assessment. For legacy embedded
  results it is derived deterministically from assessment ID, result index,
  and the existing finding ID; new protocol results carry this value in the
  result JSON.
* A fingerprint is a versioned, endpoint-scoped **candidate** logical key.
  Version 1 uses explicit `endpoint_id`, `scanner_id`, stable rule/check/CVE
  ID, and resource key. Machine identifiers are case-normalized and resource
  separators are normalized. Severity, title, description, remediation, and
  timestamps are never identity inputs.

Fingerprint equality is candidate matching, not proof of equivalence. Missing
stable inputs produce no fingerprint. No deduplication or vulnerability
lifecycle is performed in Phase 3L.
