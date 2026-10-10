# Compliance evidence semantics

Evidence is derived from tenant-scoped `RemoteAssessment` results, normalized
findings, scanner execution results, and execution evidence. No legacy global
vulnerability table is used as compliance truth. Evidence older than the
configured 24-hour window is `UNKNOWN`; running, missing, failed, and weakly
covered scanner observations are also `UNKNOWN` unless a matching finding was
already observed. Revoked endpoints are excluded from active-fleet posture.
