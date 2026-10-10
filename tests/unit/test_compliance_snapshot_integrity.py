from dataclasses import replace
from datetime import datetime, timezone
from backend.domain.compliance import ComplianceStatus
from backend.domain.compliance_snapshot import *

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

def snapshot():
    return ComplianceSnapshot(ComplianceSnapshotId.new(), "org", "framework", "1", NOW, ComplianceSnapshotStatus.COMPLETE, True, 1, 1, 1, 1, 0, 0, 0, endpoints=(ComplianceEndpointSnapshot("endpoint", "host", "Windows", "active", 1),), controls=(ComplianceControlSnapshot("endpoint", "C-1", "Control", "full", ComplianceStatus.COMPLIANT, "observed", NOW),))

def test_snapshot_digest_is_deterministic_and_detects_tampering():
    value = snapshot_with_digest(snapshot())
    assert verify_snapshot_integrity(value) is ComplianceSnapshotIntegrityStatus.VALID
    tampered = replace(value, controls=(replace(value.controls[0], status=ComplianceStatus.NON_COMPLIANT),))
    assert verify_snapshot_integrity(tampered) is ComplianceSnapshotIntegrityStatus.INVALID

def test_legacy_snapshot_without_digest_is_unavailable_not_invalid():
    assert verify_snapshot_integrity(snapshot()) is ComplianceSnapshotIntegrityStatus.UNAVAILABLE
