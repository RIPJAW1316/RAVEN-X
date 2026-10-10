from datetime import datetime, timedelta, timezone
from backend.domain.compliance import ComplianceStatus
from backend.domain.compliance_snapshot import *
from backend.infrastructure.persistence.in_memory_compliance_snapshot_repository import InMemoryComplianceSnapshotRepository
from backend.application.compliance.retention import ComplianceSnapshotRetentionRunner

NOW = datetime(2026, 1, 31, tzinfo=timezone.utc)

def make_snapshot(org, when, version="1", sid=None, endpoint="e1", status=ComplianceStatus.COMPLIANT):
    return ComplianceSnapshot(sid or ComplianceSnapshotId.new(), org, "framework", version, when, ComplianceSnapshotStatus.COMPLETE, True, 1, 1, 1, 1 if status is ComplianceStatus.COMPLIANT else 0, 1 if status is ComplianceStatus.NON_COMPLIANT else 0, 1 if status is ComplianceStatus.UNKNOWN else 0, 0, endpoints=(ComplianceEndpointSnapshot(endpoint, "host", "Windows", "active", 1),), controls=(ComplianceControlSnapshot(endpoint, "C-1", "Control", "full", status, "observed", when),))

def test_retention_dry_run_protects_minimum_and_is_tenant_scoped():
    repo = InMemoryComplianceSnapshotRepository()
    old = make_snapshot("org-a", NOW - timedelta(days=100)); newest = make_snapshot("org-a", NOW); other = make_snapshot("org-b", NOW - timedelta(days=100))
    for value in (old, newest, other): repo.add(value)
    runner = ComplianceSnapshotRetentionRunner(repo, ComplianceSnapshotRetentionPolicy(max_age_days=30, max_snapshots_per_framework=10, minimum_snapshots_to_keep=1), now_fn=lambda: NOW)
    result = runner.run_once(dry_run=True)
    assert [x.snapshot_id for x in result["candidates"]] == [str(old.snapshot_id)]
    assert repo.get_for_organization(old.snapshot_id, "org-a") is not None
    runner.run_once(organization_id="org-a")
    assert repo.get_for_organization(old.snapshot_id, "org-a") is None
    assert repo.get_for_organization(other.snapshot_id, "org-b") is not None

def test_retention_count_and_framework_versions_are_independent():
    repo = InMemoryComplianceSnapshotRepository()
    values = [make_snapshot("org", NOW - timedelta(days=i), version="1") for i in (3, 2, 1)] + [make_snapshot("org", NOW - timedelta(days=20), version="2")]
    for value in values: repo.add(value)
    runner = ComplianceSnapshotRetentionRunner(repo, ComplianceSnapshotRetentionPolicy(max_age_days=999, max_snapshots_per_framework=2, minimum_snapshots_to_keep=1), now_fn=lambda: NOW)
    candidates = runner.evaluate_retention("org")
    assert len(candidates) == 1
    assert candidates[0].framework_version == "1"
    runner.run_once(organization_id="org")
    assert len(repo.list_for_organization("org", "framework", limit=10)) == 3

def test_delete_is_idempotent_and_aggregate_removed():
    repo = InMemoryComplianceSnapshotRepository(); value = make_snapshot("org", NOW); repo.add(value)
    assert repo.delete_for_retention("org", value.snapshot_id) is True
    assert repo.delete_for_retention("org", value.snapshot_id) is False
