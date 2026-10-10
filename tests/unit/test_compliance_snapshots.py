from datetime import datetime, timezone
from backend.domain.compliance_snapshot import *
from backend.domain.compliance import ComplianceStatus
from backend.infrastructure.persistence.in_memory_compliance_snapshot_repository import InMemoryComplianceSnapshotRepository

NOW=datetime(2026,1,1,tzinfo=timezone.utc)
def snap(org="org"):
    return ComplianceSnapshot(ComplianceSnapshotId.new(),org,"ravenx.windows.baseline","1",NOW,ComplianceSnapshotStatus.COMPLETE,True,1,1,1,1,0,0,0,endpoints=(ComplianceEndpointSnapshot("e","host","Windows","active",1),),controls=(ComplianceControlSnapshot("e","RX-WIN-FW-001","Firewall","full",ComplianceStatus.COMPLIANT,"evidence_satisfied",NOW),))
def test_snapshot_is_immutable_and_tenant_scoped():
    repo=InMemoryComplianceSnapshotRepository(); value=snap(); repo.add(value)
    assert repo.get_for_organization(value.snapshot_id,"other") is None
    loaded=repo.get_for_organization(value.snapshot_id,"org"); assert loaded.to_dict()==value.to_dict()
def test_snapshot_listing_is_deterministic_and_previous_is_available():
    repo=InMemoryComplianceSnapshotRepository(); first=snap(); repo.add(first); second=ComplianceSnapshot(ComplianceSnapshotId.new(),"org","ravenx.windows.baseline","1",NOW.replace(hour=1),ComplianceSnapshotStatus.COMPLETE,True,1,1,1,0,1,0,0,endpoints=first.endpoints,controls=first.controls); repo.add(second)
    assert repo.list_for_organization("org")[0].snapshot_id==second.snapshot_id
    assert repo.get_previous(second).snapshot_id==first.snapshot_id
