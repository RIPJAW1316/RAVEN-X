from sqlalchemy import select, delete
from datetime import timezone
from ...core.database.models import ComplianceSnapshotRecord,ComplianceSnapshotEndpointRecord,ComplianceSnapshotControlRecord
from ...domain.compliance_snapshot import *
from ...domain.compliance import ComplianceStatus
def _s(v): return v.astimezone(timezone.utc).replace(tzinfo=None)
def _l(v): return v.replace(tzinfo=timezone.utc)
class SQLAlchemyComplianceSnapshotRepository:
    def __init__(self,db): self.db=db
    def add(self,snapshot):
        with self.db.get_db() as session:
            session.add(ComplianceSnapshotRecord(snapshot_id=str(snapshot.snapshot_id),organization_id=str(snapshot.organization_id),framework_id=snapshot.framework_id,framework_version=snapshot.framework_version,created_at=_s(snapshot.created_at),status=snapshot.status.value,evaluation_complete=snapshot.evaluation_complete,endpoints_examined=snapshot.endpoints_examined,endpoint_count=snapshot.endpoint_count,control_evaluation_count=snapshot.control_evaluation_count,compliant_count=snapshot.compliant_count,non_compliant_count=snapshot.non_compliant_count,unknown_count=snapshot.unknown_count,not_applicable_count=snapshot.not_applicable_count,source_scope_type=snapshot.source_scope_type,source_scope_reference_id=snapshot.source_scope_reference_id,snapshot_digest_sha256=snapshot.snapshot_digest_sha256))
            for endpoint in snapshot.endpoints: session.add(ComplianceSnapshotEndpointRecord(snapshot_id=str(snapshot.snapshot_id),endpoint_id=endpoint.endpoint_id,hostname=endpoint.hostname,platform=endpoint.platform,lifecycle_status=endpoint.lifecycle_status,evaluation_count=endpoint.evaluation_count))
            for control in snapshot.controls: session.add(ComplianceSnapshotControlRecord(snapshot_id=str(snapshot.snapshot_id),endpoint_id=control.endpoint_id,control_id=control.control_id,control_title=control.control_title,capability=control.capability,status=control.status.value,reason_code=control.reason_code,evaluated_at=_s(control.evaluated_at),source_assessment_id=control.source_assessment_id,evidence_age_seconds=control.evidence_age_seconds,coverage_status=control.coverage_status))
    def _load(self,r,session):
        eps=tuple(ComplianceEndpointSnapshot(x.endpoint_id,x.hostname,x.platform,x.lifecycle_status,x.evaluation_count) for x in session.execute(select(ComplianceSnapshotEndpointRecord).where(ComplianceSnapshotEndpointRecord.snapshot_id==r.snapshot_id)).scalars())
        controls=tuple(ComplianceControlSnapshot(x.endpoint_id,x.control_id,x.control_title,x.capability,ComplianceStatus(x.status),x.reason_code,_l(x.evaluated_at),x.source_assessment_id,x.evidence_age_seconds,x.coverage_status) for x in session.execute(select(ComplianceSnapshotControlRecord).where(ComplianceSnapshotControlRecord.snapshot_id==r.snapshot_id)).scalars())
        return ComplianceSnapshot(ComplianceSnapshotId(r.snapshot_id),r.organization_id,r.framework_id,r.framework_version,_l(r.created_at),ComplianceSnapshotStatus(r.status),r.evaluation_complete,r.endpoints_examined,r.endpoint_count,r.control_evaluation_count,r.compliant_count,r.non_compliant_count,r.unknown_count,r.not_applicable_count,r.source_scope_type,r.source_scope_reference_id,eps,controls,r.snapshot_digest_sha256)
    def get_for_organization(self,snapshot_id,organization_id):
        with self.db.get_db() as s:
            r=s.get(ComplianceSnapshotRecord,str(snapshot_id)); return self._load(r,s) if r and str(r.organization_id)==str(organization_id) else None
    def list_for_organization(self,organization_id,framework_id=None,limit=50,offset=0):
        with self.db.get_db() as s:
            q=select(ComplianceSnapshotRecord).where(ComplianceSnapshotRecord.organization_id==str(organization_id));
            if framework_id is not None:q=q.where(ComplianceSnapshotRecord.framework_id==str(framework_id))
            rows=s.execute(q.order_by(ComplianceSnapshotRecord.created_at.desc(),ComplianceSnapshotRecord.snapshot_id.desc()).offset(offset).limit(limit)).scalars(); return tuple(self._load(r,s) for r in rows)
    def get_previous(self,snapshot):
        values=self.list_for_organization(snapshot.organization_id,snapshot.framework_id,limit=2); return next((x for x in values if str(x.snapshot_id)!=str(snapshot.snapshot_id)),None)
    def delete_for_retention(self, organization_id, snapshot_id):
        with self.db.get_db() as session:
            row = session.get(ComplianceSnapshotRecord, str(snapshot_id))
            if row is None or str(row.organization_id) != str(organization_id):
                return False
            session.execute(delete(ComplianceSnapshotControlRecord).where(ComplianceSnapshotControlRecord.snapshot_id == str(snapshot_id)))
            session.execute(delete(ComplianceSnapshotEndpointRecord).where(ComplianceSnapshotEndpointRecord.snapshot_id == str(snapshot_id)))
            session.delete(row)
            return True
    def list_organizations(self):
        with self.db.get_db() as session:
            return tuple(x[0] for x in session.execute(select(ComplianceSnapshotRecord.organization_id).distinct()).all())
