import csv, io, json, hashlib
from collections import Counter
from datetime import datetime, timezone
from ...domain.compliance import ComplianceStatus
from ...domain.compliance_snapshot import *
from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType

class TenantComplianceSnapshotService:
    def __init__(self, compliance_service, endpoint_repository, snapshot_repository, authorizer, *, max_endpoints=100, max_export_rows=10000, audit_sink=None, metrics=None, logger=None, group_repository=None, scope_repository=None):
        self.compliance=compliance_service; self.endpoints=endpoint_repository; self.repo=snapshot_repository; self.authorizer=authorizer; self.max_endpoints=max_endpoints; self.max_export_rows=max_export_rows; self.audit=audit_sink; self.metrics=metrics; self.logger=logger; self.groups=group_repository; self.scopes=scope_repository
    def create(self, principal, context, framework_id, *, scope_type="organization", scope_reference_id=None):
        started = datetime.now(timezone.utc)
        try:
            return self._create(principal, context, framework_id, scope_type=scope_type, scope_reference_id=scope_reference_id)
        except Exception as exc:
            if self.metrics: self.metrics.increment("compliance_snapshots_failed_total")
            if self.logger: self.logger.exception("compliance.snapshot.failed")
            if self.audit:
                from ...domain.security import SecurityAuditEvent, SecurityAuditOutcome
                self.audit.append(SecurityAuditEvent(event_type="compliance.snapshot.failed", principal=principal, outcome=SecurityAuditOutcome.FAILED, organization_id=str(getattr(context, "organization_id", "")), metadata={"framework_id":str(framework_id),"scope_type":scope_type,"error_category":type(exc).__name__,"duration_ms":int((datetime.now(timezone.utc)-started).total_seconds()*1000)}))
            raise

    def _create(self, principal, context, framework_id, *, scope_type="organization", scope_reference_id=None):
        self._auth(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance")
        if scope_type=="organization": endpoints=tuple(x for x in self.endpoints.list_for_organization(context.organization_id) if x.status is not EndpointStatus.REVOKED)
        elif scope_type=="endpoint_group":
            self._auth(principal,context,AuthorizationAction.ENDPOINT_GROUP_READ,"endpoint_group",scope_reference_id); group=self.groups.get(scope_reference_id) if self.groups else None
            if group is None or group.organization_id!=context.organization_id or group.status.value!="active": raise KeyError("group not found")
            endpoints=tuple(x for i in self.groups.list_members(scope_reference_id,limit=self.max_endpoints+1) if (x:=self.endpoints.get_for_organization(i,context.organization_id)) is not None and x.status is not EndpointStatus.REVOKED)
        elif scope_type=="saved_fleet_scope":
            self._auth(principal,context,AuthorizationAction.FLEET_SCOPE_READ,"fleet_scope",scope_reference_id); scope=self.scopes.get(scope_reference_id) if self.scopes else None
            if scope is None or scope.organization_id!=context.organization_id or scope.status.value!="active": raise KeyError("scope not found")
            endpoints=tuple(self.endpoints.get_for_organization(x.endpoint_id,context.organization_id) for x in self.compliance.endpoints.query_for_organization(context.organization_id,scope.fleet_query).items)
            endpoints=tuple(x for x in endpoints if x is not None and x.status is not EndpointStatus.REVOKED)
        else: raise ValueError("unsupported snapshot scope")
        if len(endpoints)>self.max_endpoints: raise ValueError("snapshot endpoint bound exceeded")
        framework=self.compliance.framework(principal,context,framework_id); controls=[]; endpoint_rows=[]
        for endpoint in endpoints:
            evaluations=self.compliance.evaluate_endpoint(principal,context,endpoint.endpoint_id,framework_id); endpoint_rows.append(ComplianceEndpointSnapshot(str(endpoint.endpoint_id),endpoint.hostname,endpoint.platform.name,endpoint.status.value,len(evaluations)))
            controls.extend(ComplianceControlSnapshot(str(endpoint.endpoint_id),e.control_id,self.compliance.registry.control(e.control_id).title,e.capability.value,e.status,e.reason_code.value,e.evaluated_at,e.source_assessment_id,e.evidence_age_seconds,e.coverage_status) for e in evaluations)
        counts=Counter(x.status for x in controls); now=datetime.now(timezone.utc); snapshot=ComplianceSnapshot(ComplianceSnapshotId.new(),str(context.organization_id),framework.framework_id,framework.version,now,ComplianceSnapshotStatus.COMPLETE,True,len(endpoints),len(endpoints),len(controls),counts[ComplianceStatus.COMPLIANT],counts[ComplianceStatus.NON_COMPLIANT],counts[ComplianceStatus.UNKNOWN],counts[ComplianceStatus.NOT_APPLICABLE],scope_type,scope_reference_id,tuple(endpoint_rows),tuple(controls)); snapshot=snapshot_with_digest(snapshot); self.repo.add(snapshot)
        if self.metrics is not None:self.metrics.increment("compliance_snapshots_created_total"); self.metrics.increment("compliance_snapshot_rows_total",len(controls))
        if self.audit is not None:self.audit.append(__import__('backend.domain.security',fromlist=['SecurityAuditEvent']).SecurityAuditEvent(event_type="compliance.snapshot.create",principal=principal,outcome=__import__('backend.domain.security',fromlist=['SecurityAuditOutcome']).SecurityAuditOutcome.SUCCESS,organization_id=str(context.organization_id),metadata={"snapshot_id":str(snapshot.snapshot_id),"framework_id":framework.framework_id,"scope_type":scope_type,"endpoint_count":len(endpoints)}))
        return snapshot
    def list(self,principal,context,framework_id,limit=50,offset=0): self._auth(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); return self.repo.list_for_organization(context.organization_id,framework_id,min(200,int(limit)),max(0,int(offset)))
    def get(self,principal,context,snapshot_id,framework_id=None):
        self._auth(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); value=self.repo.get_for_organization(snapshot_id,context.organization_id)
        if value is None or (framework_id is not None and value.framework_id != str(framework_id)): raise KeyError("snapshot not found")
        return value
    def compare(self,principal,context,snapshot_id,previous_id=None):
        current=self.get(principal,context,snapshot_id); previous=self.repo.get_for_organization(previous_id,context.organization_id) if previous_id else self.repo.get_previous(current); compatible=bool(previous and previous.framework_version==current.framework_version and previous.framework_id==current.framework_id)
        if not previous:return ComplianceSnapshotDelta(None,str(current.snapshot_id),False,endpoint_count_delta=current.endpoint_count)
        old_ids={x.endpoint_id for x in previous.endpoints}; new_ids={x.endpoint_id for x in current.endpoints}
        control_deltas=[]
        if compatible:
            for control_id in sorted({x.control_id for x in previous.controls}|{x.control_id for x in current.controls}):
                def counts(snapshot):
                    rows=[x.status for x in snapshot.controls if x.control_id==control_id]
                    return tuple(rows.count(v) for v in (ComplianceStatus.COMPLIANT,ComplianceStatus.NON_COMPLIANT,ComplianceStatus.UNKNOWN,ComplianceStatus.NOT_APPLICABLE))
                a,b=counts(previous),counts(current)
                control_deltas.append({"control_id":control_id,"compliant_delta":b[0]-a[0],"non_compliant_delta":b[1]-a[1],"unknown_delta":b[2]-a[2],"not_applicable_delta":b[3]-a[3]})
        return ComplianceSnapshotDelta(str(previous.snapshot_id),str(current.snapshot_id),compatible,current.compliant_count-previous.compliant_count,current.non_compliant_count-previous.non_compliant_count,current.unknown_count-previous.unknown_count,current.not_applicable_count-previous.not_applicable_count,current.endpoint_count-previous.endpoint_count,len(new_ids-old_ids),len(old_ids-new_ids),tuple(control_deltas))
    def timeline(self,principal,context,framework_id,*,version=None,from_dt=None,to_dt=None,limit=50):
        self._auth(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); limit=max(1,min(500,int(limit)))
        if from_dt and to_dt and from_dt>to_dt: raise ValueError("from must not be after to")
        values=self.repo.list_for_organization(context.organization_id,framework_id,limit=10000,offset=0)
        points=[ComplianceTimelinePoint(str(x.snapshot_id),x.created_at,x.framework_version,x.endpoint_count,x.control_evaluation_count,x.compliant_count,x.non_compliant_count,x.unknown_count,x.not_applicable_count,x.evaluation_complete) for x in values if (version is None or x.framework_version==version) and (from_dt is None or x.created_at>=from_dt) and (to_dt is None or x.created_at<=to_dt)]
        points.sort(key=lambda x:(x.created_at,x.snapshot_id)); return tuple(points[-limit:])
    def control_trend(self,principal,context,framework_id,control_id,*,version=None,limit=50):
        self._auth(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); self._auth(principal,context,AuthorizationAction.ENDPOINT_READ,"fleet")
        if not version: raise ValueError("framework version is required")
        values=self.repo.list_for_organization(context.organization_id,framework_id,limit=10000,offset=0); points=[]
        for x in values:
            if x.framework_version!=version: continue
            rows=[c.status for c in x.controls if c.control_id==control_id]
            if not rows: continue
            points.append(ComplianceControlTrendPoint(str(x.snapshot_id),x.created_at,version,control_id,rows.count(ComplianceStatus.COMPLIANT),rows.count(ComplianceStatus.NON_COMPLIANT),rows.count(ComplianceStatus.UNKNOWN),rows.count(ComplianceStatus.NOT_APPLICABLE),len({c.endpoint_id for c in x.controls if c.control_id==control_id})))
        if not points:
            raise KeyError("control trend not found")
        points.sort(key=lambda x:(x.created_at,x.snapshot_id)); return tuple(points[-max(1,min(500,int(limit))):])
    def endpoint_history(self,principal,context,endpoint_id,framework_id,*,limit=50):
        self._auth(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); self._auth(principal,context,AuthorizationAction.ENDPOINT_READ,"endpoint",endpoint_id)
        values=self.repo.list_for_organization(context.organization_id,framework_id,limit=10000,offset=0); points=[]
        for x in values:
            endpoint=next((e for e in x.endpoints if e.endpoint_id==str(endpoint_id)),None)
            if endpoint is None: continue
            rows=[c.status for c in x.controls if c.endpoint_id==str(endpoint_id)]
            points.append(ComplianceEndpointHistoryPoint(str(x.snapshot_id),x.created_at,str(endpoint_id),endpoint.hostname,endpoint.platform,endpoint.lifecycle_status,rows.count(ComplianceStatus.COMPLIANT),rows.count(ComplianceStatus.NON_COMPLIANT),rows.count(ComplianceStatus.UNKNOWN),rows.count(ComplianceStatus.NOT_APPLICABLE)))
        points.sort(key=lambda x:(x.snapshot_created_at,x.snapshot_id)); return tuple(points[-max(1,min(500,int(limit))):])
    def export(self,principal,context,snapshot_id,fmt):
        snapshot=self.get(principal,context,snapshot_id); self._auth(principal,context,AuthorizationAction.ENDPOINT_READ,"fleet"); fmt=fmt.lower()
        if fmt=="json": value=json.dumps(snapshot.to_dict(),sort_keys=True,separators=(",",":")); self._record_export(principal,snapshot,fmt,value); return value,"application/json"
        if fmt!="csv": raise ValueError("unsupported export format")
        if len(snapshot.controls)>self.max_export_rows: raise ValueError("export row bound exceeded")
        out=io.StringIO(); writer=csv.writer(out); writer.writerow(["snapshot_id","snapshot_created_at","framework_id","framework_version","endpoint_id","hostname","control_id","control_title","status","reason","evaluated_at","source_assessment_id"])
        names={x.endpoint_id:x.hostname for x in snapshot.endpoints}
        for row in snapshot.controls: writer.writerow([str(snapshot.snapshot_id),snapshot.created_at.isoformat(),snapshot.framework_id,snapshot.framework_version,_csv(row.endpoint_id),_csv(names.get(row.endpoint_id,"")),_csv(row.control_id),_csv(row.control_title),row.status.value,_csv(row.reason_code),row.evaluated_at.isoformat(),_csv(row.source_assessment_id or "")])
        value=out.getvalue(); self._record_export(principal,snapshot,fmt,value); return value,"text/csv"
    def export_manifest(self, principal, context, snapshot_id, fmt):
        body, content_type = self.export(principal, context, snapshot_id, fmt)
        snapshot = self.repo.get_for_organization(snapshot_id, context.organization_id)
        return {"snapshot_id":str(snapshot.snapshot_id),"format":str(fmt).lower(),"export_format_version":1,"generated_at":datetime.now(timezone.utc).isoformat(),"row_count":len(snapshot.controls),"framework_id":snapshot.framework_id,"framework_version":snapshot.framework_version,"snapshot_digest_sha256":snapshot.snapshot_digest_sha256,"sha256_digest":hashlib.sha256(body.encode("utf-8")).hexdigest(),"content_type":content_type}
    def verify_integrity(self, principal, context, snapshot_id):
        return verify_snapshot_integrity(self.get(principal, context, snapshot_id))
    def _record_export(self, principal, snapshot, fmt, body):
        if self.metrics:
            self.metrics.increment("compliance_exports_total"); self.metrics.increment("compliance_export_rows_total",len(snapshot.controls))
        if self.audit:
            from ...domain.security import SecurityAuditEvent, SecurityAuditOutcome
            self.audit.append(SecurityAuditEvent(event_type="compliance.snapshot.export", principal=principal, outcome=SecurityAuditOutcome.SUCCESS, organization_id=str(snapshot.organization_id), metadata={"snapshot_id":str(snapshot.snapshot_id),"format":fmt,"row_count":len(snapshot.controls),"digest":hashlib.sha256(body.encode("utf-8")).hexdigest()}))
    def _auth(self,p,c,a,t,i=None):
        if p.principal_type is not PrincipalType.HUMAN or c is None: raise PermissionError("human context required")
        d=self.authorizer.authorize(AuthorizationRequest(p,a,AuthorizationResource(t,str(i) if i else None,{"organization_id":str(c.organization_id)}),organization_context=c));
        if not d.allowed:raise PermissionError(d.reason_code)
def _csv(value):
    text=str(value or "")
    return "'"+text if text[:1] in "=+-@" else text
