"""Bounded internal scheduler; no background loop or generic jobs."""
from dataclasses import replace
from datetime import datetime, timezone
from ...domain.endpoint import EndpointStatus
from ...domain.organization import OrganizationStatus
from ...domain.security import SecurityPrincipal, SecurityAuditEvent, SecurityAuditOutcome
from ...domain.scheduling import AssessmentScheduleCalculator, AssessmentScheduleRun, AssessmentScheduleRunId, ScheduleRunStatus, ScheduleStatus, ScheduleTargetType
from ..control_plane.assessment_dispatch import RemoteAssessmentState

class AssessmentScheduleRunner:
    def __init__(self, schedule_repository, run_repository, assessment_service, endpoint_repository, organization_repository, assessments, *, clock=None, batch_size=100, audit_sink=None, metrics=None, group_repository=None, scope_repository=None, max_targets=100):
        self.schedules=schedule_repository; self.runs=run_repository; self.assessment_service=assessment_service; self.endpoints=endpoint_repository; self.organizations=organization_repository; self.assessments=assessments; self.clock=clock; self.batch_size=batch_size; self.audit_sink=audit_sink; self.metrics=metrics; self.groups=group_repository; self.scopes=scope_repository; self.max_targets=max_targets
    def run_once(self, *, now=None):
        now=now or (self.clock or (lambda: datetime.now(timezone.utc)))(); summary=[]
        for schedule in self.schedules.list_due(now, self.batch_size):
            if schedule.status is not ScheduleStatus.ACTIVE: continue
            run=AssessmentScheduleRun(AssessmentScheduleRunId.new(), schedule.schedule_id, schedule.organization_id, schedule.next_run_at, now)
            if not self.runs.add_if_absent(run):
                existing = self.runs.get(schedule.schedule_id, schedule.next_run_at)
                if existing is None or existing.completed_at is not None:
                    summary.append(existing); continue
                run = existing
            outcomes=dict(run.target_outcomes); created=list(run.assessment_ids); failed=sum(1 for value in outcomes.values() if value == "FAILED")
            org=self.organizations.get(schedule.organization_id)
            if org is None or org.status is not OrganizationStatus.ACTIVE:
                run=replace(run,status=ScheduleRunStatus.SKIPPED,reason="organization unavailable",completed_at=now)
            else:
                if not run.resolved_endpoint_ids and run.targets_resolved_at is None:
                    try:
                        resolved,criteria=self._resolve_targets(schedule)
                        if len(resolved)>self.max_targets: raise ValueError("TARGET_LIMIT_EXCEEDED")
                        run=replace(run,resolved_endpoint_ids=tuple(str(x) for x in resolved),targets_resolved_at=now,target_type=schedule.target.target_type.value,target_reference_id=schedule.target.reference_id,scope_criteria_snapshot=criteria,resolution_reason="RESOLVED")
                        self.runs.update(run)
                        if self.metrics is not None: self.metrics.increment("schedule.target_resolutions")
                    except ValueError as error:
                        if self.metrics is not None:
                            self.metrics.increment("schedule.target_resolution_failures")
                            if str(error) == "TARGET_LIMIT_EXCEEDED": self.metrics.increment("schedule.target_limit_exceeded")
                        run=replace(run,status=ScheduleRunStatus.SKIPPED,reason=str(error),resolution_reason=str(error),completed_at=now,target_type=schedule.target.target_type.value,target_reference_id=schedule.target.reference_id); self.runs.update(run); self.schedules.update(replace(schedule,last_run_at=now,next_run_at=AssessmentScheduleCalculator.next_run(schedule.recurrence,schedule.next_run_at,now),updated_at=now)); summary.append(run)
                        if self.audit_sink is not None: self.audit_sink.append(SecurityAuditEvent(event_type="assessment_schedule.run", principal=SecurityPrincipal.system(), outcome=SecurityAuditOutcome.FAILED, organization_id=str(schedule.organization_id), metadata={"schedule_id":str(schedule.schedule_id),"target_type":schedule.target.target_type.value,"resolved_count":0,"resolution_reason":str(error)}))
                        continue
                # Dynamic targets can resolve to an empty set. Persist that outcome
                # as an explicit skipped run; the timestamped snapshot prevents
                # accidental re-resolution during crash recovery/resume.
                if not run.resolved_endpoint_ids:
                    run=replace(run,status=ScheduleRunStatus.SKIPPED,reason="EMPTY_TARGET",resolution_reason="EMPTY_TARGET",completed_at=now)
                    self.runs.update(run)
                    self.schedules.update(replace(schedule,last_run_at=now,next_run_at=AssessmentScheduleCalculator.next_run(schedule.recurrence,schedule.next_run_at,now),updated_at=now))
                    if self.metrics is not None: self.metrics.increment("schedule.empty_target_runs")
                    summary.append(run)
                    if self.audit_sink is not None: self.audit_sink.append(SecurityAuditEvent(event_type="assessment_schedule.run", principal=SecurityPrincipal.system(), outcome=SecurityAuditOutcome.SUCCESS, organization_id=str(schedule.organization_id), metadata={"schedule_id":str(schedule.schedule_id),"target_type":schedule.target.target_type.value,"resolved_count":0,"resolution_reason":"EMPTY_TARGET"}))
                    continue
                for endpoint_value in run.resolved_endpoint_ids:
                    endpoint_id=__import__('backend.domain.endpoint',fromlist=['EndpointId']).EndpointId(endpoint_value)
                    if str(endpoint_id) in outcomes and outcomes[str(endpoint_id)] in {"CREATED", "SKIPPED_REVOKED", "SKIPPED_ACTIVE"}:
                        continue
                    endpoint=self.endpoints.get_for_organization(endpoint_id,schedule.organization_id)
                    if endpoint is None or endpoint.status is EndpointStatus.REVOKED:
                        outcomes[str(endpoint_id)]="SKIPPED_REVOKED"; continue
                    scheduled = self.assessments.list_for_schedule(schedule.schedule_id) if hasattr(self.assessments, "list_for_schedule") else tuple(a for a in self.assessments.list() if getattr(a, "schedule_id", None) == str(schedule.schedule_id))
                    active=any((a.endpoint_id==endpoint_id and not a.terminal) for a in scheduled)
                    if active: outcomes[str(endpoint_id)]="SKIPPED_ACTIVE"; continue
                    try:
                        assessment=self.assessment_service.create_scheduled_assessment(endpoint_id, schedule.scanner_ids, schedule.organization_id, requested_at=schedule.next_run_at, schedule_id=schedule.schedule_id)
                        created.append(assessment.assessment_id); outcomes[str(endpoint_id)]="CREATED"
                    except Exception:
                        outcomes[str(endpoint_id)]="FAILED"; failed += 1
                status=ScheduleRunStatus.CREATED if created and not failed and all(v=="CREATED" for v in outcomes.values()) else ScheduleRunStatus.PARTIAL if created else ScheduleRunStatus.FAILED
                run=replace(run,status=status,assessment_ids=tuple(created),target_outcomes=outcomes,completed_at=now)
            self.runs.update(run); updated=replace(schedule,last_run_at=now,next_run_at=AssessmentScheduleCalculator.next_run(schedule.recurrence,schedule.next_run_at,now),updated_at=now); self.schedules.update(updated); summary.append(run)
            if self.audit_sink is not None:
                self.audit_sink.append(SecurityAuditEvent(event_type="assessment_schedule.run", principal=SecurityPrincipal.system(), outcome=SecurityAuditOutcome.SUCCESS if run.status is not ScheduleRunStatus.FAILED else SecurityAuditOutcome.FAILED, organization_id=str(schedule.organization_id), metadata={"schedule_id": str(schedule.schedule_id), "scheduled_for": schedule.next_run_at.isoformat(), "target_type": schedule.target.target_type.value, "resolved_count": len(run.resolved_endpoint_ids), "created_count": len(created), "skipped_count": sum(1 for value in outcomes.values() if value.startswith("SKIPPED")), "failed_count": failed}))
            if self.metrics is not None:
                self.metrics.increment("assessment_schedule.runs")
                self.metrics.increment("scheduled_assessments.created", len(created))
                self.metrics.increment("scheduled_assessments.skipped", sum(1 for value in outcomes.values() if value.startswith("SKIPPED")))
                if run.status is ScheduleRunStatus.FAILED: self.metrics.increment("assessment_schedule.run_failures")
        return tuple(summary)
    def _resolve_targets(self,schedule):
        target=schedule.target
        if target.target_type is ScheduleTargetType.EXPLICIT_ENDPOINTS: return tuple(target.endpoint_ids),{}
        if target.target_type is ScheduleTargetType.ENDPOINT_GROUP:
            group=self.groups.get(target.reference_id) if self.groups else None
            if group is None: raise ValueError("TARGET_NOT_FOUND")
            if group.organization_id!=schedule.organization_id: raise ValueError("TARGET_OWNERSHIP_MISMATCH")
            if group.status.value!="active": raise ValueError("TARGET_REVOKED")
            return tuple(__import__('backend.domain.endpoint',fromlist=['EndpointId']).EndpointId(x) for x in self.groups.list_members(target.reference_id,limit=self.max_targets+1,offset=0)),{}
        scope=self.scopes.get(target.reference_id) if self.scopes else None
        if scope is None: raise ValueError("TARGET_NOT_FOUND")
        if scope.organization_id!=schedule.organization_id: raise ValueError("TARGET_OWNERSHIP_MISMATCH")
        if scope.status.value!="active": raise ValueError("TARGET_REVOKED")
        q=replace(scope.fleet_query,limit=min(self.max_targets+1,200),offset=0)
        page=self.endpoints.query_for_organization(schedule.organization_id,q)
        if page.total>self.max_targets: raise ValueError("TARGET_LIMIT_EXCEEDED")
        return tuple(__import__('backend.domain.endpoint',fromlist=['EndpointId']).EndpointId(x.endpoint_id) for x in page.items),scope.to_dict().get("criteria",{})
