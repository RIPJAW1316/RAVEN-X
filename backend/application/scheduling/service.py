"""Tenant-safe human administration for assessment schedules."""
from dataclasses import replace
from datetime import datetime, timezone
from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.organization import OrganizationStatus
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityPrincipal, SecurityAuditEvent, SecurityAuditOutcome
from ...domain.scheduling import AssessmentRecurrence, AssessmentSchedule, AssessmentScheduleId, AssessmentScheduleCalculator, ScheduleStatus, AssessmentScheduleTarget, ScheduleTargetType

class TenantAssessmentScheduleService:
    def __init__(self, schedule_repository, endpoint_repository, organization_repository, authorizer, *, audit_sink=None, clock=None, max_targets=100, scanner_registry=None):
        self.repository=schedule_repository; self.endpoint_repository=endpoint_repository; self.organization_repository=organization_repository; self.authorizer=authorizer; self.audit_sink=audit_sink; self.clock=clock; self.max_targets=max_targets; self.scanner_registry=scanner_registry
    def create(self, principal, context, name, endpoint_ids, scanner_ids, recurrence, *, starts_at=None, target=None, group_repository=None, scope_repository=None):
        self._ctx(principal, context); self._require(principal, context, AuthorizationAction.ASSESSMENT_SCHEDULE_CREATE)
        if isinstance(starts_at, str): starts_at = datetime.fromisoformat(starts_at)
        schedule_target=self._validate_target(principal, context,target,endpoint_ids,group_repository,scope_repository); targets=self._validate_targets(context, schedule_target.endpoint_ids) if schedule_target.target_type is ScheduleTargetType.EXPLICIT_ENDPOINTS else (); scanners=self._validate_scanners(scanner_ids); rec=recurrence if isinstance(recurrence, AssessmentRecurrence) else AssessmentRecurrence.from_dict(recurrence)
        now=self._now(); anchor=starts_at or rec.starts_at or now; next_run=anchor if anchor > now else AssessmentScheduleCalculator.next_run(rec, anchor, now)
        schedule=AssessmentSchedule(AssessmentScheduleId.new(), context.organization_id, name, tuple(targets), tuple(scanners), rec, next_run, created_at=now, updated_at=now, created_by=principal.principal_id,target=schedule_target)
        self.repository.add(schedule); self._audit("assessment_schedule.created", principal, schedule, AuthorizationAction.ASSESSMENT_SCHEDULE_CREATE); return schedule
    def list(self, principal, context):
        self._ctx(principal, context); self._require(principal, context, AuthorizationAction.ASSESSMENT_SCHEDULE_READ); return self.repository.list_for_organization(context.organization_id)
    def get(self, principal, context, schedule_id):
        self._ctx(principal, context); schedule=self.repository.get(schedule_id)
        if schedule is None or schedule.organization_id != context.organization_id: raise KeyError("schedule not found")
        self._require(principal, context, AuthorizationAction.ASSESSMENT_SCHEDULE_READ, schedule_id); return schedule
    def list_runs(self, principal, context, schedule_id, run_repository):
        self.get(principal, context, schedule_id)
        if run_repository is None or not hasattr(run_repository, "list_for_schedule"):
            return ()
        return run_repository.list_for_schedule(schedule_id)
    def update(self, principal, context, schedule_id, **changes):
        current=self.get(principal, context, schedule_id); self._require(principal, context, AuthorizationAction.ASSESSMENT_SCHEDULE_UPDATE, schedule_id); now=self._now()
        # Supplying endpoint_ids retains the legacy explicit-target update
        # semantics. A supplied target opts into the dynamic group/scope model.
        target_input = changes.get("target")
        if target_input is None and "endpoint_ids" in changes:
            schedule_target = AssessmentScheduleTarget(ScheduleTargetType.EXPLICIT_ENDPOINTS, tuple(changes.get("endpoint_ids") or ()))
        elif target_input is None:
            schedule_target = current.target
        else:
            schedule_target = self._validate_target(principal, context, target_input, changes.get("endpoint_ids", ()), changes.get("group_repository"), changes.get("scope_repository"))
        targets=self._validate_targets(context, schedule_target.endpoint_ids) if schedule_target.target_type is ScheduleTargetType.EXPLICIT_ENDPOINTS else ()
        scanners=self._validate_scanners(changes.get("scanner_ids", current.scanner_ids)); rec=changes.get("recurrence", current.recurrence); rec=rec if isinstance(rec, AssessmentRecurrence) else AssessmentRecurrence.from_dict(rec)
        next_run=AssessmentScheduleCalculator.next_run(rec, None, now) if "recurrence" in changes else current.next_run_at
        updated=replace(current, name=changes.get("name", current.name), target_endpoint_ids=tuple(targets), scanner_ids=tuple(scanners), recurrence=rec, next_run_at=next_run, updated_at=now, target=schedule_target)
        self.repository.update(updated); self._audit("assessment_schedule.updated", principal, updated, AuthorizationAction.ASSESSMENT_SCHEDULE_UPDATE)
        if updated.target != current.target: self._audit("assessment_schedule.target_changed", principal, updated, AuthorizationAction.ASSESSMENT_SCHEDULE_UPDATE)
        return updated
    def pause(self, principal, context, schedule_id): return self._transition(principal, context, schedule_id, ScheduleStatus.PAUSED, AuthorizationAction.ASSESSMENT_SCHEDULE_PAUSE, "assessment_schedule.paused")
    def resume(self, principal, context, schedule_id):
        current=self.get(principal, context, schedule_id); self._require(principal, context, AuthorizationAction.ASSESSMENT_SCHEDULE_UPDATE, schedule_id); now=self._now()
        updated=replace(current.transition_to(ScheduleStatus.ACTIVE, now), next_run_at=AssessmentScheduleCalculator.next_run(current.recurrence, None, now)); self.repository.update(updated); self._audit("assessment_schedule.resumed", principal, updated, AuthorizationAction.ASSESSMENT_SCHEDULE_UPDATE); return updated
    def revoke(self, principal, context, schedule_id): return self._transition(principal, context, schedule_id, ScheduleStatus.REVOKED, AuthorizationAction.ASSESSMENT_SCHEDULE_REVOKE, "assessment_schedule.revoked")
    def _transition(self, principal, context, schedule_id, status, action, event):
        current=self.get(principal, context, schedule_id); self._require(principal, context, action, schedule_id); updated=current.transition_to(status, self._now()); self.repository.update(updated); self._audit(event, principal, updated, action); return updated
    def _validate_targets(self, context, endpoint_ids):
        values=tuple(endpoint_ids or ())
        if not values or len(values)>self.max_targets: raise ValueError("invalid target count")
        result=[]
        for value in values:
            endpoint=self.endpoint_repository.get_for_organization(value if isinstance(value, EndpointId) else EndpointId(value), context.organization_id)
            if endpoint is None: raise KeyError("endpoint not found")
            if endpoint.status is EndpointStatus.REVOKED: raise ValueError("revoked endpoint cannot be scheduled")
            result.append(endpoint.endpoint_id)
        if len(set(map(str,result))) != len(result): raise ValueError("duplicate target endpoint")
        return result
    def _validate_scanners(self, scanner_ids):
        values=tuple(str(x).strip() for x in (scanner_ids or ()) if str(x).strip())
        if not values: raise ValueError("scanner_ids are required")
        if len(values)>100: raise ValueError("too many scanner ids")
        return values
    def _validate_target(self,principal,context,target,endpoint_ids,groups,scopes):
        if target is None: return AssessmentScheduleTarget(ScheduleTargetType.EXPLICIT_ENDPOINTS,tuple(endpoint_ids or ()))
        value=target if isinstance(target,AssessmentScheduleTarget) else AssessmentScheduleTarget(target.get("type"),tuple(target.get("endpoint_ids",())),target.get("group_id") or target.get("scope_id") or target.get("reference_id"))
        if value.target_type is ScheduleTargetType.ENDPOINT_GROUP:
            self._require(principal, context, AuthorizationAction.ENDPOINT_GROUP_READ, value.reference_id)
            item=groups.get(value.reference_id) if groups is not None else None
            if item is None or item.organization_id!=context.organization_id or item.status.value!="active": raise ValueError("invalid endpoint group target")
        if value.target_type is ScheduleTargetType.SAVED_FLEET_SCOPE:
            self._require(principal, context, AuthorizationAction.FLEET_SCOPE_READ, value.reference_id)
            item=scopes.get(value.reference_id) if scopes is not None else None
            if item is None or item.organization_id!=context.organization_id or item.status.value!="active": raise ValueError("invalid saved fleet scope target")
        return value
    def _require(self, principal, context, action, resource_id=None):
        d=self.authorizer.authorize(AuthorizationRequest(principal, action, AuthorizationResource("assessment_schedule", str(resource_id) if resource_id else None, {"organization_id":str(context.organization_id)}), organization_context=context))
        if not d.allowed: raise PermissionError(d.reason_code)
    @staticmethod
    def _ctx(principal, context):
        if principal.principal_type.value!="human" or context is None: raise PermissionError("human organization context required")
    def _now(self): return (self.clock or (lambda: datetime.now(timezone.utc)))()
    def _audit(self,event,principal,schedule,action):
        if self.audit_sink: self.audit_sink.append(SecurityAuditEvent(event_type=event, principal=principal, action=action, resource=AuthorizationResource("assessment_schedule",str(schedule.schedule_id)), outcome=SecurityAuditOutcome.SUCCESS, organization_id=str(schedule.organization_id), user_id=principal.principal_id, metadata={"target_type":schedule.target.target_type.value,"target_count":len(schedule.target_endpoint_ids),"scanner_ids":list(schedule.scanner_ids)}))
