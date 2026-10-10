from datetime import datetime, timezone, timedelta
import pytest
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.organization import Organization, OrganizationId, OrganizationStatus
from backend.domain.scheduling import *
from backend.application.organization.context import OrganizationContext
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_schedule_repository import InMemoryAssessmentScheduleRepository, InMemoryAssessmentScheduleRunRepository
from backend.application.scheduling import TenantAssessmentScheduleService, AssessmentScheduleRunner
from backend.infrastructure.persistence.in_memory_group_scope_repository import InMemoryEndpointGroupRepository, InMemorySavedFleetScopeRepository
from backend.domain.group_scope import SavedFleetScope, SavedFleetScopeId
from backend.domain.fleet import FleetQuery
from backend.domain.group_scope import EndpointGroup, EndpointGroupId

NOW = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

class Repo:
    def __init__(self, items=()): self.items={str(x.endpoint_id):x for x in items}
    def get_for_organization(self,e,o):
        x=self.items.get(str(e)); return x if x and x.organization_id==o else None
class OrgRepo:
    def __init__(self,o): self.o=o
    def get(self,_): return self.o
class Allow:
    def authorize(self,request): return type("D",(),{"allowed":True,"reason_code":"allowed"})()
class AssessmentSink:
    def __init__(self): self.items=[]
    def list_for_schedule(self,_): return self.items
    def add(self,x): self.items.append(x)
class AssessmentService:
    def __init__(self,sink): self.sink=sink
    def create_scheduled_assessment(self,e,scanners,org,**kw):
        x=type("A",(),{"assessment_id":f"a-{len(self.sink.items)}","schedule_id":str(kw["schedule_id"]),"endpoint_id":e,"terminal":False})()
        self.sink.items.append(x); return x

def endpoint(org, status=EndpointStatus.ACTIVE):
    return Endpoint(EndpointId.new(), "host", PlatformInfo("Windows"), organization_id=org, status=status, created_at=NOW, updated_at=NOW)

def test_recurrence_daily_timezone_and_weekly():
    daily=AssessmentRecurrence(ScheduleFrequency.DAILY, hour=9, timezone="UTC")
    assert AssessmentScheduleCalculator.next_run(daily, NOW, NOW) == datetime(2026,1,2,9,tzinfo=timezone.utc)
    weekly=AssessmentRecurrence(ScheduleFrequency.WEEKLY, days_of_week=(0,), hour=10, timezone="UTC")
    assert AssessmentScheduleCalculator.next_run(weekly, NOW, NOW).weekday() == 0

def test_schedule_service_enforces_tenant_and_limits():
    org=OrganizationId.new(); ep=endpoint(org); repo=InMemoryAssessmentScheduleRepository()
    service=TenantAssessmentScheduleService(repo,Repo([ep]),OrgRepo(Organization(org,"Org",created_at=NOW,updated_at=NOW)),Allow(),clock=lambda:NOW,max_targets=1)
    from backend.domain.user import UserId
    uid=UserId.new(); context=OrganizationContext(org,"membership",uid,resolved_at=NOW); principal=SecurityPrincipal.human(uid)
    s=service.create(principal,context,"Daily",[ep.endpoint_id],["windows.firewall"],AssessmentRecurrence(ScheduleFrequency.DAILY,timezone="UTC"))
    assert s.organization_id == org
    with pytest.raises(ValueError): service.create(principal,context,"Too many",[ep.endpoint_id,EndpointId.new()],["windows.firewall"],AssessmentRecurrence(ScheduleFrequency.DAILY))

def test_runner_creates_one_assessment_and_is_idempotent():
    org=OrganizationId.new(); ep=endpoint(org); schedules=InMemoryAssessmentScheduleRepository(); runs=InMemoryAssessmentScheduleRunRepository()
    schedule=AssessmentSchedule(AssessmentScheduleId.new(),org,"s",(ep.endpoint_id,),("windows.firewall",),AssessmentRecurrence(ScheduleFrequency.DAILY),NOW-timedelta(minutes=1),created_at=NOW-timedelta(days=1),updated_at=NOW-timedelta(days=1))
    schedules.add(schedule); sink=AssessmentSink(); runner=AssessmentScheduleRunner(schedules,runs,AssessmentService(sink),Repo([ep]),OrgRepo(Organization(org,"Org",created_at=NOW,updated_at=NOW)),sink,clock=lambda:NOW)
    first=runner.run_once(); second=runner.run_once(); assert len(sink.items)==1; assert first[0].status is ScheduleRunStatus.CREATED; assert second == ()

def test_revoked_endpoint_is_skipped():
    org=OrganizationId.new(); ep=endpoint(org,EndpointStatus.REVOKED); schedules=InMemoryAssessmentScheduleRepository(); runs=InMemoryAssessmentScheduleRunRepository()
    schedule=AssessmentSchedule(AssessmentScheduleId.new(),org,"s",(ep.endpoint_id,),("windows.firewall",),AssessmentRecurrence(ScheduleFrequency.DAILY),NOW-timedelta(minutes=1),created_at=NOW-timedelta(days=1),updated_at=NOW-timedelta(days=1))
    schedules.add(schedule); sink=AssessmentSink(); result=AssessmentScheduleRunner(schedules,runs,AssessmentService(sink),Repo([ep]),OrgRepo(Organization(org,"Org",created_at=NOW,updated_at=NOW)),sink,clock=lambda:NOW).run_once()[0]
    assert result.status is ScheduleRunStatus.FAILED and result.target_outcomes[str(ep.endpoint_id)] == "SKIPPED_REVOKED"

def test_group_target_snapshot_is_used_for_schedule_run():
    org=OrganizationId.new(); one=endpoint(org); two=endpoint(org); schedules=InMemoryAssessmentScheduleRepository(); runs=InMemoryAssessmentScheduleRunRepository(); groups=InMemoryEndpointGroupRepository(); group=EndpointGroup(EndpointGroupId.new(),org,"g",created_at=NOW,updated_at=NOW); groups.add(group); groups.add_members(group.group_id,[one.endpoint_id,two.endpoint_id],organization_id=org)
    target=AssessmentScheduleTarget(ScheduleTargetType.ENDPOINT_GROUP,reference_id=str(group.group_id))
    schedule=AssessmentSchedule(AssessmentScheduleId.new(),org,"s",(),("windows.firewall",),AssessmentRecurrence(ScheduleFrequency.DAILY),NOW-timedelta(minutes=1),created_at=NOW-timedelta(days=1),updated_at=NOW-timedelta(days=1),target=target); schedules.add(schedule); sink=AssessmentSink()
    result=AssessmentScheduleRunner(schedules,runs,AssessmentService(sink),Repo([one,two]),OrgRepo(Organization(org,"Org",created_at=NOW,updated_at=NOW)),sink,clock=lambda:NOW,group_repository=groups).run_once()[0]
    assert set(result.resolved_endpoint_ids)=={str(one.endpoint_id),str(two.endpoint_id)} and len(sink.items)==2

def test_empty_dynamic_target_is_explicitly_skipped_and_not_reresolved():
    org=OrganizationId.new(); schedules=InMemoryAssessmentScheduleRepository(); runs=InMemoryAssessmentScheduleRunRepository(); groups=InMemoryEndpointGroupRepository(); group=EndpointGroup(EndpointGroupId.new(),org,"empty",created_at=NOW,updated_at=NOW); groups.add(group)
    target=AssessmentScheduleTarget(ScheduleTargetType.ENDPOINT_GROUP,reference_id=str(group.group_id))
    schedule=AssessmentSchedule(AssessmentScheduleId.new(),org,"s",(),("windows.firewall",),AssessmentRecurrence(ScheduleFrequency.DAILY),NOW-timedelta(minutes=1),created_at=NOW-timedelta(days=1),updated_at=NOW-timedelta(days=1),target=target); schedules.add(schedule); sink=AssessmentSink()
    runner=AssessmentScheduleRunner(schedules,runs,AssessmentService(sink),Repo([]),OrgRepo(Organization(org,"Org",created_at=NOW,updated_at=NOW)),sink,clock=lambda:NOW,group_repository=groups)
    result=runner.run_once()[0]
    assert result.status is ScheduleRunStatus.SKIPPED
    assert result.reason == "EMPTY_TARGET" and result.targets_resolved_at == NOW
    assert runner.run_once() == ()
