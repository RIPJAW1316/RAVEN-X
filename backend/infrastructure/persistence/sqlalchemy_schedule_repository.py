from datetime import timezone
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from ...core.database.models import AssessmentScheduleRecord, AssessmentScheduleRunRecord
from ...domain.scheduling import *

def _store(v): return v.astimezone(timezone.utc).replace(tzinfo=None)
def _load(v): return v.replace(tzinfo=timezone.utc)

def _schedule(record):
    return AssessmentSchedule(AssessmentScheduleId(record.schedule_id), record.organization_id, record.name,
        tuple(record.target_endpoint_ids or ()), tuple(record.scanner_ids or ()), AssessmentRecurrence.from_dict(record.recurrence_json),
        _load(record.next_run_at), ScheduleStatus(record.status), _load(record.last_run_at) if record.last_run_at else None,
        _load(record.created_at), _load(record.updated_at), record.created_by, record.overlap_policy, record.schedule_metadata or {},
        AssessmentScheduleTarget(record.target_type or "explicit_endpoints", tuple(record.target_endpoint_ids or ()) if (record.target_type or "explicit_endpoints")=="explicit_endpoints" else (), record.target_reference_id))

def _run(record):
    return AssessmentScheduleRun(AssessmentScheduleRunId(record.run_id), record.schedule_id, record.organization_id,
        _load(record.scheduled_for), _load(record.started_at), ScheduleRunStatus(record.status), tuple(record.assessment_ids or ()), record.target_outcomes or {}, record.reason, _load(record.completed_at) if record.completed_at else None, tuple(record.resolved_endpoint_ids or ()), _load(record.targets_resolved_at) if record.targets_resolved_at else None, record.target_type, record.target_reference_id, record.scope_criteria_snapshot or {}, record.resolution_reason)

class SQLAlchemyAssessmentScheduleRepository:
    def __init__(self, database_manager): self._db = database_manager
    def add(self, schedule):
        try:
            with self._db.get_db() as s:
                s.add(AssessmentScheduleRecord(schedule_id=str(schedule.schedule_id), organization_id=str(schedule.organization_id), name=schedule.name, status=schedule.status.value, recurrence_json=schedule.recurrence.to_dict(), target_endpoint_ids=[str(x) for x in schedule.target_endpoint_ids], scanner_ids=list(schedule.scanner_ids), next_run_at=_store(schedule.next_run_at), last_run_at=_store(schedule.last_run_at) if schedule.last_run_at else None, created_by=schedule.created_by, created_at=_store(schedule.created_at), updated_at=_store(schedule.updated_at), overlap_policy=schedule.overlap_policy.value, schedule_metadata=dict(schedule.metadata),target_type=schedule.target.target_type.value,target_reference_id=schedule.target.reference_id)); s.flush()
        except IntegrityError as exc: raise ValueError("schedule already exists") from exc
    def get(self, schedule_id):
        with self._db.get_db() as s:
            record = s.get(AssessmentScheduleRecord, str(schedule_id))
            return _schedule(record) if record else None
    def update(self, schedule):
        with self._db.get_db() as s:
            r=s.get(AssessmentScheduleRecord,str(schedule.schedule_id));
            if not r: raise KeyError("schedule not found")
            r.name=schedule.name; r.status=schedule.status.value; r.recurrence_json=schedule.recurrence.to_dict(); r.target_endpoint_ids=[str(x) for x in schedule.target_endpoint_ids]; r.scanner_ids=list(schedule.scanner_ids); r.next_run_at=_store(schedule.next_run_at); r.last_run_at=_store(schedule.last_run_at) if schedule.last_run_at else None; r.updated_at=_store(schedule.updated_at); r.overlap_policy=schedule.overlap_policy.value; r.schedule_metadata=dict(schedule.metadata); r.target_type=schedule.target.target_type.value; r.target_reference_id=schedule.target.reference_id
    def list_for_organization(self, organization_id):
        with self._db.get_db() as s: return tuple(_schedule(r) for r in s.execute(select(AssessmentScheduleRecord).where(AssessmentScheduleRecord.organization_id==str(organization_id)).order_by(AssessmentScheduleRecord.created_at)).scalars())
    def list_due(self, now, limit):
        with self._db.get_db() as s: return tuple(_schedule(r) for r in s.execute(select(AssessmentScheduleRecord).where(AssessmentScheduleRecord.status==ScheduleStatus.ACTIVE.value, AssessmentScheduleRecord.next_run_at<=_store(now)).order_by(AssessmentScheduleRecord.next_run_at).limit(limit)).scalars())

class SQLAlchemyAssessmentScheduleRunRepository:
    def __init__(self, database_manager): self._db=database_manager
    def add_if_absent(self, run):
        try:
            with self._db.get_db() as s:
                s.add(AssessmentScheduleRunRecord(run_id=str(run.run_id), schedule_id=str(run.schedule_id), organization_id=str(run.organization_id), scheduled_for=_store(run.scheduled_for), started_at=_store(run.started_at), status=run.status.value, assessment_ids=list(run.assessment_ids), target_outcomes=dict(run.target_outcomes), reason=run.reason, completed_at=_store(run.completed_at) if run.completed_at else None,resolved_endpoint_ids=list(run.resolved_endpoint_ids),targets_resolved_at=_store(run.targets_resolved_at) if run.targets_resolved_at else None,target_type=run.target_type,target_reference_id=run.target_reference_id,scope_criteria_snapshot=dict(run.scope_criteria_snapshot),resolution_reason=run.resolution_reason)); s.flush(); return True
        except IntegrityError: return False
    def get(self, schedule_id, scheduled_for):
        with self._db.get_db() as s:
            r=s.execute(select(AssessmentScheduleRunRecord).where(AssessmentScheduleRunRecord.schedule_id==str(schedule_id), AssessmentScheduleRunRecord.scheduled_for==_store(scheduled_for))).scalar_one_or_none(); return _run(r) if r else None
    def update(self, run):
        with self._db.get_db() as s:
            r=s.get(AssessmentScheduleRunRecord,str(run.run_id));
            if not r: raise KeyError("schedule run not found")
            r.status=run.status.value; r.assessment_ids=list(run.assessment_ids); r.target_outcomes=dict(run.target_outcomes); r.reason=run.reason; r.completed_at=_store(run.completed_at) if run.completed_at else None; r.resolved_endpoint_ids=list(run.resolved_endpoint_ids); r.targets_resolved_at=_store(run.targets_resolved_at) if run.targets_resolved_at else None; r.target_type=run.target_type; r.target_reference_id=run.target_reference_id; r.scope_criteria_snapshot=dict(run.scope_criteria_snapshot); r.resolution_reason=run.resolution_reason
    def list_for_schedule(self, schedule_id):
        with self._db.get_db() as s: return tuple(_run(r) for r in s.execute(select(AssessmentScheduleRunRecord).where(AssessmentScheduleRunRecord.schedule_id==str(schedule_id)).order_by(AssessmentScheduleRunRecord.scheduled_for)).scalars())
