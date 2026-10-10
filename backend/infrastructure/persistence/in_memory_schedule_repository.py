from dataclasses import replace
from ...domain.scheduling import ScheduleStatus

class InMemoryAssessmentScheduleRepository:
    def __init__(self): self._items = {}
    def add(self, schedule):
        if str(schedule.schedule_id) in self._items: raise ValueError("schedule already exists")
        self._items[str(schedule.schedule_id)] = schedule
    def get(self, schedule_id): return self._items.get(str(schedule_id))
    def update(self, schedule):
        if str(schedule.schedule_id) not in self._items: raise KeyError("schedule not found")
        self._items[str(schedule.schedule_id)] = schedule
    def list_for_organization(self, organization_id): return tuple(x for x in self._items.values() if str(x.organization_id) == str(organization_id))
    def list_due(self, now, limit): return tuple(x for x in self._items.values() if x.status is ScheduleStatus.ACTIVE and x.next_run_at <= now)[:limit]

class InMemoryAssessmentScheduleRunRepository:
    def __init__(self): self._items = {}
    def add_if_absent(self, run):
        key = (str(run.schedule_id), run.scheduled_for.astimezone(__import__('datetime').timezone.utc).isoformat())
        if key in self._items: return False
        self._items[key] = run; return True
    def get(self, schedule_id, scheduled_for):
        key = (str(schedule_id), scheduled_for.astimezone(__import__('datetime').timezone.utc).isoformat()); return self._items.get(key)
    def update(self, run):
        key = (str(run.schedule_id), run.scheduled_for.astimezone(__import__('datetime').timezone.utc).isoformat()); self._items[key] = run
    def list_for_schedule(self, schedule_id): return tuple(x for x in self._items.values() if str(x.schedule_id) == str(schedule_id))
