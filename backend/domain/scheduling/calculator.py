from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from .models import AssessmentRecurrence, ScheduleFrequency

class AssessmentScheduleCalculator:
    """Pure deterministic recurrence calculator; returned values are UTC-aware."""
    @staticmethod
    def next_run(recurrence: AssessmentRecurrence, previous: datetime | None, now: datetime) -> datetime:
        if now.tzinfo is None or now.utcoffset() is None: raise ValueError("now must be timezone-aware")
        anchor = previous or recurrence.starts_at or now
        if anchor.tzinfo is None or anchor.utcoffset() is None: raise ValueError("anchor must be timezone-aware")
        local = anchor.astimezone(ZoneInfo(recurrence.timezone))
        if recurrence.frequency is ScheduleFrequency.INTERVAL:
            candidate = local + timedelta(hours=recurrence.interval)
        elif recurrence.frequency is ScheduleFrequency.DAILY:
            candidate = local + timedelta(days=recurrence.interval)
            if recurrence.hour is not None: candidate = candidate.replace(hour=recurrence.hour, minute=recurrence.minute or 0, second=0, microsecond=0)
        else:
            candidate = local + timedelta(days=1)
            while candidate.weekday() not in recurrence.days_of_week: candidate += timedelta(days=1)
            candidate = candidate.replace(hour=recurrence.hour if recurrence.hour is not None else local.hour, minute=recurrence.minute if recurrence.minute is not None else local.minute, second=0, microsecond=0)
        while candidate.astimezone(timezone.utc) <= now.astimezone(timezone.utc):
            if recurrence.frequency is ScheduleFrequency.WEEKLY: candidate += timedelta(days=7)
            elif recurrence.frequency is ScheduleFrequency.DAILY: candidate += timedelta(days=recurrence.interval)
            else: candidate += timedelta(hours=recurrence.interval)
        return candidate.astimezone(timezone.utc)
