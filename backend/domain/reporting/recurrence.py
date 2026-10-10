"""Read-only candidate recurrence contracts."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional, Tuple


@dataclass(frozen=True)
class RecurrenceOccurrence:
    occurrence_id: str
    assessment_id: str
    observed_at: datetime
    severity: str
    scanner_id: Optional[str]
    title: str
    fingerprint_version: int = 1

    def to_dict(self):
        return {"occurrence_id": self.occurrence_id, "assessment_id": self.assessment_id,
                "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
                "severity": self.severity, "scanner_id": self.scanner_id,
                "title": self.title, "fingerprint_version": self.fingerprint_version}


@dataclass(frozen=True)
class FindingRecurrenceSummary:
    source_occurrence_id: str
    endpoint_id: str
    identity_status: str
    occurrence_count: int
    first_observed_at: Optional[datetime]
    last_observed_at: Optional[datetime]
    recent_occurrences: Tuple[RecurrenceOccurrence, ...] = ()
    history_complete: bool = True
    assessments_examined: int = 0
    malformed_occurrence_count: int = 0
    generated_at: datetime = None

    def to_dict(self):
        return {"source_occurrence_id": self.source_occurrence_id,
                "endpoint_id": self.endpoint_id, "identity_status": self.identity_status,
                "occurrence_count": self.occurrence_count,
                "first_observed_at": _iso(self.first_observed_at),
                "last_observed_at": _iso(self.last_observed_at),
                "recent_occurrences": [item.to_dict() for item in self.recent_occurrences],
                "history_complete": self.history_complete,
                "assessments_examined": self.assessments_examined,
                "malformed_occurrence_count": self.malformed_occurrence_count,
                "generated_at": _iso(self.generated_at)}


def _iso(value):
    if value is None: return None
    if value.tzinfo is None or value.utcoffset() is None: value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()
