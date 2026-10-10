"""Persistence port needed by the local assessment use case."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol

from ...domain.assessment import AssessmentResult, AssessmentTarget


@dataclass(frozen=True)
class PersistedAssessment:
    assessment_id: str
    scan_type: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    total_findings: int
    error: Optional[str] = None


class AssessmentRepository(Protocol):
    def create_assessment(
        self,
        assessment_id: str,
        scan_type: str,
        target: AssessmentTarget,
        started_at: datetime,
    ) -> None:
        """Persist an initial running assessment."""

    def persist_completed(self, result: AssessmentResult) -> None:
        """Persist a completed result and its findings."""

    def mark_failed(self, assessment_id: str, finished_at: datetime, error: str) -> None:
        """Persist a terminal failure state."""

    def get(self, assessment_id: str) -> Optional[PersistedAssessment]:
        """Read a persistence-neutral assessment summary."""
