"""Assessment domain contracts independent of UI and infrastructure."""

from .models import (
    AssessmentResult,
    AssessmentStatus,
    AssessmentTarget,
    Evidence,
    Finding,
    FindingSeverity,
)

__all__ = [
    "AssessmentResult",
    "AssessmentStatus",
    "AssessmentTarget",
    "Evidence",
    "Finding",
    "FindingSeverity",
]
