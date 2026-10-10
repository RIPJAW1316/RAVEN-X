"""Application port for assessment runners."""

from typing import Mapping, Optional, Protocol

from ...domain.assessment import AssessmentResult, AssessmentTarget


class AssessmentRunner(Protocol):
    def run(
        self,
        target: Optional[AssessmentTarget] = None,
        options: Optional[Mapping[str, object]] = None,
    ) -> AssessmentResult:
        """Run an assessment and return domain data without persisting it."""
