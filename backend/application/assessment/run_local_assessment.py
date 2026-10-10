"""Use case that runs and persists one local assessment."""

from dataclasses import replace
from datetime import datetime
import uuid
from typing import Mapping, Optional, Tuple, Union

from ...domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget
from ..ports.assessment_repository import AssessmentRepository
from .local_orchestrator import LocalAssessmentOrchestrator
from .local_runner import LocalAssessmentRunner
from .options import AssessmentOptions


class RunLocalAssessment:
    """Coordinate a local runner and repository without knowing SQLAlchemy."""

    def __init__(
        self,
        runner: LocalAssessmentRunner,
        repository: AssessmentRepository,
        orchestrator: Optional[LocalAssessmentOrchestrator] = None,
    ):
        self._runner = runner
        self._repository = repository
        self._orchestrator = orchestrator

    def start(self, scan_type: str, target: Optional[AssessmentTarget] = None) -> Tuple[str, AssessmentTarget]:
        resolved_target = target or self._runner.resolve_target()
        assessment_id = str(uuid.uuid4())
        self._repository.create_assessment(
            assessment_id=assessment_id,
            scan_type=scan_type,
            target=resolved_target,
            started_at=datetime.utcnow(),
        )
        return assessment_id, resolved_target

    def execute(
        self,
        assessment_id: str,
        target: AssessmentTarget,
        options: Optional[Union[AssessmentOptions, Mapping[str, object]]] = None,
    ) -> AssessmentResult:
        scanner_ids = _selected_scanner_ids(options)
        if scanner_ids is None:
            legacy_options = options if isinstance(options, Mapping) else None
            result = self._runner.run(target=target, options=legacy_options)
        elif self._orchestrator is None:
            now = datetime.utcnow()
            result = AssessmentResult(
                assessment_id=assessment_id,
                target=target,
                status=AssessmentStatus.FAILED,
                started_at=now,
                finished_at=now,
                error="Scanner selection was requested but no local orchestrator is configured",
            )
        else:
            result = self._orchestrator.run(target=target, scanner_ids=scanner_ids)

        result = replace(result, assessment_id=assessment_id)

        if result.status is AssessmentStatus.FAILED:
            self._repository.mark_failed(assessment_id, result.finished_at or datetime.utcnow(), result.error or "Unknown scanner error")
            return result

        try:
            self._repository.persist_completed(result)
        except Exception as error:
            message = f"Persistence failed: {error}"
            self._repository.mark_failed(assessment_id, datetime.utcnow(), message)
            raise

        return result


def _selected_scanner_ids(
    options: Optional[Union[AssessmentOptions, Mapping[str, object]]],
) -> Optional[Tuple[str, ...]]:
    if isinstance(options, AssessmentOptions):
        return options.scanner_ids
    if isinstance(options, Mapping) and "scanner_ids" in options:
        scanner_ids = options["scanner_ids"]
        if scanner_ids is None:
            return None
        return tuple(scanner_ids)
    return None
