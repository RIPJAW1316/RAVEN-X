"""Application use-case tests without SQLAlchemy or platform effects."""

from datetime import datetime

import pytest

from backend.application.assessment.run_local_assessment import RunLocalAssessment
from backend.application.assessment.local_runner import LocalAssessmentRunner
from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, Finding, FindingSeverity


TARGET = AssessmentTarget("local:test", "test-host", "Windows")


class FakeRepository:
    def __init__(self, persist_error=None):
        self.calls = []
        self.persist_error = persist_error

    def create_assessment(self, assessment_id, scan_type, target, started_at):
        self.calls.append(("create", assessment_id, scan_type, target))

    def persist_completed(self, result):
        self.calls.append(("complete", result.assessment_id, len(result.findings)))
        if self.persist_error:
            raise self.persist_error

    def mark_failed(self, assessment_id, finished_at, error):
        self.calls.append(("failed", assessment_id, error))


class FakeRunner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def resolve_target(self):
        return TARGET

    def run(self, target, options=None):
        self.calls.append((target, options))
        return self.result


def _completed_result(findings=()):
    now = datetime.utcnow()
    return AssessmentResult("runner-id", TARGET, AssessmentStatus.COMPLETED, now, now, findings=findings)


def test_use_case_creates_then_persists_successful_assessment():
    finding = Finding("finding-1", FindingSeverity.LOW, "Network", "Example", "Example", "Network")
    repository = FakeRepository()
    runner = FakeRunner(_completed_result((finding,)))
    use_case = RunLocalAssessment(runner, repository)

    assessment_id, target = use_case.start("full")
    result = use_case.execute(assessment_id, target)

    assert result.assessment_id == assessment_id
    assert [call[0] for call in repository.calls] == ["create", "complete"]
    assert runner.calls == [(TARGET, None)]


def test_use_case_persists_zero_findings_as_completed():
    repository = FakeRepository()
    use_case = RunLocalAssessment(FakeRunner(_completed_result()), repository)

    assessment_id, target = use_case.start("full")
    use_case.execute(assessment_id, target)

    assert repository.calls[-1] == ("complete", assessment_id, 0)


def test_use_case_persists_scanner_failure():
    now = datetime.utcnow()
    failure = AssessmentResult("runner-id", TARGET, AssessmentStatus.FAILED, now, now, error="scanner failed")
    repository = FakeRepository()
    use_case = RunLocalAssessment(FakeRunner(failure), repository)

    assessment_id, target = use_case.start("full")
    result = use_case.execute(assessment_id, target)

    assert result.status is AssessmentStatus.FAILED
    assert repository.calls[-1] == ("failed", assessment_id, "scanner failed")


def test_use_case_marks_assessment_failed_when_persistence_fails():
    repository = FakeRepository(persist_error=RuntimeError("disk full"))
    use_case = RunLocalAssessment(FakeRunner(_completed_result()), repository)
    assessment_id, target = use_case.start("full")

    with pytest.raises(RuntimeError, match="disk full"):
        use_case.execute(assessment_id, target)

    assert repository.calls[-1] == ("failed", assessment_id, "Persistence failed: disk full")


def test_use_case_persists_normalization_issue_from_local_runner():
    class ScannerWithMalformedFinding:
        system_info = {}

        def scan_all(self, progress_callback=None):
            return [
                {
                    "severity": "low",
                    "category": "Network",
                    "title": "Example",
                    "details": "Example",
                    "component": "Network",
                },
                7,
            ]

    repository = FakeRepository()
    use_case = RunLocalAssessment(LocalAssessmentRunner(ScannerWithMalformedFinding), repository)
    assessment_id, target = use_case.start("full", TARGET)
    result = use_case.execute(assessment_id, target)

    assert result.scanner_metadata["normalization_issues"][0].raw_value == 7
    assert repository.calls[-1] == ("complete", assessment_id, 1)
