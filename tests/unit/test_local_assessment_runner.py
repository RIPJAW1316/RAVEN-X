"""Tests for the adapter over the existing local scanner."""

import json
from pathlib import Path

from backend.application.assessment.local_runner import LocalAssessmentRunner
from backend.domain.assessment import AssessmentStatus, AssessmentTarget


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_firewall_finding.json"


class FakeScanner:
    def __init__(self, findings=None, error=None):
        self.findings = findings if findings is not None else []
        self.error = error
        self.system_info = {"hostname": "scanner-host", "os_version": "Windows Test"}
        self.progress_callbacks = []

    def scan_all(self, progress_callback=None):
        self.progress_callbacks.append(progress_callback)
        if self.error:
            raise self.error
        return self.findings


def test_runner_adapts_mocked_legacy_scan_to_domain_result():
    legacy = json.loads(FIXTURE.read_text(encoding="utf-8"))
    scanner = FakeScanner([legacy])
    runner = LocalAssessmentRunner(scanner_factory=lambda: scanner)
    target = AssessmentTarget(
        target_id="local:test-host",
        hostname="test-host",
        platform="Windows",
        platform_version="test",
        metadata={"source": "test"},
    )

    result = runner.run(target=target, options={"progress_callback": "callback marker"})

    assert result.status is AssessmentStatus.COMPLETED
    assert result.target == target
    assert result.findings[0].title == legacy["title"]
    assert scanner.progress_callbacks == ["callback marker"]
    assert result.scanner_metadata["system_info"] == scanner.system_info


def test_runner_handles_zero_findings_without_creating_side_effects():
    scanner = FakeScanner([])
    runner = LocalAssessmentRunner(scanner_factory=lambda: scanner)

    result = runner.run(target=AssessmentTarget("local:test", "test", "Windows"))

    assert result.status is AssessmentStatus.COMPLETED
    assert result.findings == ()
    assert not hasattr(scanner, "apply_fix")
    assert not hasattr(scanner, "analyze")


def test_runner_represents_scanner_failure_explicitly():
    runner = LocalAssessmentRunner(scanner_factory=lambda: FakeScanner(error=RuntimeError("scanner failed")))

    result = runner.run(target=AssessmentTarget("local:test", "test", "Windows"))

    assert result.status is AssessmentStatus.FAILED
    assert result.error == "scanner failed"
    assert result.findings == ()


def test_runner_retains_partial_normalization_issues():
    legacy = json.loads(FIXTURE.read_text(encoding="utf-8"))
    runner = LocalAssessmentRunner(scanner_factory=lambda: FakeScanner([legacy, 42]))

    result = runner.run(target=AssessmentTarget("local:test", "test", "Windows"))

    assert result.status is AssessmentStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.scanner_metadata["normalization_issues"][0].raw_value == 42
