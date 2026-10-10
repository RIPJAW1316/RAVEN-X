"""Local scanner-selection orchestration tests with no platform side effects."""

from datetime import datetime

from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.assessment.options import AssessmentOptions
from backend.application.assessment.run_local_assessment import RunLocalAssessment
from backend.application.scanner.legacy_adapters import legacy_scanner_adapters
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, Finding, FindingSeverity
from backend.domain.scanner import (
    ScannerCapability,
    ScannerExecutionResult,
    ScannerExecutionStatus,
    ScannerManifest,
    TargetCapabilities,
)


TARGET = AssessmentTarget("local:test", "test-host", "Windows", metadata={"source": "test"})
FIREWALL_CAPABILITY = ScannerCapability("windows.firewall.read")
FIREWALL_MANIFEST = ScannerManifest(
    "windows.firewall",
    "Firewall",
    "Test firewall scanner",
    "Firewall",
    "1.0",
    frozenset({FIREWALL_CAPABILITY}),
)


class FakeRuntime:
    def __init__(self, manifest, result=None, error=None):
        self.manifest = manifest
        self.result = result
        self.error = error
        self.calls = []

    def execute(self, target, capabilities):
        self.calls.append((target, capabilities))
        if self.error:
            raise self.error
        return self.result


def _success(scanner_id="windows.firewall", findings=()):
    now = datetime.utcnow()
    return ScannerExecutionResult(scanner_id, ScannerExecutionStatus.SUCCESS, now, now, findings=findings)


def _orchestrator(*runtimes, capabilities=TargetCapabilities(frozenset({FIREWALL_CAPABILITY}))):
    return LocalAssessmentOrchestrator(ScannerRegistry(runtimes), lambda target: capabilities)


def test_selected_executable_scanner_aggregates_normalized_findings_and_target():
    finding = Finding("finding-1", FindingSeverity.HIGH, "Firewall", "Firewall disabled", "details", "Firewall")
    runtime = FakeRuntime(FIREWALL_MANIFEST, _success(findings=(finding,)))

    result = _orchestrator(runtime).run(TARGET, ("windows.firewall",))

    assert result.status is AssessmentStatus.COMPLETED
    assert result.target == TARGET
    assert result.findings == (finding,)
    assert result.scanner_results[0].status is ScannerExecutionStatus.SUCCESS
    assert result.scanner_metadata["requested_scanner_ids"] == ("windows.firewall",)
    assert runtime.calls


def test_empty_selection_is_a_completed_assessment_with_no_scanner_results():
    result = _orchestrator().run(TARGET, ())

    assert result.status is AssessmentStatus.COMPLETED
    assert result.findings == ()
    assert result.scanner_results == ()


def test_unknown_scanner_is_explicitly_skipped_in_selection_result():
    result = _orchestrator().run(TARGET, ("windows.fake",))

    assert result.status is AssessmentStatus.COMPLETED
    assert result.scanner_results[0].status is ScannerExecutionStatus.SKIPPED
    assert result.scanner_results[0].error == "scanner is not registered"


def test_incompatible_scanner_is_not_executed_and_keeps_reason():
    runtime = FakeRuntime(FIREWALL_MANIFEST, _success())

    result = _orchestrator(runtime, capabilities=TargetCapabilities()).run(TARGET, ("windows.firewall",))

    scanner_result = result.scanner_results[0]
    assert scanner_result.status is ScannerExecutionStatus.INCOMPATIBLE
    assert scanner_result.error == "required capability unavailable: windows.firewall.read"
    assert runtime.calls == []


def test_promoted_legacy_requests_execute_with_an_injected_safe_scanner():
    class FakeLegacyScanner:
        def __init__(self):
            self.vulnerabilities = []

        def check_firewall(self):
            pass

        def check_uac(self):
            pass

        def check_bitlocker_status(self):
            pass

        def check_smb_protocol(self):
            pass

    runtimes = legacy_scanner_adapters(FakeLegacyScanner)[1:]
    capabilities = TargetCapabilities(
        frozenset({ScannerCapability("windows.registry.read"), ScannerCapability("windows.powershell")})
    )

    result = _orchestrator(*runtimes, capabilities=capabilities).run(
        TARGET,
        ("windows.uac", "windows.bitlocker", "windows.smb"),
    )

    assert [item.status for item in result.scanner_results] == [ScannerExecutionStatus.SUCCESS] * 3


def test_scanner_failure_does_not_fail_completed_orchestration_or_discard_successes():
    successful = FakeRuntime(FIREWALL_MANIFEST, _success())
    failed_manifest = ScannerManifest("windows.other", "Other", "Test scanner", "Other", "1.0")
    failed = FakeRuntime(failed_manifest, error=RuntimeError("scanner failed"))

    result = _orchestrator(successful, failed).run(TARGET, ("windows.firewall", "windows.other"))

    assert result.status is AssessmentStatus.COMPLETED
    assert [item.status for item in result.scanner_results] == [
        ScannerExecutionStatus.SUCCESS,
        ScannerExecutionStatus.FAILED,
    ]
    assert result.scanner_results[1].error == "scanner failed"


def test_selection_none_keeps_the_use_case_on_the_legacy_runner_path():
    class LegacyRunner:
        def __init__(self):
            self.calls = []

        def resolve_target(self):
            return TARGET

        def run(self, target, options=None):
            self.calls.append((target, options))
            now = datetime.utcnow()
            return AssessmentResult("legacy", target, AssessmentStatus.COMPLETED, now, now)

    class Repository:
        def __init__(self):
            self.calls = []

        def create_assessment(self, assessment_id, scan_type, target, started_at):
            self.calls.append("create")

        def persist_completed(self, result):
            self.calls.append("complete")

        def mark_failed(self, assessment_id, finished_at, error):
            self.calls.append("failed")

    runner = LegacyRunner()
    repository = Repository()
    use_case = RunLocalAssessment(runner, repository)
    assessment_id, target = use_case.start("full")

    result = use_case.execute(assessment_id, target, AssessmentOptions())

    assert result.status is AssessmentStatus.COMPLETED
    assert runner.calls == [(TARGET, None)]
    assert repository.calls == ["create", "complete"]
