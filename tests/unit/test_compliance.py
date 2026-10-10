from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

from backend.domain.compliance import ComplianceStatus, ComplianceReason, ravenx_windows_baseline_registry
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.application.compliance import ComplianceControlEvaluator

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def endpoint(platform="Windows"):
    return Endpoint(EndpointId.new(), "host", PlatformInfo(platform), created_at=NOW)


def test_registry_is_curated_and_versioned():
    registry = ravenx_windows_baseline_registry()
    framework = registry.framework("ravenx.windows.baseline")
    assert framework.version == "1"
    assert len(registry.controls_for(framework.framework_id)) == 4


def test_observed_finding_is_non_compliant():
    control = ravenx_windows_baseline_registry().control("RX-WIN-SMB-001")
    assessment = SimpleNamespace(assessment_id="a1", state="completed", completed_at=NOW,
        result={"findings": [{"metadata": {"scanner_id": "windows.smb", "rule_id": "smb.smb1_enabled"}}], "scanner_results": []})
    result = ComplianceControlEvaluator(clock=lambda: NOW).evaluate(control, endpoint(), [assessment])
    assert result.status is ComplianceStatus.NON_COMPLIANT
    assert result.reason_code is ComplianceReason.FINDING_OBSERVED


def test_absence_with_unknown_coverage_is_not_compliant():
    control = ravenx_windows_baseline_registry().control("RX-WIN-UAC-001")
    assessment = SimpleNamespace(assessment_id="a1", state="completed", completed_at=NOW,
        result={"findings": [], "scanner_results": [{"scanner_id": "windows.uac", "status": "success"}]})
    result = ComplianceControlEvaluator(clock=lambda: NOW).evaluate(control, endpoint(), [assessment])
    assert result.status is ComplianceStatus.UNKNOWN
    assert result.reason_code is ComplianceReason.COVERAGE_UNKNOWN


def test_stale_evidence_is_unknown_and_non_windows_is_not_applicable():
    control = ravenx_windows_baseline_registry().control("RX-WIN-FW-001")
    stale = SimpleNamespace(assessment_id="a1", state="completed", completed_at=NOW - timedelta(days=2), result={"findings": [], "scanner_results": []})
    assert ComplianceControlEvaluator(clock=lambda: NOW).evaluate(control, endpoint(), [stale]).reason_code is ComplianceReason.STALE_EVIDENCE
    assert ComplianceControlEvaluator(clock=lambda: NOW).evaluate(control, endpoint("Linux"), []).status is ComplianceStatus.NOT_APPLICABLE
