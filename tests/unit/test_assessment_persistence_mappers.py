"""Tests for explicit assessment-domain to ORM mapping."""

from datetime import datetime

from backend.application.assessment.normalizer import NormalizationIssue
from backend.domain.assessment import (
    AssessmentResult,
    AssessmentStatus,
    AssessmentTarget,
    Finding,
    FindingSeverity,
)
from backend.infrastructure.persistence.mappers import (
    apply_completed_result,
    scan_from_target,
    vulnerability_from_finding,
)


def _target():
    return AssessmentTarget("local:test", "test-host", "Windows", "Windows Test", {"architecture": "x64"})


def _finding(severity=FindingSeverity.HIGH):
    return Finding(
        finding_id="finding-1",
        severity=severity,
        category="Firewall",
        title="Windows Firewall Disabled",
        details="The public profile is disabled.",
        component="Windows Defender Firewall",
        remediation="Enable the firewall.",
        legacy_metadata={"powershell_command": "Set-NetFirewallProfile -Enabled True"},
    )


def test_target_and_finding_map_to_existing_orm_schema():
    started = datetime.utcnow()
    scan = scan_from_target("assessment-1", "full", _target(), started)
    vulnerability = vulnerability_from_finding("assessment-1", _finding())

    assert scan.status == "running"
    assert scan.system_info["hostname"] == "test-host"
    assert scan.system_info["architecture"] == "x64"
    assert vulnerability.scan_id == "assessment-1"
    assert vulnerability.severity == "high"
    assert vulnerability.powershell_command == "Set-NetFirewallProfile -Enabled True"


def test_unknown_severity_and_missing_optional_values_map_safely():
    finding = Finding(
        finding_id="finding-unknown",
        severity=FindingSeverity.UNKNOWN,
        category="Unknown",
        title="Unknown finding",
        details="No optional remediation data.",
        component="Unknown",
    )

    vulnerability = vulnerability_from_finding("assessment-2", finding)

    assert vulnerability.severity == "unknown"
    assert vulnerability.remediation is None
    assert vulnerability.powershell_command is None


def test_completed_result_preserves_existing_risk_calculation_and_issue_count():
    started = datetime.utcnow()
    scan = scan_from_target("assessment-3", "full", _target(), started)
    finished = datetime.utcnow()
    result = AssessmentResult(
        assessment_id="assessment-3",
        target=_target(),
        status=AssessmentStatus.COMPLETED,
        started_at=started,
        finished_at=finished,
        findings=(_finding(),),
        scanner_metadata={
            "system_info": {"hostname": "scanner-host"},
            "normalization_issues": (NormalizationIssue(0, "legacy finding must be a mapping", 7),),
        },
    )

    apply_completed_result(scan, result)

    assert scan.status == "completed"
    assert scan.risk_score == 70.0
    assert scan.risk_level == "Critical Risk"
    assert scan.system_info["hostname"] == "scanner-host"
    assert scan.system_info["normalization_issue_count"] == 1
