"""Explicit mapping from assessment-domain data to existing ORM models."""

from datetime import datetime
from typing import Any, Dict, Mapping

from ...core.database.models import Scan, Vulnerability
from ...domain.assessment import AssessmentResult, AssessmentTarget, Finding, FindingSeverity


def target_system_info(target: AssessmentTarget) -> Dict[str, Any]:
    """Represent the minimal target contract in the existing Scan JSON field."""
    return {
        "hostname": target.hostname,
        "platform": target.platform,
        "platform_version": target.platform_version,
        **dict(target.metadata),
    }


def scan_from_target(assessment_id: str, scan_type: str, target: AssessmentTarget, started_at: datetime) -> Scan:
    return Scan(
        id=assessment_id,
        scan_type=scan_type,
        start_time=started_at,
        status="running",
        system_info=target_system_info(target),
    )


def vulnerability_from_finding(assessment_id: str, finding: Finding) -> Vulnerability:
    """Map supported finding data without making ORM objects executable."""
    return Vulnerability(
        scan_id=assessment_id,
        severity=finding.severity.value,
        category=finding.category,
        title=finding.title,
        details=finding.details,
        component=finding.component,
        remediation=finding.remediation,
        powershell_command=finding.legacy_metadata.get("powershell_command"),
    )


def _risk_score(findings: tuple[Finding, ...]) -> tuple[float, str]:
    """Preserve the existing local/backend severity-weight calculation."""
    if not findings:
        return 0.0, "Low Risk"

    weights = {
        FindingSeverity.CRITICAL: 10,
        FindingSeverity.HIGH: 7,
        FindingSeverity.MEDIUM: 4,
        FindingSeverity.LOW: 1,
    }
    score = sum(weights.get(finding.severity, 0) for finding in findings)
    percentage = round(score / (len(findings) * 10) * 100, 1)
    if percentage >= 70:
        return percentage, "Critical Risk"
    if percentage >= 40:
        return percentage, "High Risk"
    if percentage >= 20:
        return percentage, "Medium Risk"
    return percentage, "Low Risk"


def apply_completed_result(scan: Scan, result: AssessmentResult) -> None:
    """Update an existing Scan using one completed domain result."""
    if result.finished_at is None:
        raise ValueError("completed result requires finished_at")

    runtime_info = result.scanner_metadata.get("system_info", {})
    system_info = dict(scan.system_info or {})
    if isinstance(runtime_info, Mapping):
        system_info.update(runtime_info)
    normalization_issues = result.scanner_metadata.get("normalization_issues", ())
    if normalization_issues:
        system_info["normalization_issue_count"] = len(normalization_issues)
        system_info["normalization_issue_reasons"] = [issue.reason for issue in normalization_issues]

    risk_score, risk_level = _risk_score(result.findings)
    scan.system_info = system_info
    scan.end_time = result.finished_at
    scan.duration_seconds = (result.finished_at - result.started_at).total_seconds()
    scan.status = "completed"
    scan.total_vulnerabilities = len(result.findings)
    scan.critical_count = sum(f.severity is FindingSeverity.CRITICAL for f in result.findings)
    scan.high_count = sum(f.severity is FindingSeverity.HIGH for f in result.findings)
    scan.medium_count = sum(f.severity is FindingSeverity.MEDIUM for f in result.findings)
    scan.low_count = sum(f.severity is FindingSeverity.LOW for f in result.findings)
    scan.risk_score = risk_score
    scan.risk_level = risk_level
