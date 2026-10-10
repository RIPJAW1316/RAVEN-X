"""Tests for pure local assessment-domain contracts."""

from datetime import datetime
import ast
from pathlib import Path

import pytest

from backend.domain.assessment import (
    AssessmentResult,
    AssessmentStatus,
    AssessmentTarget,
    Evidence,
    Finding,
    FindingSeverity,
)


def test_target_requires_local_identity_fields():
    with pytest.raises(ValueError, match="hostname"):
        AssessmentTarget(target_id="local:test", hostname="", platform="Windows")


def test_domain_contracts_only_import_standard_library_modules():
    source_path = Path(__file__).resolve().parents[2] / "backend" / "domain" / "assessment" / "models.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert imported_roots <= {"dataclasses", "datetime", "enum", "typing"}


def test_severity_parsing_handles_known_and_unknown_legacy_values():
    assert FindingSeverity.from_legacy("HIGH") is FindingSeverity.HIGH
    assert FindingSeverity.from_legacy("informational") is FindingSeverity.UNKNOWN
    assert FindingSeverity.from_legacy(None) is FindingSeverity.UNKNOWN


def test_evidence_and_finding_are_data_only_contracts():
    evidence = Evidence(source="legacy.scanner", description="Public profile is off.", observed_value="OFF")
    finding = Finding(
        finding_id="finding-1",
        severity=FindingSeverity.HIGH,
        category="Firewall",
        title="Windows Firewall Disabled",
        details="Public profile is off.",
        component="Windows Defender Firewall",
        evidence=(evidence,),
    )

    assert finding.evidence[0].observed_value == "OFF"
    assert not hasattr(finding, "execute")


def test_completed_and_failed_results_have_explicit_state():
    target = AssessmentTarget(target_id="local:test", hostname="test", platform="Windows")
    finished = datetime.utcnow()
    completed = AssessmentResult(
        assessment_id="assessment-1",
        target=target,
        status=AssessmentStatus.COMPLETED,
        started_at=finished,
        finished_at=finished,
    )
    failed = AssessmentResult(
        assessment_id="assessment-2",
        target=target,
        status=AssessmentStatus.FAILED,
        started_at=finished,
        finished_at=finished,
        error="scanner unavailable",
    )

    assert completed.succeeded is True
    assert failed.succeeded is False


def test_result_rejects_invalid_terminal_state():
    target = AssessmentTarget(target_id="local:test", hostname="test", platform="Windows")
    with pytest.raises(ValueError, match="require finished_at"):
        AssessmentResult(
            assessment_id="assessment-1",
            target=target,
            status=AssessmentStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )
