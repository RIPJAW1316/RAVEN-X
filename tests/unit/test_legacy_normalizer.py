"""Deterministic compatibility tests for legacy finding normalization."""

import json
from pathlib import Path

import pytest

from backend.application.assessment.normalizer import (
    MalformedLegacyFindingError,
    normalize_legacy_finding,
    normalize_legacy_findings,
)
from backend.domain.assessment import FindingSeverity


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_firewall_finding.json"


def test_seven_field_legacy_fixture_normalizes_without_losing_data():
    legacy = json.loads(FIXTURE.read_text(encoding="utf-8"))

    finding = normalize_legacy_finding(legacy)

    assert finding.severity is FindingSeverity.HIGH
    assert finding.category == legacy["category"]
    assert finding.title == legacy["title"]
    assert finding.details == legacy["details"]
    assert finding.component == legacy["component"]
    assert finding.remediation == legacy["remediation"]
    assert finding.legacy_metadata["powershell_command"] == legacy["powershell_command"]
    assert finding.evidence[0].description == legacy["details"]


def test_normalization_is_deterministic_for_same_legacy_finding():
    legacy = json.loads(FIXTURE.read_text(encoding="utf-8"))

    assert normalize_legacy_finding(legacy).finding_id == normalize_legacy_finding(legacy).finding_id


def test_unknown_severity_and_missing_optional_fields_are_explicit():
    finding = normalize_legacy_finding(
        {
            "severity": "urgent-but-unmapped",
            "category": "Network",
            "title": "Example",
            "details": "Example detail",
            "component": "Network stack",
        }
    )

    assert finding.severity is FindingSeverity.UNKNOWN
    assert finding.remediation is None
    assert finding.legacy_metadata == {}


def test_extra_legacy_fields_are_preserved_in_metadata():
    finding = normalize_legacy_finding(
        {
            "severity": "low",
            "category": "Network",
            "title": "Example",
            "details": "Example detail",
            "component": "Network stack",
            "collector_note": "Kept for future mapping",
        }
    )

    assert finding.metadata["extra_legacy_fields"] == {"collector_note": "Kept for future mapping"}


def test_malformed_finding_is_reported_without_discarding_other_findings():
    valid = json.loads(FIXTURE.read_text(encoding="utf-8"))
    findings, issues = normalize_legacy_findings([valid, "not a mapping"])

    assert len(findings) == 1
    assert issues[0].index == 1
    assert issues[0].raw_value == "not a mapping"

    with pytest.raises(MalformedLegacyFindingError):
        normalize_legacy_finding("not a mapping")
