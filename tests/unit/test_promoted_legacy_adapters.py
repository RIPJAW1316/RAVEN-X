"""Promoted legacy checks execute only through mocked narrow adapters."""

import json
from pathlib import Path

import pytest

from backend.application.scanner.legacy_adapters import (
    BITLOCKER_MANIFEST,
    SMB_MANIFEST,
    UAC_MANIFEST,
    LegacyMethodScannerAdapter,
)
from backend.domain.assessment import AssessmentTarget
from backend.domain.scanner import ScannerExecutionStatus, TargetCapabilities


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_firewall_finding.json"
TARGET = AssessmentTarget("local:promoted", "test-host", "Windows")
PROMOTED = (
    (UAC_MANIFEST, "check_uac"),
    (BITLOCKER_MANIFEST, "check_bitlocker_status"),
    (SMB_MANIFEST, "check_smb_protocol"),
)


def _capabilities(manifest):
    return TargetCapabilities(manifest.required_capabilities)


@pytest.mark.parametrize("manifest,method_name", PROMOTED)
def test_promoted_adapter_reuses_existing_normalizer_for_mocked_legacy_finding(manifest, method_name):
    finding = json.loads(FIXTURE.read_text(encoding="utf-8"))

    class FakeLegacyScanner:
        def __init__(self):
            self.vulnerabilities = []

    def check(self):
        self.vulnerabilities.append(finding)

    setattr(FakeLegacyScanner, method_name, check)
    result = LegacyMethodScannerAdapter(manifest, method_name, FakeLegacyScanner).execute(TARGET, _capabilities(manifest))

    assert result.scanner_id == manifest.scanner_id
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert result.findings[0].title == finding["title"]
    assert result.findings[0].legacy_metadata["powershell_command"] == finding["powershell_command"]


@pytest.mark.parametrize("manifest,method_name", PROMOTED)
def test_promoted_adapter_represents_zero_findings_without_platform_effects(manifest, method_name):
    class FakeLegacyScanner:
        def __init__(self):
            self.vulnerabilities = []

    setattr(FakeLegacyScanner, method_name, lambda self: None)
    result = LegacyMethodScannerAdapter(manifest, method_name, FakeLegacyScanner).execute(TARGET, _capabilities(manifest))

    assert result.status is ScannerExecutionStatus.SUCCESS
    assert result.findings == ()


@pytest.mark.parametrize("manifest,method_name", PROMOTED)
def test_promoted_adapter_represents_mocked_legacy_check_failure(manifest, method_name):
    class FakeLegacyScanner:
        def __init__(self):
            self.vulnerabilities = []

    def fail(self):
        raise RuntimeError("legacy check failed")

    setattr(FakeLegacyScanner, method_name, fail)
    result = LegacyMethodScannerAdapter(manifest, method_name, FakeLegacyScanner).execute(TARGET, _capabilities(manifest))

    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error == "legacy check failed"
