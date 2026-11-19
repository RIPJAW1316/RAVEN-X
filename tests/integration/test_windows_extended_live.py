"""Opt-in read-only command smoke test on a real Windows host."""

import os
import platform

import pytest

from backend.agent.windows_extended_checks import CHECKS
from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners
from backend.domain.assessment import AssessmentTarget
from backend.domain.scanner import ScannerCapability, ScannerExecutionStatus, TargetCapabilities


@pytest.mark.skipif(platform.system() != "Windows" or os.getenv("RAVENX_RUN_LIVE_READONLY") != "1",
                    reason="requires opt-in on a Windows host")
@pytest.mark.parametrize("scanner_id", CHECKS)
def test_read_only_extended_check_returns_structured_coverage(scanner_id):
    manifest = next(x.manifest for x in windows_read_only_scanners() if x.manifest.scanner_id == scanner_id)
    result = WindowsReadOnlyScanner(manifest).execute(
        AssessmentTarget("endpoint:local-smoke", "workstation", "Windows"),
        TargetCapabilities(frozenset({ScannerCapability("windows.powershell")})),
    )
    print(f"{scanner_id}: {result.status.value}, findings={len(result.findings)}")
    assert result.status in (ScannerExecutionStatus.SUCCESS, ScannerExecutionStatus.INCOMPATIBLE)
