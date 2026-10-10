from datetime import datetime, timezone

import scanner as legacy

from backend.application.scanner.legacy_adapters import (
    UAC_MANIFEST, SMB_MANIFEST, BITLOCKER_MANIFEST, LegacyMethodScannerAdapter,
)
from backend.domain.assessment import AssessmentTarget
from backend.domain.scanner import ScannerCapability, ScannerExecutionStatus, ExecutionCompleteness


TARGET = AssessmentTarget("target", "host", "Windows")


def _caps(manifest):
    return __import__("backend.domain.scanner", fromlist=["TargetCapabilities"]).TargetCapabilities(
        frozenset(manifest.required_capabilities))


class FakeUac:
    def __init__(self, fail=False, insecure=False):
        self.vulnerabilities = []
        self.fail = fail
        self.insecure = insecure

    def _reg_read(self, hive, path, key):
        if self.fail:
            raise OSError("registry unavailable")
        return 1 if self.insecure and key == "ConsentPromptBehaviorAdmin" else (0 if self.insecure else (2 if key == "ConsentPromptBehaviorAdmin" else 1))

    def check_uac(self):
        try:
            consent = self._reg_read(None, "policy", "ConsentPromptBehaviorAdmin")
            desktop = self._reg_read(None, "policy", "PromptOnSecureDesktop")
        except Exception:
            return
        if consent != 2 or desktop != 1:
            self.vulnerabilities.append({"severity": "high", "category": "UAC", "title": "UAC insecure",
                                         "details": "policy is not secure", "component": "UAC"})


def test_uac_secure_path_is_complete_and_empty():
    result = LegacyMethodScannerAdapter(UAC_MANIFEST, "check_uac", lambda: FakeUac()).execute(TARGET, _caps(UAC_MANIFEST))
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert result.findings == ()
    assert result.execution_evidence.completeness is ExecutionCompleteness.COMPLETE
    assert result.execution_evidence.rules_completed == ("uac.configuration",)


def test_uac_registry_failure_is_not_secure_empty():
    result = LegacyMethodScannerAdapter(UAC_MANIFEST, "check_uac", lambda: FakeUac(fail=True)).execute(TARGET, _caps(UAC_MANIFEST))
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "REGISTRY_READ_FAILED"
    assert result.execution_evidence.completeness is ExecutionCompleteness.PARTIAL


def test_uac_insecure_path_emits_identity_metadata():
    result = LegacyMethodScannerAdapter(UAC_MANIFEST, "check_uac", lambda: FakeUac(insecure=True)).execute(TARGET, _caps(UAC_MANIFEST))
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert result.findings[0].metadata["rule_id"] == "uac.configuration"


class FakePowerShell:
    __module__ = legacy.__name__

    def __init__(self, scanner_id, value):
        self.vulnerabilities = []
        self.value = value

    def check_smb_protocol(self):
        value = legacy.run_ps("smb")
        if isinstance(value, dict) and value.get("EnableSMB1Protocol"):
            self.vulnerabilities.append({"severity": "critical", "category": "SMB", "title": "SMBv1", "details": "enabled", "component": "SMB"})

    def check_bitlocker_status(self):
        value = legacy.run_ps("bitlocker")
        if isinstance(value, dict) and value.get("VolumeStatus") != "FullyEncrypted":
            self.vulnerabilities.append({"severity": "high", "category": "BitLocker", "title": "Not encrypted", "details": "C:", "component": "BitLocker"})


def test_smb_command_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(legacy, "run_ps", lambda *args, **kwargs: None)
    result = LegacyMethodScannerAdapter(SMB_MANIFEST, "check_smb_protocol", lambda: FakePowerShell("smb", None)).execute(TARGET, _caps(SMB_MANIFEST))
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "COMMAND_FAILED"


def test_bitlocker_parse_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(legacy, "run_ps", lambda *args, **kwargs: {"unexpected": True})
    result = LegacyMethodScannerAdapter(BITLOCKER_MANIFEST, "check_bitlocker_status", lambda: FakePowerShell("bitlocker", None)).execute(TARGET, _caps(BITLOCKER_MANIFEST))
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "OUTPUT_PARSE_FAILED"
