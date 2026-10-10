"""Scanner-runtime contracts, registry, and legacy-adapter tests."""

import json
from pathlib import Path

import pytest

from backend.application.scanner.compatibility import evaluate_compatibility
from backend.application.scanner.legacy_adapters import (
    BITLOCKER_MANIFEST,
    FIREWALL_MANIFEST,
    SMB_MANIFEST,
    UAC_MANIFEST,
    LegacyMethodScannerAdapter,
    legacy_scanner_adapters,
)
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import AssessmentTarget
from backend.domain.scanner import (
    CompatibilityStatus,
    ScannerCapability,
    ScannerExecutionStatus,
    ScannerImplementationStatus,
    ScannerManifest,
    TargetCapabilities,
)


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_firewall_finding.json"
TARGET = AssessmentTarget("local:test", "test-host", "Windows")
FIREWALL_CAPABILITIES = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")}))


def test_manifest_has_stable_identity_capabilities_and_status():
    assert FIREWALL_MANIFEST.scanner_id == "windows.firewall"
    assert FIREWALL_MANIFEST.required_capabilities == frozenset({ScannerCapability("windows.firewall.read")})
    assert FIREWALL_MANIFEST.status is ScannerImplementationStatus.AVAILABLE
    assert UAC_MANIFEST.status is ScannerImplementationStatus.AVAILABLE
    assert BITLOCKER_MANIFEST.status is ScannerImplementationStatus.AVAILABLE
    assert SMB_MANIFEST.status is ScannerImplementationStatus.AVAILABLE


def test_manifest_and_capability_reject_invalid_machine_identifiers():
    with pytest.raises(ValueError):
        ScannerManifest("Windows Firewall", "Firewall", "desc", "Firewall", "1.0")
    with pytest.raises(ValueError):
        ScannerCapability("Windows.Registry.Read")


def test_target_capabilities_support_and_missing_capability():
    assert FIREWALL_CAPABILITIES.supports(ScannerCapability("windows.firewall.read"))
    assert not FIREWALL_CAPABILITIES.supports(ScannerCapability("windows.registry.read"))


def test_compatibility_is_explicit_and_preserves_missing_capability_reason():
    compatible = evaluate_compatibility(FIREWALL_MANIFEST, TARGET, FIREWALL_CAPABILITIES)
    incompatible = evaluate_compatibility(FIREWALL_MANIFEST, TARGET, TargetCapabilities())

    assert compatible.status is CompatibilityStatus.COMPATIBLE
    assert incompatible.status is CompatibilityStatus.INCOMPATIBLE
    assert incompatible.reasons == ("required capability unavailable: windows.firewall.read",)


def test_registry_registers_looks_up_and_filters_executable_scanners():
    adapters = legacy_scanner_adapters()
    registry = ScannerRegistry(adapters)

    assert registry.get("windows.firewall") is adapters[0]
    assert {scanner.manifest.scanner_id for scanner in registry.list()} == {
        "windows.firewall",
        "windows.uac",
        "windows.bitlocker",
        "windows.smb",
    }
    assert [scanner.manifest.scanner_id for scanner in registry.list_compatible(TARGET, FIREWALL_CAPABILITIES)] == [
        "windows.firewall"
    ]

    with pytest.raises(ValueError, match="already registered"):
        registry.register(adapters[0])


def test_promoted_scanner_is_technically_compatible_and_executable_without_host_access():
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

    registry = ScannerRegistry(legacy_scanner_adapters(FakeLegacyScanner))
    capabilities = TargetCapabilities(frozenset({ScannerCapability("windows.registry.read")}))

    compatibility = evaluate_compatibility(UAC_MANIFEST, TARGET, capabilities)
    executable = registry.list_compatible(TARGET, capabilities)
    execution = registry.get("windows.uac").execute(TARGET, capabilities)

    assert compatibility.status is CompatibilityStatus.COMPATIBLE
    assert "windows.uac" in [scanner.manifest.scanner_id for scanner in executable]
    assert execution.status is ScannerExecutionStatus.SUCCESS


def test_firewall_adapter_normalizes_mocked_legacy_finding_without_platform_effects():
    legacy_finding = json.loads(FIXTURE.read_text(encoding="utf-8"))

    class FakeLegacyScanner:
        def __init__(self):
            self.vulnerabilities = []

        def check_firewall(self):
            self.vulnerabilities.append(legacy_finding)

    adapter = LegacyMethodScannerAdapter(FIREWALL_MANIFEST, "check_firewall", FakeLegacyScanner)
    result = adapter.execute(TARGET, FIREWALL_CAPABILITIES)

    assert result.status is ScannerExecutionStatus.SUCCESS
    assert result.findings[0].title == legacy_finding["title"]
    assert result.findings[0].legacy_metadata["powershell_command"] == legacy_finding["powershell_command"]
    assert result.native_metrics == {"findings_produced": 1, "normalization_issue_count": 0}


def test_adapter_returns_incompatible_or_failed_without_side_effects():
    factory_calls = []

    class ExplodingScanner:
        def __init__(self):
            factory_calls.append("created")
            self.vulnerabilities = []

        def check_firewall(self):
            raise RuntimeError("scanner failure")

    adapter = LegacyMethodScannerAdapter(FIREWALL_MANIFEST, "check_firewall", ExplodingScanner)
    incompatible = adapter.execute(TARGET, TargetCapabilities())
    failed = adapter.execute(TARGET, FIREWALL_CAPABILITIES)

    assert incompatible.status is ScannerExecutionStatus.INCOMPATIBLE
    assert factory_calls == ["created"]
    assert failed.status is ScannerExecutionStatus.FAILED
    assert failed.error == "scanner failure"
