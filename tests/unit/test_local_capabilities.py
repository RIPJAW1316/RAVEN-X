"""Read-only local capability discovery and orchestration integration tests."""

from datetime import datetime

from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.scanner.compatibility import evaluate_compatibility
from backend.application.scanner.local_capabilities import (
    LocalTargetCapabilityProvider,
    StaticTargetCapabilityProvider,
)
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import AssessmentTarget
from backend.domain.scanner import (
    CapabilityAvailability,
    CapabilityObservation,
    CompatibilityStatus,
    ScannerCapability,
    ScannerExecutionResult,
    ScannerExecutionStatus,
    ScannerManifest,
    TargetCapabilities,
)


WINDOWS_TARGET = AssessmentTarget("local:capabilities", "test-host", "Windows")
NON_WINDOWS_TARGET = AssessmentTarget("local:capabilities", "test-host", "Linux")
FIREWALL = ScannerCapability("windows.firewall.read")
REGISTRY = ScannerCapability("windows.registry.read")
POWERSHELL = ScannerCapability("windows.powershell")


def test_windows_capability_discovery_uses_only_injected_read_only_availability_probes():
    command_calls = []
    module_calls = []

    provider = LocalTargetCapabilityProvider(
        command_locator=lambda command: command_calls.append(command) or f"C:/Windows/{command}",
        module_finder=lambda module: module_calls.append(module) or object(),
    )

    capabilities = provider.discover(WINDOWS_TARGET)

    assert capabilities.values == frozenset({FIREWALL, REGISTRY, POWERSHELL})
    assert command_calls == ["netsh", "powershell.exe"]
    assert module_calls == ["winreg"]
    assert all(observation.availability is CapabilityAvailability.SUPPORTED for observation in capabilities.observations)


def test_non_windows_target_is_conservatively_unsupported_without_running_probes():
    def probe_must_not_run(name):
        raise AssertionError(f"probe should not run: {name}")

    capabilities = LocalTargetCapabilityProvider(probe_must_not_run, probe_must_not_run).discover(NON_WINDOWS_TARGET)

    assert capabilities.values == frozenset()
    assert all(observation.availability is CapabilityAvailability.UNSUPPORTED for observation in capabilities.observations)
    assert all(observation.source == "target.platform" for observation in capabilities.observations)


def test_absent_windows_dependency_is_explicitly_unsupported():
    capabilities = LocalTargetCapabilityProvider(lambda command: None, lambda module: None).discover(WINDOWS_TARGET)

    assert capabilities.values == frozenset()
    assert capabilities.availability_for(FIREWALL) is CapabilityAvailability.UNSUPPORTED
    assert capabilities.availability_for(REGISTRY) is CapabilityAvailability.UNSUPPORTED
    assert capabilities.availability_for(POWERSHELL) is CapabilityAvailability.UNSUPPORTED


def test_discovery_failure_is_retained_as_unknown_not_supported():
    def command_locator(command):
        if command == "powershell.exe":
            raise RuntimeError("lookup denied")
        return "present"

    capabilities = LocalTargetCapabilityProvider(command_locator, lambda module: object()).discover(WINDOWS_TARGET)

    assert capabilities.supports(FIREWALL)
    assert capabilities.availability_for(POWERSHELL) is CapabilityAvailability.UNKNOWN
    assert "lookup denied" in next(item.reason for item in capabilities.observations if item.capability == POWERSHELL)


def test_unknown_discovered_capability_prevents_execution_and_preserves_the_reason():
    manifest = ScannerManifest(
        "windows.firewall",
        "Firewall",
        "Test firewall scanner",
        "Firewall",
        "1.0",
        frozenset({FIREWALL}),
    )

    class Runtime:
        def __init__(self, scanner_manifest):
            self.manifest = scanner_manifest
            self.calls = 0

        def execute(self, target, capabilities):
            self.calls += 1
            now = datetime.utcnow()
            return ScannerExecutionResult("windows.firewall", ScannerExecutionStatus.SUCCESS, now, now)

    runtime = Runtime(manifest)
    capabilities = TargetCapabilities(
        observations=(
            CapabilityObservation(FIREWALL, CapabilityAvailability.UNKNOWN, "test", "lookup failed"),
        )
    )
    compatibility = evaluate_compatibility(manifest, WINDOWS_TARGET, capabilities)
    result = LocalAssessmentOrchestrator(ScannerRegistry((runtime,)), lambda target: capabilities).run(
        WINDOWS_TARGET,
        ("windows.firewall",),
    )

    assert compatibility.status is CompatibilityStatus.UNKNOWN
    assert result.scanner_results[0].status is ScannerExecutionStatus.INCOMPATIBLE
    assert result.scanner_results[0].error == "required capability could not be determined: windows.firewall.read"
    assert runtime.calls == 0


def test_capability_provider_exception_is_an_explicit_orchestration_failure():
    result = LocalAssessmentOrchestrator(ScannerRegistry(), lambda target: (_ for _ in ()).throw(RuntimeError("discovery failed"))).run(
        WINDOWS_TARGET,
        (),
    )

    assert result.error == "local assessment execution failed"
    assert result.finished_at is not None


def test_static_capability_provider_is_explicit_and_injectable():
    expected = TargetCapabilities(frozenset({FIREWALL}))

    assert StaticTargetCapabilityProvider(expected).capabilities_for(WINDOWS_TARGET) == expected
