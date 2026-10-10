"""Read-only local capability discovery for the modeled scanner catalog."""

from importlib.util import find_spec
from shutil import which
from typing import Callable, Optional, Tuple

from ...domain.assessment import AssessmentTarget
from ...domain.scanner import (
    CapabilityAvailability,
    CapabilityObservation,
    ScannerCapability,
    TargetCapabilities,
)


CommandLocator = Callable[[str], Optional[str]]
ModuleFinder = Callable[[str], object]


class LocalTargetCapabilityProvider:
    """Discover command/module availability without invoking a scanner or command."""

    def __init__(self, command_locator: CommandLocator = which, module_finder: ModuleFinder = find_spec):
        self._command_locator = command_locator
        self._module_finder = module_finder

    def capabilities_for(self, target: AssessmentTarget) -> TargetCapabilities:
        return self.discover(target)

    def discover(self, target: AssessmentTarget) -> TargetCapabilities:
        capabilities = []
        observations = []
        checks: Tuple[Tuple[ScannerCapability, str, str, Callable[[str], object]], ...] = (
            (ScannerCapability("windows.firewall.read"), "command", "netsh", self._command_locator),
            (ScannerCapability("windows.registry.read"), "module", "winreg", self._module_finder),
            (ScannerCapability("windows.powershell"), "command", "powershell.exe", self._command_locator),
        )

        for capability, kind, probe_name, probe in checks:
            if target.platform.lower() != "windows":
                observations.append(
                    CapabilityObservation(
                        capability,
                        CapabilityAvailability.UNSUPPORTED,
                        "target.platform",
                        f"{target.platform} is not supported by this Windows runtime",
                    )
                )
                continue
            try:
                available = bool(probe(probe_name))
            except Exception as error:
                observations.append(
                    CapabilityObservation(
                        capability,
                        CapabilityAvailability.UNKNOWN,
                        f"{kind}:{probe_name}",
                        f"capability discovery failed: {error}",
                    )
                )
                continue

            availability = CapabilityAvailability.SUPPORTED if available else CapabilityAvailability.UNSUPPORTED
            if available:
                capabilities.append(capability)
            observations.append(
                CapabilityObservation(
                    capability,
                    availability,
                    f"{kind}:{probe_name}",
                    "availability probe succeeded" if available else "availability probe found no support",
                )
            )

        return TargetCapabilities(frozenset(capabilities), tuple(observations))


class StaticTargetCapabilityProvider:
    """Explicit test/controlled-environment fallback; never selected implicitly."""

    def __init__(self, capabilities: TargetCapabilities):
        self._capabilities = capabilities

    def capabilities_for(self, target: AssessmentTarget) -> TargetCapabilities:
        return self._capabilities
