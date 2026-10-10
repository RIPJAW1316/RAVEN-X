"""Local scanner runtime registry and adapters."""

from .compatibility import evaluate_compatibility
from .local_capabilities import LocalTargetCapabilityProvider, StaticTargetCapabilityProvider
from .registry import ScannerRegistry


def __getattr__(name):
    if name == "legacy_scanner_adapters":
        # The personal desktop scanner is loaded only for callers that
        # explicitly request the legacy adapter. Endpoint service startup
        # uses the separate read-only Windows scanner module.
        from .legacy_adapters import legacy_scanner_adapters
        globals()[name] = legacy_scanner_adapters
        return legacy_scanner_adapters
    raise AttributeError(name)

__all__ = [
    "LocalTargetCapabilityProvider",
    "StaticTargetCapabilityProvider",
    "ScannerRegistry",
    "evaluate_compatibility",
    "legacy_scanner_adapters",
]
