"""In-memory local scanner registry."""

from typing import Dict, Iterable, Optional, Protocol, Tuple

from ...domain.assessment import AssessmentTarget
from ...domain.scanner import (
    CompatibilityStatus,
    ScannerExecutionResult,
    ScannerImplementationStatus,
    ScannerManifest,
    TargetCapabilities,
)
from .compatibility import evaluate_compatibility


class ScannerRuntime(Protocol):
    manifest: ScannerManifest

    def execute(self, target: AssessmentTarget, target_capabilities: TargetCapabilities) -> ScannerExecutionResult:
        """Execute one local scanner through the runtime contract."""


class ScannerRegistry:
    def __init__(self, scanners: Iterable[ScannerRuntime] = ()):
        self._scanners: Dict[str, ScannerRuntime] = {}
        for scanner in scanners:
            self.register(scanner)

    def register(self, scanner: ScannerRuntime) -> None:
        scanner_id = scanner.manifest.scanner_id
        if scanner_id in self._scanners:
            raise ValueError(f"scanner {scanner_id!r} is already registered")
        self._scanners[scanner_id] = scanner

    def get(self, scanner_id: str) -> Optional[ScannerRuntime]:
        return self._scanners.get(scanner_id)

    def list(self) -> Tuple[ScannerRuntime, ...]:
        return tuple(self._scanners.values())

    def list_compatible(
        self,
        target: AssessmentTarget,
        target_capabilities: TargetCapabilities,
    ) -> Tuple[ScannerRuntime, ...]:
        return tuple(
            scanner
            for scanner in self._scanners.values()
            if scanner.manifest.status is ScannerImplementationStatus.AVAILABLE
            and evaluate_compatibility(scanner.manifest, target, target_capabilities).status is CompatibilityStatus.COMPATIBLE
        )
