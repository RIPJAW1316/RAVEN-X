"""Registry-driven local scanner selection, separate from the legacy full scan."""

from datetime import datetime
import uuid
from typing import Callable, Tuple

from ...application.scanner.compatibility import evaluate_compatibility
from ...application.scanner.registry import ScannerRegistry
from ...domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget
from ...domain.scanner import (
    CompatibilityStatus,
    ScannerExecutionResult,
    ScannerExecutionStatus,
    ScannerImplementationStatus,
    TargetCapabilities,
)


CapabilityProvider = Callable[[AssessmentTarget], TargetCapabilities]


class LocalAssessmentOrchestrator:
    """Run an explicit scanner selection and aggregate its local results."""

    def __init__(self, registry: ScannerRegistry, capability_provider: CapabilityProvider):
        self._registry = registry
        self._capability_provider = capability_provider

    def run(self, target: AssessmentTarget, scanner_ids: Tuple[str, ...]) -> AssessmentResult:
        started_at = datetime.utcnow()
        assessment_id = str(uuid.uuid4())

        try:
            capabilities = self._capability_provider(target)
            scanner_results = tuple(
                self._execute_requested_scanner(scanner_id, target, capabilities)
                for scanner_id in scanner_ids
            )
            findings = tuple(
                finding
                for result in scanner_results
                # A registered local collector can confirm a violation before
                # another read fails. Preserve that evidence without changing
                # its FAILED status or incomplete coverage.
                if result.status in (ScannerExecutionStatus.SUCCESS, ScannerExecutionStatus.FAILED)
                for finding in result.findings
            )
            return AssessmentResult(
                assessment_id=assessment_id,
                target=target,
                status=AssessmentStatus.COMPLETED,
                started_at=started_at,
                finished_at=datetime.utcnow(),
                findings=findings,
                scanner_metadata={
                    "execution_path": "selected_scanners",
                    "requested_scanner_ids": scanner_ids,
                },
                scanner_results=scanner_results,
            )
        except Exception:
            return AssessmentResult(
                assessment_id=assessment_id,
                target=target,
                status=AssessmentStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.utcnow(),
                error="local assessment execution failed",
            )

    def _execute_requested_scanner(
        self,
        scanner_id: str,
        target: AssessmentTarget,
        capabilities: TargetCapabilities,
    ) -> ScannerExecutionResult:
        started_at = datetime.utcnow()
        scanner = self._registry.get(scanner_id)
        if scanner is None:
            return ScannerExecutionResult(
                scanner_id=scanner_id,
                status=ScannerExecutionStatus.SKIPPED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="scanner is not registered",
            )

        compatibility = evaluate_compatibility(scanner.manifest, target, capabilities)
        if compatibility.status is not CompatibilityStatus.COMPATIBLE:
            return ScannerExecutionResult(
                scanner_id=scanner_id,
                status=ScannerExecutionStatus.INCOMPATIBLE,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="; ".join(compatibility.reasons),
            )
        if scanner.manifest.status is not ScannerImplementationStatus.AVAILABLE:
            return ScannerExecutionResult(
                scanner_id=scanner_id,
                status=ScannerExecutionStatus.SKIPPED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="scanner is legacy-only and has no independent runtime adapter",
            )

        try:
            return scanner.execute(target, capabilities)
        except Exception:
            return ScannerExecutionResult(
                scanner_id=scanner_id,
                status=ScannerExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="local scanner execution failed",
            )
