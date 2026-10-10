"""Thin local adapter over the existing personal-mode scanner."""

from datetime import datetime
import platform
import socket
import uuid
from typing import Any, Callable, Mapping, Optional

from scanner import VulnerabilityScanner

from ...domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget
from .normalizer import normalize_legacy_findings


class LocalAssessmentRunner:
    """Run the unchanged legacy scanner and return normalized domain results."""

    def __init__(self, scanner_factory: Callable[[], Any] = VulnerabilityScanner):
        self._scanner_factory = scanner_factory

    def resolve_target(self) -> AssessmentTarget:
        """Describe the local host without assigning enterprise identity."""
        hostname = socket.gethostname()
        return AssessmentTarget(
            target_id=f"local:{hostname}",
            hostname=hostname,
            platform=platform.system() or "Windows",
            platform_version=platform.version() or None,
        )

    def run(
        self,
        target: Optional[AssessmentTarget] = None,
        options: Optional[Mapping[str, object]] = None,
    ) -> AssessmentResult:
        """Invoke ``VulnerabilityScanner.scan_all`` without persistence or remediation."""
        started_at = datetime.utcnow()
        assessment_id = str(uuid.uuid4())
        resolved_target = target or self.resolve_target()
        options = options or {}

        try:
            scanner = self._scanner_factory()
            findings = scanner.scan_all(progress_callback=options.get("progress_callback"))
            if not isinstance(findings, (list, tuple)):
                raise TypeError("legacy scanner returned a non-sequence finding result")

            normalized_findings, normalization_issues = normalize_legacy_findings(findings)
            scanner_metadata = {
                "legacy_scanner": scanner.__class__.__name__,
                "system_info": getattr(scanner, "system_info", {}),
                "normalization_issues": normalization_issues,
            }
            return AssessmentResult(
                assessment_id=assessment_id,
                target=resolved_target,
                status=AssessmentStatus.COMPLETED,
                started_at=started_at,
                finished_at=datetime.utcnow(),
                findings=normalized_findings,
                scanner_metadata=scanner_metadata,
            )
        except Exception as error:
            return AssessmentResult(
                assessment_id=assessment_id,
                target=resolved_target,
                status=AssessmentStatus.FAILED,
                started_at=started_at,
                finished_at=datetime.utcnow(),
                error=str(error),
            )
