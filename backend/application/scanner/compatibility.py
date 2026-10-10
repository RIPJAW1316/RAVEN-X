"""Single compatibility evaluation path for local scanner manifests."""

from ...domain.assessment import AssessmentTarget
from ...domain.scanner import (
    CapabilityAvailability,
    CompatibilityResult,
    CompatibilityStatus,
    ScannerManifest,
    TargetCapabilities,
)


def evaluate_compatibility(
    manifest: ScannerManifest,
    target: AssessmentTarget,
    target_capabilities: TargetCapabilities,
) -> CompatibilityResult:
    """Evaluate technical target support independently from implementation state."""
    reasons = []
    if target.platform not in manifest.supported_platforms:
        reasons.append(f"platform {target.platform!r} is unsupported")

    missing = sorted(
        capability.value
        for capability in manifest.required_capabilities
        if target_capabilities.availability_for(capability) is CapabilityAvailability.UNSUPPORTED
    )
    unknown = sorted(
        capability.value
        for capability in manifest.required_capabilities
        if target_capabilities.availability_for(capability) is CapabilityAvailability.UNKNOWN
    )
    reasons.extend(f"required capability unavailable: {capability}" for capability in missing)
    reasons.extend(f"required capability could not be determined: {capability}" for capability in unknown)

    if reasons and (target.platform not in manifest.supported_platforms or missing):
        status = CompatibilityStatus.INCOMPATIBLE
    elif unknown:
        status = CompatibilityStatus.UNKNOWN
    else:
        status = CompatibilityStatus.COMPATIBLE

    return CompatibilityResult(
        scanner_id=manifest.scanner_id,
        status=status,
        reasons=tuple(reasons),
    )
