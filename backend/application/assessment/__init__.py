"""Assessment application services.

The package keeps scanner-backed services lazy so importing the control-plane
composition does not import the optional Windows desktop scanner (or its GUI
dependencies).  Public names remain compatible with earlier callers.
"""

from importlib import import_module

_EXPORTS = {
    "AssessmentRunner": (".runner", "AssessmentRunner"),
    "AssessmentOptions": (".options", "AssessmentOptions"),
    "LocalAssessmentOrchestrator": (".local_orchestrator", "LocalAssessmentOrchestrator"),
    "LocalAssessmentRunner": (".local_runner", "LocalAssessmentRunner"),
    "NormalizationIssue": (".normalizer", "NormalizationIssue"),
    "normalize_legacy_finding": (".normalizer", "normalize_legacy_finding"),
    "normalize_legacy_findings": (".normalizer", "normalize_legacy_findings"),
    "RunLocalAssessment": (".run_local_assessment", "RunLocalAssessment"),
    "TenantAssessmentService": (".tenant_service", "TenantAssessmentService"),
}


def __getattr__(name):
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value

__all__ = [
    *_EXPORTS,
]
