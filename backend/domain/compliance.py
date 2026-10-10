"""Pure, conservative compliance/GRC contracts."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class ComplianceEvaluationCapability(str, Enum):
    FULL = "full"
    DETECTION_ONLY = "detection_only"
    UNSUPPORTED = "unsupported"


class ComplianceReason(str, Enum):
    EVIDENCE_SATISFIED = "evidence_satisfied"
    FINDING_OBSERVED = "finding_observed"
    SCANNER_NOT_RUN = "scanner_not_run"
    SCANNER_FAILED = "scanner_failed"
    COVERAGE_UNKNOWN = "coverage_unknown"
    STALE_EVIDENCE = "stale_evidence"
    ASSESSMENT_INCOMPLETE = "assessment_incomplete"
    ENDPOINT_NOT_APPLICABLE = "endpoint_not_applicable"
    CONTROL_UNSUPPORTED = "control_unsupported"


@dataclass(frozen=True)
class ComplianceFramework:
    framework_id: str
    name: str
    version: str
    description: str
    control_ids: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.framework_id.strip() or not self.name.strip() or not self.version.strip():
            raise ValueError("framework identity fields are required")
        if len(set(self.control_ids)) != len(self.control_ids): raise ValueError("duplicate control IDs")

    def to_dict(self):
        return {"framework_id": self.framework_id, "name": self.name, "version": self.version,
                "description": self.description, "control_ids": list(self.control_ids)}


@dataclass(frozen=True)
class ControlEvidenceRequirement:
    scanner_id: str
    rule_id: str
    resource_key: str | None = None
    minimum_coverage: str = "declared"

    def __post_init__(self):
        if not self.scanner_id.strip() or not self.rule_id.strip(): raise ValueError("scanner and rule are required")

    def to_dict(self):
        return {"scanner_id": self.scanner_id, "rule_id": self.rule_id,
                "resource_key": self.resource_key, "minimum_coverage": self.minimum_coverage}


@dataclass(frozen=True)
class ComplianceControl:
    control_id: str
    framework_id: str
    title: str
    description: str
    evidence_requirements: tuple[ControlEvidenceRequirement, ...]
    applicability_platform: str | None = "Windows"
    capability: ComplianceEvaluationCapability = ComplianceEvaluationCapability.DETECTION_ONLY

    def __post_init__(self):
        if not self.control_id.strip() or not self.framework_id.strip() or not self.title.strip(): raise ValueError("control identity fields are required")
        object.__setattr__(self, "capability", ComplianceEvaluationCapability(self.capability))
        if not self.evidence_requirements: raise ValueError("control requires evidence requirements")

    def to_dict(self):
        return {"control_id": self.control_id, "framework_id": self.framework_id, "title": self.title,
                "description": self.description, "applicability_platform": self.applicability_platform,
                "capability": self.capability.value,
                "evidence_requirements": [x.to_dict() for x in self.evidence_requirements]}


@dataclass(frozen=True)
class ControlEvaluation:
    control_id: str
    status: ComplianceStatus
    reason_code: ComplianceReason
    evaluated_at: datetime
    endpoint_id: str
    source_assessment_id: str | None = None
    source_finding_ids: tuple[str, ...] = ()
    evidence_summary: str = ""
    coverage_status: str = "unknown"
    evidence_age_seconds: float | None = None
    capability: ComplianceEvaluationCapability = ComplianceEvaluationCapability.DETECTION_ONLY

    def __post_init__(self):
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None: raise ValueError("evaluated_at must be timezone-aware")
        object.__setattr__(self, "status", ComplianceStatus(self.status)); object.__setattr__(self, "reason_code", ComplianceReason(self.reason_code)); object.__setattr__(self, "capability", ComplianceEvaluationCapability(self.capability))

    def to_dict(self):
        return {"control_id": self.control_id, "endpoint_id": self.endpoint_id, "status": self.status.value,
                "reason": self.reason_code.value, "evaluated_at": self.evaluated_at.astimezone(timezone.utc).isoformat(),
                "source_assessment_id": self.source_assessment_id, "source_finding_ids": list(self.source_finding_ids),
                "evidence_summary": self.evidence_summary, "coverage_status": self.coverage_status,
                "evidence_age_seconds": self.evidence_age_seconds, "capability": self.capability.value}


@dataclass(frozen=True)
class CompliancePostureSummary:
    framework_id: str
    framework_version: str
    organization_id: str
    evaluated_at: datetime
    endpoints_evaluated: int
    endpoints_examined: int
    evaluation_complete: bool
    controls_evaluated: int
    compliant: int
    non_compliant: int
    unknown: int
    not_applicable: int

    def to_dict(self):
        return {"framework_id": self.framework_id, "framework_version": self.framework_version,
                "organization_id": self.organization_id, "evaluated_at": self.evaluated_at.astimezone(timezone.utc).isoformat(),
                "endpoints_evaluated": self.endpoints_evaluated, "endpoints_examined": self.endpoints_examined,
                "evaluation_complete": self.evaluation_complete, "controls_evaluated": self.controls_evaluated,
                "compliant": self.compliant, "non_compliant": self.non_compliant,
                "unknown": self.unknown, "not_applicable": self.not_applicable}


class ComplianceFrameworkRegistry:
    def __init__(self, frameworks=(), controls=()):
        self._frameworks = {}; self._controls = {}
        for framework in frameworks: self.register_framework(framework)
        for control in controls: self.register_control(control)

    def register_framework(self, framework):
        if framework.framework_id in self._frameworks: raise ValueError("duplicate framework ID")
        self._frameworks[framework.framework_id] = framework

    def register_control(self, control):
        if control.control_id in self._controls: raise ValueError("duplicate control ID")
        if control.framework_id not in self._frameworks: raise ValueError("control framework is not registered")
        self._controls[control.control_id] = control

    def framework(self, framework_id): return self._frameworks.get(str(framework_id))
    def control(self, control_id): return self._controls.get(str(control_id))
    def frameworks(self): return tuple(self._frameworks.values())
    def controls_for(self, framework_id): return tuple(x for x in self._controls.values() if x.framework_id == str(framework_id))


def ravenx_windows_baseline_registry():
    framework = ComplianceFramework("ravenx.windows.baseline", "Raven-X Windows Security Baseline", "1", "Raven-X-authored technical posture controls; not a certification.")
    controls = (
        ComplianceControl("RX-WIN-FW-001", framework.framework_id, "Windows firewall profiles evaluated", "Windows Defender Firewall profiles are evaluated by the deterministic firewall adapter.", (ControlEvidenceRequirement("windows.firewall", "firewall.profile"),), capability=ComplianceEvaluationCapability.FULL),
        ComplianceControl("RX-WIN-UAC-001", framework.framework_id, "UAC policy observation", "Windows UAC policy observation reports an observed insecure configuration when present.", (ControlEvidenceRequirement("windows.uac", "uac.configuration"),)),
        ComplianceControl("RX-WIN-SMB-001", framework.framework_id, "SMBv1 disabled", "SMBv1 is disabled when the scanner observes it enabled.", (ControlEvidenceRequirement("windows.smb", "smb.smb1_enabled"),)),
        ComplianceControl("RX-WIN-BIT-001", framework.framework_id, "OS-volume BitLocker protection", "The Windows C: OS volume reports BitLocker protection.", (ControlEvidenceRequirement("windows.bitlocker", "bitlocker.os_volume"),)),
    )
    framework = ComplianceFramework(framework.framework_id, framework.name, framework.version, framework.description, tuple(x.control_id for x in controls))
    return ComplianceFrameworkRegistry((framework,), controls)
