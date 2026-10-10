"""Pure, conservative coverage and observation contracts."""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import re
from typing import FrozenSet, Mapping, Optional, Tuple


class CoverageStatus(str, Enum):
    COVERED = "covered"
    NOT_COVERED = "not_covered"
    INDETERMINATE = "indeterminate"


class FindingObservationStatus(str, Enum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    NOT_EVALUATED = "not_evaluated"
    UNKNOWN = "unknown"


class CoverageGranularity(str, Enum):
    SCANNER = "scanner"
    RULE = "rule"
    RESOURCE = "resource"
    UNKNOWN = "unknown"


class LifecycleEligibilityStatus(str, Enum):
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass(frozen=True)
class ScannerCoverageContract:
    scanner_id: str
    granularity: CoverageGranularity = CoverageGranularity.UNKNOWN
    reason: str = "scanner coverage is not explicitly declared"
    contract_version: int = 1
    rule_ids: Tuple[str, ...] = ()
    resource_scope: Tuple[str, ...] = ()
    scanner_versions: FrozenSet[str] = frozenset()
    allows_absence_inference: bool = False

    def __post_init__(self):
        if not isinstance(self.scanner_id, str) or not re.fullmatch(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*", self.scanner_id):
            raise ValueError("scanner_id must be lowercase and machine-readable")
        object.__setattr__(self, "granularity", CoverageGranularity(self.granularity))
        if not isinstance(self.contract_version, int) or self.contract_version <= 0:
            raise ValueError("coverage contract version must be positive")
        rules = tuple(str(item).strip() for item in self.rule_ids)
        resources = tuple(str(item).strip().casefold() for item in self.resource_scope)
        versions = frozenset(str(item).strip() for item in self.scanner_versions)
        if any(not item for item in rules) or len(set(rules)) != len(rules):
            raise ValueError("declared rule identifiers must be non-empty and unique")
        if any(not item for item in resources) or len(set(resources)) != len(resources):
            raise ValueError("declared resource scope must be non-empty and unique")
        if any(not item for item in versions):
            raise ValueError("scanner versions must be non-empty")
        if self.allows_absence_inference and not str(self.reason).strip():
            raise ValueError("strong coverage requires a documented guarantee")
        if self.granularity is CoverageGranularity.RULE and not rules:
            raise ValueError("rule coverage requires declared rule identifiers")
        if self.granularity is CoverageGranularity.RESOURCE and self.allows_absence_inference and not (rules or resources):
            raise ValueError("strong resource coverage requires rule or resource scope")
        object.__setattr__(self, "rule_ids", rules)
        object.__setattr__(self, "resource_scope", resources)
        object.__setattr__(self, "scanner_versions", versions)

    def covers(self, fingerprint: Mapping, scanner_version: Optional[str] = None, execution_evidence=None) -> bool:
        if not self.allows_absence_inference or not isinstance(fingerprint, Mapping):
            return False
        if execution_evidence is None:
            return False
        completeness = getattr(execution_evidence, "completeness", None)
        if getattr(completeness, "value", completeness) != "complete":
            return False
        if getattr(execution_evidence, "scanner_id", self.scanner_id) != self.scanner_id:
            return False
        if self.rule_ids:
            rule_id = fingerprint.get("components", {}).get("rule_id") if isinstance(fingerprint.get("components"), Mapping) else None
            if rule_id not in self.rule_ids or rule_id not in tuple(getattr(execution_evidence, "rules_completed", ())):
                return False
        if self.resource_scope:
            components = fingerprint.get("components")
            resource = str(components.get("resource_key", "")).casefold() if isinstance(components, Mapping) else ""
            if resource not in self.resource_scope:
                return False
            if getattr(execution_evidence, "resource_enumeration_complete", None) is not True:
                return False
            result = next((item for item in getattr(execution_evidence, "resource_results", ()) if item.resource_key == resource), None)
            if result is None or getattr(getattr(result, "status", None), "value", None) != "evaluated":
                return False
        if scanner_version is not None and self.scanner_versions and str(scanner_version) not in self.scanner_versions:
            return False
        if scanner_version is None and self.scanner_versions:
            return False
        components = fingerprint.get("components")
        if not isinstance(components, Mapping) or components.get("scanner_id") != self.scanner_id:
            return False
        if self.rule_ids and components.get("rule_id") not in self.rule_ids:
            return False
        if self.resource_scope and str(components.get("resource_key", "")).casefold() not in self.resource_scope:
            return False
        return True

    def to_dict(self):
        return {"scanner_id": self.scanner_id, "granularity": self.granularity.value,
                "reason": self.reason, "contract_version": self.contract_version,
                "rule_ids": list(self.rule_ids), "resource_scope": list(self.resource_scope),
                "scanner_versions": sorted(self.scanner_versions),
                "allows_absence_inference": self.allows_absence_inference}


@dataclass(frozen=True)
class CoverageAttestation:
    scanner_id: str
    scanner_version: Optional[str]
    coverage_granularity: CoverageGranularity
    rule_id: Optional[str]
    resource_scope: Optional[str]
    execution_status: Optional[str]
    contract_version: int
    coverage_status: CoverageStatus
    absence_inference_allowed: bool
    reason_code: str

    def __post_init__(self):
        object.__setattr__(self, "coverage_granularity", CoverageGranularity(self.coverage_granularity))

    def to_dict(self):
        return {"scanner_id": self.scanner_id, "scanner_version": self.scanner_version,
                "coverage_granularity": self.coverage_granularity.value, "rule_id": self.rule_id,
                "resource_scope": self.resource_scope, "execution_status": self.execution_status,
                "contract_version": self.contract_version, "coverage_status": self.coverage_status.value,
                "absence_inference_allowed": self.absence_inference_allowed, "reason_code": self.reason_code}


@dataclass(frozen=True)
class LifecycleReadinessSummary:
    eligible_scanner_count: int
    ineligible_scanner_count: int
    strong_coverage_scanners: Tuple[str, ...]
    unknown_coverage_scanners: Tuple[str, ...]
    source_finding_eligible: bool

    def to_dict(self):
        return {"eligible_scanner_count": self.eligible_scanner_count,
                "ineligible_scanner_count": self.ineligible_scanner_count,
                "strong_coverage_scanners": list(self.strong_coverage_scanners),
                "unknown_coverage_scanners": list(self.unknown_coverage_scanners),
                "source_finding_eligible": self.source_finding_eligible}


@dataclass(frozen=True)
class CoverageObservation:
    assessment_id: str
    assessment_status: str
    scanner_id: str
    scanner_execution_status: Optional[str]
    coverage_status: CoverageStatus
    observation_status: FindingObservationStatus
    reason_code: str
    observed_at: datetime
    attestation: Optional[CoverageAttestation] = None

    def to_dict(self):
        return {"assessment_id": self.assessment_id, "assessment_status": self.assessment_status,
                "scanner_id": self.scanner_id, "scanner_execution_status": self.scanner_execution_status,
                "coverage_status": self.coverage_status.value,
                "observation_status": self.observation_status.value,
                "reason_code": self.reason_code,
                "observed_at": _iso(self.observed_at),
                "attestation": self.attestation.to_dict() if self.attestation else None}


@dataclass(frozen=True)
class FindingCoverageHistory:
    source_occurrence_id: str
    endpoint_id: str
    identity_status: str
    observations: Tuple[CoverageObservation, ...]
    history_complete: bool
    assessments_examined: int
    latest_observation_status: Optional[FindingObservationStatus]
    lifecycle_eligibility: LifecycleEligibilityStatus
    malformed_assessment_count: int = 0
    generated_at: Optional[datetime] = None
    lifecycle_readiness: Optional[LifecycleReadinessSummary] = None

    def to_dict(self):
        return {"source_occurrence_id": self.source_occurrence_id, "endpoint_id": self.endpoint_id,
                "identity_status": self.identity_status,
                "observations": [item.to_dict() for item in self.observations],
                "history_complete": self.history_complete, "assessments_examined": self.assessments_examined,
                "latest_observation_status": self.latest_observation_status.value if self.latest_observation_status else None,
                "lifecycle_eligibility": self.lifecycle_eligibility.value,
                "malformed_assessment_count": self.malformed_assessment_count,
                "generated_at": _iso(self.generated_at),
                "lifecycle_readiness": self.lifecycle_readiness.to_dict() if self.lifecycle_readiness else None}


# Naming aliases keep the contract discoverable without duplicating models.
CoverageResult = FindingCoverageHistory
FindingCoverageResult = FindingCoverageHistory


def _iso(value):
    if value is None: return None
    if value.tzinfo is None or value.utcoffset() is None: value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()
