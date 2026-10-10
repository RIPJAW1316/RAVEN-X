"""Pure metadata and outcome contracts for local scanner runtimes."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re
from typing import Any, FrozenSet, Mapping, Optional, Tuple

from ..assessment import Finding


_SCANNER_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")


class ScannerImplementationStatus(str, Enum):
    AVAILABLE = "available"
    LEGACY_ONLY = "legacy_only"
    EXPERIMENTAL = "experimental"
    UNAVAILABLE = "unavailable"


class CompatibilityStatus(str, Enum):
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class CapabilityAvailability(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ScannerExecutionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    INCOMPATIBLE = "incompatible"


class ExecutionCompleteness(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ResourceEvaluationStatus(str, Enum):
    EVALUATED = "evaluated"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ResourceExecutionEvidence:
    resource_key: str
    status: ResourceEvaluationStatus
    reason_code: str = ""

    def __post_init__(self):
        key = str(self.resource_key).strip().casefold()
        reason = str(self.reason_code or "")[:256]
        if not key or len(key) > 256:
            raise ValueError("resource_key must be non-empty and bounded")
        if any(word in reason.casefold() for word in ("password", "token", "secret", "powershell", "command", "authorization")):
            raise ValueError("resource evidence reason must not contain secrets or commands")
        object.__setattr__(self, "resource_key", key)
        object.__setattr__(self, "status", ResourceEvaluationStatus(self.status))
        object.__setattr__(self, "reason_code", reason)

    def to_dict(self):
        return {"resource_key": self.resource_key, "status": self.status.value, "reason_code": self.reason_code}

    @classmethod
    def from_dict(cls, value):
        return cls(value["resource_key"], value["status"], value.get("reason_code", ""))


@dataclass(frozen=True)
class ScannerExecutionEvidence:
    scanner_id: str
    scanner_version: Optional[str] = None
    completeness: ExecutionCompleteness = ExecutionCompleteness.UNKNOWN
    rules_attempted: Tuple[str, ...] = ()
    rules_completed: Tuple[str, ...] = ()
    resource_enumeration_complete: Optional[bool] = None
    resources_discovered: Tuple[str, ...] = ()
    resource_results: Tuple[ResourceExecutionEvidence, ...] = ()
    normalization_status: str = "unknown"
    partial_reason: Optional[str] = None

    def __post_init__(self):
        rules_attempted = tuple(str(item).strip() for item in self.rules_attempted)
        rules_completed = tuple(str(item).strip() for item in self.rules_completed)
        resources = tuple(str(item).strip().casefold() for item in self.resources_discovered)
        if any(not item for item in rules_attempted + rules_completed) or len(rules_attempted) > 100 or len(rules_completed) > 100:
            raise ValueError("rule execution evidence is invalid or exceeds its bound")
        if not set(rules_completed).issubset(rules_attempted):
            raise ValueError("rules_completed must be a subset of rules_attempted")
        if len(resources) > 100 or any(not item or len(item) > 256 for item in resources):
            raise ValueError("resource enumeration evidence is invalid or exceeds its bound")
        if len(set(resources)) != len(resources):
            raise ValueError("resources_discovered must be unique")
        resource_results = tuple(item if isinstance(item, ResourceExecutionEvidence) else ResourceExecutionEvidence.from_dict(item) for item in self.resource_results)
        if len(resource_results) > 100:
            raise ValueError("resource result evidence exceeds its bound")
        if resources and any(item.resource_key not in resources for item in resource_results):
            raise ValueError("resource result must refer to a discovered resource")
        completeness = ExecutionCompleteness(self.completeness)
        partial_reason = None if self.partial_reason is None else str(self.partial_reason)[:256]
        if partial_reason and any(word in partial_reason.casefold() for word in ("password", "token", "secret", "powershell", "command", "authorization")):
            raise ValueError("partial_reason must not contain secrets or commands")
        if completeness is ExecutionCompleteness.COMPLETE and partial_reason:
            raise ValueError("complete evidence cannot contain a partial reason")
        if self.resource_enumeration_complete is not None and not isinstance(self.resource_enumeration_complete, bool):
            raise ValueError("resource_enumeration_complete must be boolean or None")
        object.__setattr__(self, "completeness", completeness)
        object.__setattr__(self, "rules_attempted", rules_attempted)
        object.__setattr__(self, "rules_completed", rules_completed)
        object.__setattr__(self, "resources_discovered", resources)
        object.__setattr__(self, "resource_results", resource_results)
        object.__setattr__(self, "normalization_status", str(self.normalization_status or "unknown")[:64])
        object.__setattr__(self, "partial_reason", partial_reason)

    def to_dict(self):
        return {"scanner_id": self.scanner_id, "scanner_version": self.scanner_version,
                "completeness": self.completeness.value, "rules_attempted": list(self.rules_attempted),
                "rules_completed": list(self.rules_completed),
                "resource_enumeration_complete": self.resource_enumeration_complete,
                "resources_discovered": list(self.resources_discovered),
                "resource_results": [item.to_dict() for item in self.resource_results],
                "normalization_status": self.normalization_status, "partial_reason": self.partial_reason}

    @classmethod
    def from_dict(cls, value):
        return cls(value["scanner_id"], value.get("scanner_version"), value.get("completeness", "unknown"),
                   tuple(value.get("rules_attempted", ())), tuple(value.get("rules_completed", ())),
                   value.get("resource_enumeration_complete"), tuple(value.get("resources_discovered", ())),
                   tuple(ResourceExecutionEvidence.from_dict(item) for item in value.get("resource_results", ())),
                   value.get("normalization_status", "unknown"), value.get("partial_reason"))


@dataclass(frozen=True, order=True)
class ScannerCapability:
    value: str

    def __post_init__(self) -> None:
        if not _SCANNER_ID.match(self.value):
            raise ValueError("capability must be lowercase and machine-readable")


@dataclass(frozen=True)
class CapabilityObservation:
    capability: ScannerCapability
    availability: CapabilityAvailability
    source: str
    reason: str


@dataclass(frozen=True)
class TargetCapabilities:
    values: FrozenSet[ScannerCapability] = frozenset()
    observations: Tuple[CapabilityObservation, ...] = ()

    def supports(self, capability: ScannerCapability) -> bool:
        return capability in self.values

    def availability_for(self, capability: ScannerCapability) -> CapabilityAvailability:
        if capability in self.values:
            return CapabilityAvailability.SUPPORTED
        for observation in self.observations:
            if observation.capability == capability:
                return observation.availability
        return CapabilityAvailability.UNSUPPORTED


@dataclass(frozen=True)
class ScannerManifest:
    scanner_id: str
    name: str
    description: str
    category: str
    version: str
    required_capabilities: FrozenSet[ScannerCapability] = frozenset()
    supported_platforms: FrozenSet[str] = frozenset({"Windows"})
    status: ScannerImplementationStatus = ScannerImplementationStatus.AVAILABLE

    def __post_init__(self) -> None:
        if not _SCANNER_ID.match(self.scanner_id):
            raise ValueError("scanner_id must be lowercase and machine-readable")
        for field_name in ("name", "description", "category", "version"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be empty")


@dataclass(frozen=True)
class CompatibilityResult:
    scanner_id: str
    status: CompatibilityStatus
    reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ScannerExecutionResult:
    scanner_id: str
    status: ScannerExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: Tuple[Finding, ...] = ()
    error: Optional[str] = None
    native_metrics: Mapping[str, Any] = field(default_factory=dict)
    scanner_version: Optional[str] = None
    execution_evidence: Optional[ScannerExecutionEvidence] = None
    error_category: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status is ScannerExecutionStatus.SUCCESS and self.completed_at is None:
            raise ValueError("successful execution requires completed_at")
        if self.status is ScannerExecutionStatus.FAILED and not self.error:
            raise ValueError("failed execution requires an error")
        if self.scanner_version is not None and not str(self.scanner_version).strip():
            raise ValueError("scanner_version must not be empty")
        if isinstance(self.execution_evidence, Mapping):
            object.__setattr__(self, "execution_evidence", ScannerExecutionEvidence.from_dict(self.execution_evidence))
        if self.execution_evidence is not None and self.execution_evidence.scanner_id != self.scanner_id:
            raise ValueError("execution evidence scanner_id must match result")
        if self.error_category is not None and not str(self.error_category).strip():
            raise ValueError("error_category must not be empty")
