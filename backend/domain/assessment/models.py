"""Pure contracts for one security assessment and its observations."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Optional, Tuple


class AssessmentStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_legacy(cls, value: Any) -> "FindingSeverity":
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            for severity in cls:
                if severity.value == normalized:
                    return severity
        return cls.UNKNOWN


@dataclass(frozen=True)
class Evidence:
    """A lightweight observation associated with a security finding."""

    source: str
    description: str
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None
    raw_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AssessmentTarget:
    """The machine assessed by a runner; it is not an enterprise endpoint."""

    target_id: str
    hostname: str
    platform: str
    platform_version: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("target_id", "hostname", "platform"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be empty")


@dataclass(frozen=True)
class Finding:
    """A normalized security finding with no remediation execution behavior."""

    finding_id: str
    severity: FindingSeverity
    category: str
    title: str
    details: str
    component: str
    remediation: Optional[str] = None
    evidence: Tuple[Evidence, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    legacy_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AssessmentResult:
    """The outcome of one scanner run, separate from database persistence."""

    assessment_id: str
    target: AssessmentTarget
    status: AssessmentStatus
    started_at: datetime
    finished_at: Optional[datetime] = None
    findings: Tuple[Finding, ...] = ()
    scanner_metadata: Mapping[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    scanner_results: Tuple[Any, ...] = ()
    organization_id: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.organization_id is not None:
            object.__setattr__(self, "organization_id", _organization_id(self.organization_id))
        if self.status is AssessmentStatus.COMPLETED and self.finished_at is None:
            raise ValueError("completed assessments require finished_at")
        if self.status is AssessmentStatus.FAILED and not self.error:
            raise ValueError("failed assessments require an error")

    @property
    def succeeded(self) -> bool:
        return self.status is AssessmentStatus.COMPLETED


def _organization_id(value):
    module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
    return module.OrganizationId.parse(value)
