"""Pure read models for tenant security reporting.

These objects deliberately contain facts and occurrence counts only.  They do
not calculate risk, compliance, or AI-derived conclusions.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Optional, Tuple


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class EndpointSummary:
    total_endpoints: int = 0
    active_endpoints: int = 0
    revoked_endpoints: int = 0

    def to_dict(self):
        return {"total_endpoints": self.total_endpoints,
                "active_endpoints": self.active_endpoints,
                "revoked_endpoints": self.revoked_endpoints}


@dataclass(frozen=True)
class PresenceSummary:
    unknown: int = 0
    online: int = 0
    stale: int = 0
    offline: int = 0
    revoked: int = 0

    def to_dict(self):
        return {"unknown": self.unknown, "online": self.online,
                "stale": self.stale, "offline": self.offline,
                "revoked": self.revoked}


@dataclass(frozen=True)
class FindingCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0

    def to_dict(self):
        return {"critical": self.critical, "high": self.high,
                "medium": self.medium, "low": self.low,
                "info": self.info, "unknown": self.unknown,
                "total_occurrences": sum((self.critical, self.high, self.medium,
                                           self.low, self.info, self.unknown))}


@dataclass(frozen=True)
class AssessmentSummary:
    assessment_id: str
    endpoint_id: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    finding_counts: Mapping[str, int] = field(default_factory=dict)

    def to_dict(self):
        return {"assessment_id": self.assessment_id,
                "endpoint_id": self.endpoint_id, "status": self.status,
                "created_at": _utc(self.created_at),
                "started_at": _utc(self.started_at) if self.started_at else None,
                "completed_at": _utc(self.completed_at) if self.completed_at else None,
                "finding_counts": dict(self.finding_counts)}


@dataclass(frozen=True)
class FindingSummary:
    assessment_id: str
    endpoint_id: str
    severity: str
    title: str
    description: str = ""
    scanner_id: Optional[str] = None
    observed_at: Optional[datetime] = None
    finding_id: Optional[str] = None

    def to_dict(self):
        return {"assessment_id": self.assessment_id, "endpoint_id": self.endpoint_id,
                "finding_id": self.finding_id, "severity": self.severity,
                "title": self.title, "description": self.description,
                "scanner_id": self.scanner_id,
                "observed_at": _utc(self.observed_at) if self.observed_at else None}


@dataclass(frozen=True)
class OrganizationSecurityOverview:
    organization_id: str
    generated_at: datetime
    endpoints: EndpointSummary
    presence: PresenceSummary
    assessments: Mapping[str, int]
    findings: FindingCounts
    recent_assessments: Tuple[AssessmentSummary, ...] = ()
    recent_high_severity_findings: Tuple[FindingSummary, ...] = ()
    malformed_finding_count: int = 0

    # Friendly aliases used by application/API consumers while the wire
    # sections remain compact and stable.
    @property
    def endpoint_summary(self): return self.endpoints
    @property
    def presence_summary(self): return self.presence
    @property
    def assessment_summary(self): return self.assessments
    @property
    def finding_summary(self): return self.findings

    def to_dict(self):
        return {"organization_id": self.organization_id,
                "generated_at": _utc(self.generated_at),
                "endpoints": self.endpoints.to_dict(),
                "presence": self.presence.to_dict(),
                "assessments": dict(self.assessments),
                "findings": self.findings.to_dict(),
                "recent_assessments": [item.to_dict() for item in self.recent_assessments],
                "recent_high_severity_findings": [item.to_dict() for item in self.recent_high_severity_findings],
                "malformed_finding_count": self.malformed_finding_count}
