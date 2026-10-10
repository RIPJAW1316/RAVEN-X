"""Tenant-safe detailed assessment and finding read services."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional, Tuple

from ...domain.assessment import FindingSeverity
from ...domain.reporting import FindingOccurrenceId, derive_fingerprint, materialize_finding_identity
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType


@dataclass(frozen=True)
class EvidenceSummary:
    source: str
    description: str
    values: Mapping[str, object]

    def to_dict(self):
        return {"source": self.source, "description": self.description, "values": dict(self.values)}


@dataclass(frozen=True)
class FindingOccurrenceDetail:
    occurrence_id: str
    assessment_id: str
    endpoint_id: str
    scanner_id: Optional[str]
    title: str
    severity: str
    description: str
    observed_at: Optional[datetime]
    fingerprint: Optional[Mapping[str, object]]
    evidence: Tuple[EvidenceSummary, ...] = ()

    def to_dict(self):
        return {"occurrence_id": self.occurrence_id, "assessment_id": self.assessment_id,
                "endpoint_id": self.endpoint_id, "scanner_id": self.scanner_id,
                "title": self.title, "severity": self.severity, "description": self.description,
                "observed_at": _iso(self.observed_at),
                "fingerprint": dict(self.fingerprint) if self.fingerprint else None,
                "evidence": [item.to_dict() for item in self.evidence]}


@dataclass(frozen=True)
class TenantAssessmentDetail:
    assessment_id: str
    organization_id: str
    endpoint_id: str
    status: str
    created_at: datetime
    requested_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    scanner_ids: Tuple[str, ...]
    progress: object
    scanner_results: Tuple[Mapping[str, object], ...]
    findings: Tuple[FindingOccurrenceDetail, ...]
    total_findings: int
    malformed_finding_count: int = 0

    def to_dict(self):
        return {"assessment_id": self.assessment_id, "organization_id": self.organization_id,
                "endpoint_id": self.endpoint_id, "status": self.status,
                "created_at": _iso(self.created_at), "requested_at": _iso(self.requested_at),
                "started_at": _iso(self.started_at), "completed_at": _iso(self.completed_at),
                "scanner_ids": list(self.scanner_ids),
                "progress": _safe(self.progress), "scanner_results": [_safe(item) for item in self.scanner_results],
                "findings": [item.to_dict() for item in self.findings],
                "total_findings": self.total_findings, "malformed_finding_count": self.malformed_finding_count}


class TenantAssessmentDetailService:
    def __init__(self, endpoint_repository, assessment_repository, authorizer, *,
                 max_findings=100, max_evidence_items=10, max_string_length=512,
                 metrics=None, logger=None):
        if min(max_findings, max_evidence_items, max_string_length) <= 0:
            raise ValueError("detail limits must be positive")
        self.endpoints, self.assessments, self.authorizer = endpoint_repository, assessment_repository, authorizer
        self.max_findings, self.max_evidence_items, self.max_string_length = max_findings, max_evidence_items, max_string_length
        self.metrics, self.logger = metrics, logger

    def get_detail(self, principal, context, assessment_id: str, *, limit: Optional[int] = None) -> TenantAssessmentDetail:
        self._context(principal, context)
        assessment = self.assessments.get_for_organization(assessment_id, context.organization_id)
        if assessment is None or assessment.organization_id is None:
            raise KeyError("assessment not found")
        endpoint = self.endpoints.get_for_organization(assessment.endpoint_id, context.organization_id)
        if endpoint is None:
            raise KeyError("assessment not found")
        self._authorize(principal, context, assessment_id)
        bound = self.max_findings if limit is None else min(self.max_findings, max(0, int(limit)))
        findings, malformed = self._finding_details(assessment, bound)
        scanner_results = self._scanner_results(assessment)
        if self.metrics is not None: self.metrics.increment("assessment_detail.requests")
        return TenantAssessmentDetail(str(assessment.assessment_id), str(context.organization_id), str(assessment.endpoint_id),
                                      _status(assessment), assessment.created_at, assessment.requested_at,
                                      assessment.started_at, assessment.completed_at, tuple(assessment.scanner_ids),
                                      assessment.progress, scanner_results, tuple(findings), len(self._raw_findings(assessment)), malformed)

    get_assessment_detail = get_detail

    def get_finding(self, principal, context, assessment_id: str, occurrence_id: str) -> FindingOccurrenceDetail:
        detail = self.get_detail(principal, context, assessment_id, limit=self.max_findings)
        for finding in detail.findings:
            if finding.occurrence_id == str(occurrence_id):
                if self.metrics is not None: self.metrics.increment("finding_detail.requests")
                return finding
        if self.metrics is not None: self.metrics.increment("finding_detail.failures")
        raise KeyError("finding not found")

    get_finding_detail = get_finding

    def _authorize(self, principal, context, assessment_id):
        context_value = context.to_dict() if hasattr(context, "to_dict") else context
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.ASSESSMENT_READ,
            AuthorizationResource("assessment", assessment_id, {"organization_id": str(context.organization_id)}),
            organization_context=context_value))
        if not decision.allowed: raise PermissionError(decision.reason_code)

    @staticmethod
    def _context(principal, context):
        if principal.principal_type is not PrincipalType.HUMAN or not hasattr(context, "organization_id"):
            raise PermissionError("human organization context required")

    def _finding_details(self, assessment, limit):
        details, malformed = [], 0
        for index, raw in enumerate(self._raw_findings(assessment)):
            if not isinstance(raw, Mapping): malformed += 1; continue
            value = materialize_finding_identity(raw, assessment_id=str(assessment.assessment_id), endpoint_id=str(assessment.endpoint_id), index=index)
            details.append(self._detail(assessment, value, index))
        details.sort(key=lambda item: (_severity_rank(item.severity), item.occurrence_id), reverse=True)
        return details[:limit], malformed

    def _detail(self, assessment, finding, index):
        observed = finding.get("observed_at") or finding.get("timestamp")
        if isinstance(observed, str):
            try: observed = datetime.fromisoformat(observed)
            except ValueError: observed = None
        if isinstance(observed, datetime) and observed.tzinfo is None: observed = observed.replace(tzinfo=timezone.utc)
        fingerprint = finding.get("logical_fingerprint")
        if not isinstance(fingerprint, Mapping):
            generated = derive_fingerprint(finding, str(assessment.endpoint_id))
            fingerprint = generated.to_dict() if generated else None
        evidence = tuple(_evidence(item, self.max_string_length) for item in (finding.get("evidence") or ()) if isinstance(item, Mapping))[:self.max_evidence_items]
        return FindingOccurrenceDetail(str(finding["occurrence_id"]), str(assessment.assessment_id), str(assessment.endpoint_id),
                                       _text(finding.get("scanner_id") or finding.get("component"), self.max_string_length),
                                       _text(finding.get("title") or finding.get("name") or "Untitled finding", self.max_string_length),
                                       _severity(finding.get("severity")), _text(finding.get("description") or finding.get("details"), self.max_string_length),
                                       observed, _safe(fingerprint), evidence)

    @staticmethod
    def _raw_findings(assessment):
        result = getattr(assessment, "result", None)
        raw = getattr(result, "findings", None) if result is not None else None
        if raw is None and isinstance(result, Mapping): raw = result.get("findings", ())
        return tuple(raw or ())

    def _scanner_results(self, assessment):
        result = getattr(assessment, "result", None)
        raw = getattr(result, "scanner_results", None) if result is not None else None
        output = []
        for item in raw or ():
            if isinstance(item, Mapping):
                output.append({"scanner_id": item.get("scanner_id"), "status": item.get("status"),
                               "finding_count": len(item.get("findings") or ()),
                               "error": type(item["error"]).__name__ if item.get("error") else None})
        return tuple(output)


class TenantFindingService:
    """Named boundary for finding reads; all lookups remain assessment-rooted."""
    def __init__(self, assessment_detail_service): self._service = assessment_detail_service
    def get(self, principal, context, assessment_id, occurrence_id):
        return self._service.get_finding(principal, context, assessment_id, occurrence_id)


def _status(item):
    value = getattr(item, "state", getattr(item, "status", "unknown")); return getattr(value, "value", str(value))
def _iso(value): return value.astimezone(timezone.utc).isoformat() if value else None
def _text(value, limit): return str(value or "")[:limit]
def _severity(value):
    value = str(getattr(value, "value", value or "unknown")).lower(); return value if value in {x.value for x in FindingSeverity} else "unknown"
def _severity_rank(value): return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}.get(value, 0)

def _safe(value, depth=0):
    if depth > 3: return "<truncated>"
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            name = str(key).lower()
            if any(token in name for token in ("password", "token", "secret", "authorization", "verifier", "private_key", "bearer", "powershell", "shell_command", "remediation")):
                continue
            result[str(key)] = _safe(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)): return [_safe(item, depth + 1) for item in value[:20]]
    if isinstance(value, (str, int, float, bool)) or value is None: return value if not isinstance(value, str) else value[:512]
    if hasattr(value, "to_dict"): return _safe(value.to_dict(), depth + 1)
    return str(value)[:512]

def _evidence(value, limit):
    safe = _safe(value)
    if not isinstance(safe, Mapping): return EvidenceSummary("unknown", _text(safe, limit), {})
    return EvidenceSummary(_text(safe.get("source", "unknown"), limit), _text(safe.get("description", ""), limit),
                           _safe({key: item for key, item in safe.items() if key not in {"source", "description"}}))
