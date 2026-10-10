"""Tenant-safe, bounded candidate recurrence comparison."""
from collections.abc import Mapping
from datetime import datetime, timezone

from ...domain.reporting import (FindingRecurrenceSummary, RecurrenceOccurrence,
                                 derive_fingerprint, materialize_finding_identity)
from ...domain.security import PrincipalType


class TenantFindingRecurrenceService:
    def __init__(self, assessment_repository, detail_service, *, max_assessments=100,
                 recent_limit=10, metrics=None, logger=None, clock=None):
        if max_assessments <= 0 or recent_limit <= 0:
            raise ValueError("recurrence limits must be positive")
        self.assessments = assessment_repository
        self.details = detail_service
        self.max_assessments, self.recent_limit = max_assessments, recent_limit
        self.metrics, self.logger = metrics, logger
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def compare(self, principal, context, assessment_id: str, occurrence_id: str) -> FindingRecurrenceSummary:
        if principal.principal_type is not PrincipalType.HUMAN or not hasattr(context, "organization_id"):
            raise PermissionError("human organization context required")
        # Resolves the source through the existing tenant-safe assessment and
        # occurrence service; clients cannot submit a fingerprint directly.
        source = self.details.get_finding(principal, context, assessment_id, occurrence_id)
        source_assessment = self.assessments.get_for_organization(assessment_id, context.organization_id)
        if source_assessment is None: raise KeyError("assessment not found")
        source_fp = source.fingerprint if isinstance(source.fingerprint, Mapping) else None
        if not self._valid_fingerprint(source_fp):
            return self._unresolved(source.occurrence_id, source.endpoint_id)

        all_items = list(self.assessments.list_for_endpoint_and_organization(source_assessment.endpoint_id, context.organization_id))
        ordered = sorted(all_items, key=lambda item: (_time(getattr(item, "created_at", None)), str(item.assessment_id)), reverse=True)
        selected = ordered[:self.max_assessments]
        if not any(item.assessment_id == source_assessment.assessment_id for item in selected):
            selected.append(source_assessment)
        complete = len(ordered) <= self.max_assessments
        matches, malformed = [], 0
        source_digest = source_fp.get("digest")
        source_version = source_fp.get("version")
        for assessment in selected:
            raw = self._raw_findings(assessment)
            for index, finding in enumerate(raw):
                if not isinstance(finding, Mapping): malformed += 1; continue
                materialized = materialize_finding_identity(finding, assessment_id=str(assessment.assessment_id), endpoint_id=str(assessment.endpoint_id), index=index)
                fingerprint = materialized.get("logical_fingerprint")
                if not self._valid_fingerprint(fingerprint):
                    if fingerprint is not None: malformed += 1
                    continue
                if fingerprint.get("version") != source_version or fingerprint.get("digest") != source_digest:
                    continue
                matches.append(self._occurrence(assessment, materialized))
        # Source may be in an omitted portion only when the selected list was
        # bounded; it was explicitly appended above, so it remains included.
        matches.sort(key=lambda item: (_time(item.observed_at), item.assessment_id, item.occurrence_id))
        result = FindingRecurrenceSummary(source.occurrence_id, source.endpoint_id, "candidate_matchable", len(matches),
                                           matches[0].observed_at if matches else None,
                                           matches[-1].observed_at if matches else None,
                                           tuple(reversed(matches[-self.recent_limit:])), complete, len(selected), malformed,
                                           self.clock())
        if self.metrics is not None: self.metrics.increment("finding_recurrence.requests")
        if self.logger is not None: self.logger.info("finding_recurrence_generated endpoint_id=%s assessments=%s matches=%s", source.endpoint_id, len(selected), len(matches))
        return result

    get_recurrence = compare

    @staticmethod
    def _raw_findings(assessment):
        result = getattr(assessment, "result", None)
        raw = getattr(result, "findings", None) if result is not None else None
        if raw is None and isinstance(result, Mapping): raw = result.get("findings", ())
        return tuple(raw or ())

    @staticmethod
    def _valid_fingerprint(value):
        if not isinstance(value, Mapping) or value.get("version") != 1 or value.get("match_semantics") != "candidate": return False
        components, digest = value.get("components"), value.get("digest")
        if not isinstance(components, Mapping) or not isinstance(digest, str): return False
        expected = derive_fingerprint({"scanner_id": components.get("scanner_id"), "rule_id": components.get("rule_id"), "resource_key": components.get("resource_key")}, components.get("endpoint_id", ""))
        return expected is not None and expected.digest == digest and dict(expected.components) == dict(components)

    @staticmethod
    def _occurrence(assessment, finding):
        observed = finding.get("observed_at") or finding.get("timestamp") or getattr(assessment, "completed_at", None) or getattr(assessment, "created_at", None)
        observed = _time(observed)
        return RecurrenceOccurrence(str(finding["occurrence_id"]), str(assessment.assessment_id), observed,
                                    _severity(finding.get("severity")), str(finding.get("scanner_id") or finding.get("component") or ""),
                                    str(finding.get("title") or finding.get("name") or "Untitled finding"))

    def _unresolved(self, occurrence_id, endpoint_id):
        if self.metrics is not None: self.metrics.increment("finding_recurrence.unresolved")
        return FindingRecurrenceSummary(str(occurrence_id), str(endpoint_id), "unresolved", 1, None, None, (), True, 0, 0, self.clock())


def _time(value):
    if value is None: return datetime.min.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try: value = datetime.fromisoformat(value)
        except ValueError: return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

def _severity(value):
    value = str(getattr(value, "value", value or "unknown")).lower()
    return value if value in {"critical", "high", "medium", "low", "info", "unknown"} else "unknown"
