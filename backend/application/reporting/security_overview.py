"""Tenant-rooted aggregation for the security overview read model."""
from collections import Counter
from datetime import datetime, timezone

from ...domain.endpoint import EndpointStatus
from ...domain.presence import PresenceState
from ...domain.reporting import (AssessmentSummary, EndpointSummary, FindingCounts, FindingSummary,
                                  FindingSummary as FindingOccurrence, OrganizationSecurityOverview,
                                  PresenceSummary)
from ...domain.security import (AuthorizationAction, AuthorizationRequest,
                                 AuthorizationResource, PrincipalType)


class TenantSecurityOverviewService:
    """Build a bounded, read-only overview from tenant-owned repositories."""

    def __init__(self, endpoint_repository, presence_repository, assessment_repository,
                 authorizer, *, recent_limit=10, high_severity_limit=20,
                 metrics=None, logger=None, clock=None):
        if recent_limit <= 0 or high_severity_limit <= 0:
            raise ValueError("report limits must be positive")
        self.endpoints = endpoint_repository
        self.presence = presence_repository
        self.assessments = assessment_repository
        self.authorizer = authorizer
        self.recent_limit = recent_limit
        self.high_severity_limit = high_severity_limit
        self.metrics = metrics
        self.logger = logger
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def overview(self, principal, context) -> OrganizationSecurityOverview:
        if principal.principal_type is not PrincipalType.HUMAN:
            raise PermissionError("human principal required")
        if not hasattr(context, "organization_id"):
            raise PermissionError("organization context required")
        self._authorize(principal, context, AuthorizationAction.ENDPOINT_READ, "security_overview.endpoints")
        self._authorize(principal, context, AuthorizationAction.ASSESSMENT_READ, "security_overview.assessments")

        organization_id = str(context.organization_id)
        endpoints = tuple(self.endpoints.list_for_organization(context.organization_id))
        presence_items = tuple(self.presence.list_for_organization(context.organization_id))
        presence_by_endpoint = {str(item.endpoint_id): item for item in presence_items}
        endpoint_summary, presence_summary = self._endpoint_presence(endpoints, presence_by_endpoint)

        # This is an authoritative tenant query.  Legacy NULL-owned records
        # are excluded even if a non-tenant repository implementation leaks one.
        tenant_endpoint_ids = {str(item.endpoint_id) for item in endpoints}
        assessments = tuple(item for item in self.assessments.list_for_organization(context.organization_id)
                             if item.organization_id is not None
                             and str(item.organization_id) == organization_id
                             and str(item.endpoint_id) in tenant_endpoint_ids)
        status_counts = Counter(self._status(item) for item in assessments)
        # Keep every currently-supported workflow bucket explicit, including
        # zeroes, so clients do not infer a missing state as an error.
        known_states = ("created", "queued", "dispatched", "running", "completed",
                        "failed", "delivery_failed", "expired", "cancel_requested",
                        "cancelled", "endpoint_unavailable")
        assessment_counts = {key: status_counts[key] for key in known_states}
        assessment_counts.update({key: value for key, value in status_counts.items() if key not in assessment_counts})
        all_findings = []
        malformed = 0
        recent = []
        for assessment in assessments:
            findings, bad = self._findings(assessment)
            malformed += bad
            all_findings.extend((assessment, finding) for finding in findings)
        for assessment in sorted(assessments, key=lambda item: (self._timestamp(item.created_at), str(item.assessment_id)), reverse=True)[:self.recent_limit]:
            finding_counts = Counter(self._finding_severity(finding) for owner, finding in all_findings if owner.assessment_id == assessment.assessment_id)
            recent.append(AssessmentSummary(str(assessment.assessment_id), str(assessment.endpoint_id),
                                             self._status(assessment), assessment.created_at, assessment.started_at,
                                             assessment.completed_at, dict(sorted(finding_counts.items()))))

        finding_counts = Counter(self._finding_severity(finding) for _, finding in all_findings)
        aggregate_counts = FindingCounts(**{key: int(finding_counts.get(key, 0))
                                            for key in ("critical", "high", "medium", "low", "info", "unknown")})
        high = [self._occurrence(owner, finding) for owner, finding in all_findings
                if self._finding_severity(finding) in {"critical", "high"}]
        high.sort(key=lambda item: ((item.observed_at or datetime.min.replace(tzinfo=timezone.utc)), item.assessment_id, item.finding_id or ""), reverse=True)
        result = OrganizationSecurityOverview(organization_id, self.clock(), endpoint_summary,
                                               presence_summary, assessment_counts, aggregate_counts,
                                               tuple(recent), tuple(high[:self.high_severity_limit]), malformed)
        if self.metrics is not None:
            self.metrics.increment("security_overview.requests")
        if self.logger is not None:
            self.logger.info("security_overview_generated organization_id=%s assessments=%s findings=%s",
                             organization_id, len(assessments), sum(finding_counts.values()))
        return result

    get_overview = overview

    def _authorize(self, principal, context, action, resource_type):
        resource = AuthorizationResource(resource_type, metadata={"organization_id": str(context.organization_id)})
        context_value = context.to_dict() if hasattr(context, "to_dict") else context
        decision = self.authorizer.authorize(AuthorizationRequest(principal, action, resource,
                                                                    organization_context=context_value))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)

    @staticmethod
    def _endpoint_presence(endpoints, presence_by_endpoint):
        counts = Counter()
        revoked = 0
        active = 0
        for endpoint in endpoints:
            if endpoint.status is EndpointStatus.REVOKED:
                revoked += 1
                continue
            active += 1
            snapshot = presence_by_endpoint.get(str(endpoint.endpoint_id))
            counts[(snapshot.state if snapshot is not None else PresenceState.UNKNOWN).value] += 1
        return EndpointSummary(active + revoked, active, revoked), PresenceSummary(
            counts[PresenceState.UNKNOWN.value], counts[PresenceState.ONLINE.value],
            counts[PresenceState.STALE.value], counts[PresenceState.OFFLINE.value], revoked)

    @staticmethod
    def _status(assessment):
        value = getattr(assessment, "state", getattr(assessment, "status", "unknown"))
        return getattr(value, "value", str(value))

    @staticmethod
    def _timestamp(value):
        if value is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    @staticmethod
    def _findings(assessment):
        result = getattr(assessment, "result", None)
        raw = getattr(result, "findings", None) if result is not None else None
        if raw is None and isinstance(result, dict):
            raw = result.get("findings", ())
        good, bad = [], 0
        for item in raw or ():
            if not isinstance(item, dict):
                # In-memory tests and application callers may still hold a
                # normalized Finding object rather than its wire mapping.
                if all(hasattr(item, name) for name in ("severity", "title")):
                    item = {"finding_id": getattr(item, "finding_id", None),
                            "severity": getattr(getattr(item, "severity", None), "value", item.severity),
                            "title": getattr(item, "title", ""),
                            "details": getattr(item, "details", ""),
                            "component": getattr(item, "component", None),
                            "metadata": getattr(item, "metadata", {})}
                else:
                    bad += 1
                    continue
            severity = item.get("severity", "unknown")
            if not isinstance(severity, (str,)) and not hasattr(severity, "value"):
                bad += 1
                continue
            if not isinstance(severity, str):
                item = dict(item)
                item["severity"] = severity.value
            good.append(item)
        return good, bad

    @staticmethod
    def _finding_severity(finding):
        raw = finding.get("severity", "unknown")
        value = str(getattr(raw, "value", raw)).strip().lower()
        return value if value in {"critical", "high", "medium", "low", "info", "unknown"} else "unknown"

    @staticmethod
    def _occurrence(assessment, finding):
        observed = finding.get("observed_at") or finding.get("timestamp")
        if isinstance(observed, str):
            try: observed = datetime.fromisoformat(observed)
            except ValueError: observed = None
        if isinstance(observed, datetime) and (observed.tzinfo is None or observed.utcoffset() is None):
            observed = observed.replace(tzinfo=timezone.utc)
        return FindingOccurrence(str(assessment.assessment_id), str(assessment.endpoint_id),
                                 TenantSecurityOverviewService._finding_severity(finding),
                                 str(finding.get("title") or finding.get("name") or "Untitled finding"),
                                 str(finding.get("description") or finding.get("details") or ""),
                                 finding.get("scanner_id") or finding.get("component"), observed,
                                 str(finding.get("finding_id")) if finding.get("finding_id") else None)
