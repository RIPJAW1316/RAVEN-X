"""Evidence-grounded, organization-scoped fleet and endpoint reports."""

from collections import Counter
from datetime import datetime, timezone
import re
from typing import Mapping

from ...domain.endpoint import EndpointStatus
from ...domain.security import (AuthorizationAction, AuthorizationRequest,
                                AuthorizationResource, PrincipalType)
from ..organization.context import OrganizationContext


_APPROVED = {EndpointStatus.ACTIVE, EndpointStatus.DEGRADED, EndpointStatus.OFFLINE}
_FAILED = {"failed", "delivery_failed", "expired", "cancelled"}
_PENDING = {"created", "queued", "dispatched"}


class TenantFleetReportService:
    """Read tenant-owned records and label missing or failed scans explicitly."""

    def __init__(self, endpoint_repository, presence_repository, assessment_repository,
                 authorizer, *, clock=None, max_endpoints=500, max_selected_assessments=200,
                 max_findings_per_endpoint=50, max_history=2000):
        if min(max_endpoints, max_selected_assessments, max_findings_per_endpoint, max_history) <= 0 or max_endpoints > 500 or max_history > 2000:
            raise ValueError("report bounds must be positive")
        self.endpoints = endpoint_repository
        self.presence = presence_repository
        self.assessments = assessment_repository
        self.authorizer = authorizer
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_endpoints = max_endpoints
        self.max_selected_assessments = max_selected_assessments
        self.max_findings_per_endpoint = max_findings_per_endpoint
        self.max_history = max_history

    def build(self, principal, context, *, endpoint_id=None, assessment_ids=None):
        if principal.principal_type is not PrincipalType.HUMAN or not isinstance(context, OrganizationContext):
            raise PermissionError("human organization context required")
        organization_id = str(context.organization_id)
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.REPORT_READ,
            AuthorizationResource("fleet_report", metadata={"organization_id": organization_id}),
            organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)

        if endpoint_id is None:
            bounded = getattr(self.endpoints, "list_for_organization_bounded", None)
            candidates = bounded(context.organization_id, limit=self.max_endpoints + 1) if bounded else self.endpoints.list_for_organization(context.organization_id)
            endpoints = tuple(item for item in candidates
                              if _owned(item, organization_id))
        else:
            item = self.endpoints.get_for_organization(endpoint_id, context.organization_id)
            if item is None or not _owned(item, organization_id):
                raise KeyError("endpoint not found")
            endpoints = (item,)
        if len(endpoints) > self.max_endpoints:
            raise ValueError("report endpoint limit exceeded")
        endpoint_ids = {str(item.endpoint_id) for item in endpoints}

        selected_ids = tuple(assessment_ids or ())
        if (len(selected_ids) > self.max_selected_assessments
                or any(not isinstance(value, str) or not value.strip() for value in selected_ids)
                or len(set(selected_ids)) != len(selected_ids)):
            raise ValueError("invalid assessment selection")
        if selected_ids:
            assessments = []
            for assessment_id in selected_ids:
                item = self.assessments.get_for_organization(assessment_id, context.organization_id)
                if item is None or not _owned(item, organization_id) or str(item.endpoint_id) not in endpoint_ids:
                    raise KeyError("assessment not found")
                assessments.append(item)
        else:
            bounded = getattr(self.assessments, "list_for_organization_bounded", None)
            candidates = bounded(context.organization_id, endpoint_ids=endpoint_ids, limit=self.max_history + 1) if bounded else self.assessments.list_for_organization(context.organization_id)
            assessments = [item for item in candidates
                           if _owned(item, organization_id) and str(item.endpoint_id) in endpoint_ids]
            if len(assessments) > self.max_history:
                raise ValueError("report history limit exceeded; select explicit assessment IDs")

        by_endpoint = {}
        for item in assessments:
            by_endpoint.setdefault(str(item.endpoint_id), []).append(item)
        bounded_presence = getattr(self.presence, "list_for_endpoints_and_organization", None)
        presence_items = bounded_presence(context.organization_id, endpoint_ids) if bounded_presence else self.presence.list_for_organization(context.organization_id)
        presence = {str(item.endpoint_id): item for item in presence_items
                    if str(item.organization_id) == organization_id and str(item.endpoint_id) in endpoint_ids}

        rows = [self._endpoint_row(item, presence.get(str(item.endpoint_id)),
                                   by_endpoint.get(str(item.endpoint_id), ()),
                                   selected_by_endpoint_scope=endpoint_id is not None)
                for item in sorted(endpoints, key=lambda value: (value.hostname.casefold(), str(value.endpoint_id)))]
        state_counts = Counter(row["scan_status"] for row in rows)
        presence_counts = Counter(row["presence_state"] for row in rows)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("report clock must be timezone-aware")
        return {
            "organization_id": organization_id,
            "generated_at": _iso(now),
            "scope": {"kind": "endpoint" if endpoint_id is not None else "fleet",
                      "endpoint_id": str(endpoint_id) if endpoint_id is not None else None,
                      "assessment_ids": list(selected_ids),
                      "selection_mode": "explicit_assessments" if selected_ids else "latest_known_attempt"},
            "summary": {
                "total_enrolled": len(rows),
                "approved": sum(row["approved"] for row in rows),
                "pending_approval": sum(row["lifecycle_status"] == "new" for row in rows),
                "revoked": sum(row["lifecycle_status"] == "revoked" for row in rows),
                "presence": {name: presence_counts[name] for name in ("online", "stale", "offline", "unknown")},
                "selected_targets": sum(row["selected_for_report"] for row in rows),
                "scanned": state_counts["scanned"],
                "partial": state_counts["partial"],
                "not_scanned": len(rows) - state_counts["scanned"] - state_counts["partial"],
                "pending": state_counts["pending"],
                "running": state_counts["running"],
                "failed": state_counts["failed"],
                "unavailable": state_counts["unavailable"],
                "findings_from_completed_scans": sum(row["findings_count"] for row in rows
                                                    if row["scan_status"] in {"scanned", "partial"}),
            },
            "endpoints": rows,
            "advisory_note": "A missing or failed assessment is not a clean scan.",
        }

    def _endpoint_row(self, endpoint, presence, assessments, *, selected_by_endpoint_scope=False):
        ordered = sorted(assessments, key=lambda item: (_timestamp(item.requested_at), str(item.assessment_id)),
                         reverse=True)
        latest = ordered[0] if ordered else None
        state = _state(latest) if latest else None
        result = latest.result if latest else None
        scanner_results = _scanner_results(result)
        findings, malformed, omitted = _findings(result, self.max_findings_per_endpoint)
        if latest is None:
            scan_status = "not_scanned"
        elif state == "completed" and result is not None:
            scan_status = "scanned" if _fully_scanned(latest, scanner_results, malformed) else "partial"
        elif state == "endpoint_unavailable":
            scan_status = "unavailable"
        elif state in _FAILED or state == "completed":
            scan_status = "failed"
        elif state in _PENDING:
            scan_status = "pending"
        elif state in {"running", "cancel_requested"}:
            scan_status = "running"
        else:
            scan_status = "not_scanned"
        successful = next((item for item in ordered if _fully_scanned(item)), None)
        return {
            "endpoint_id": str(endpoint.endpoint_id),
            "hostname": endpoint.hostname,
            "platform": endpoint.platform.name,
            "lifecycle_status": endpoint.status.value,
            "approved": endpoint.status in _APPROVED,
            "presence_state": presence.state.value if presence else "unknown",
            "last_seen_at": _iso(presence.last_seen_at if presence else endpoint.last_seen),
            "selected_for_report": selected_by_endpoint_scope or latest is not None,
            "scan_status": scan_status,
            "latest_assessment": ({"assessment_id": str(latest.assessment_id), "status": state,
                                   "requested_at": _iso(latest.requested_at),
                                   "started_at": _iso(latest.started_at),
                                   "completed_at": _iso(latest.completed_at),
                                   "failed_at": _iso(latest.failed_at),
                                   "scanner_ids": list(latest.scanner_ids)} if latest else None),
            "last_successful_assessment_at": _iso(successful.completed_at) if successful else None,
            "findings_count": len(findings) + omitted,
            "findings": findings,
            "findings_omitted": omitted,
            "malformed_findings": malformed,
            "scanner_results": scanner_results,
            "partial_evidence": result is not None and scan_status != "scanned",
        }


def _owned(item, organization_id):
    return item.organization_id is not None and str(item.organization_id) == organization_id


def _state(item):
    return item.state.value if hasattr(item.state, "value") else str(item.state)


def _fully_scanned(assessment, scanner_results=None, malformed_findings=None):
    if assessment is None or _state(assessment) != "completed" or assessment.result is None:
        return False
    if scanner_results is None:
        scanner_results = _scanner_results(assessment.result)
    if malformed_findings is None:
        _, malformed_findings, _ = _findings(assessment.result, 0)
    result_status = getattr(assessment.result, "status", None)
    if result_status is None and isinstance(assessment.result, Mapping):
        result_status = assessment.result.get("status")
    result_status = getattr(result_status, "value", result_status)
    requested = set(assessment.scanner_ids)
    successful = {item["scanner_id"] for item in scanner_results if item["status"] == "success"}
    return (bool(requested) and requested <= successful and result_status == "completed"
            and malformed_findings == 0 and all(item["status"] == "success" for item in scanner_results))


def _timestamp(value):
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value):
    return _timestamp(value).isoformat() if value is not None else None


def _raw_findings(result):
    value = getattr(result, "findings", None)
    if value is None and isinstance(result, Mapping):
        value = result.get("findings")
    return tuple(value) if isinstance(value, (list, tuple)) else ()


def _text(value, limit):
    return str(value or "")[:limit]


def _findings(result, limit):
    projected = []
    raw_value = getattr(result, "findings", None)
    if raw_value is None and isinstance(result, Mapping):
        raw_value = result.get("findings")
    malformed = 1 if raw_value is not None and not isinstance(raw_value, (list, tuple)) else 0
    raw = _raw_findings(result)
    for finding in raw:
        if not isinstance(finding, Mapping):
            malformed += 1
            continue
        if len(projected) >= limit:
            continue
        severity = str(getattr(finding.get("severity"), "value", finding.get("severity", "unknown"))).lower()
        if severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
            severity = "unknown"
        evidence = []
        raw_evidence = finding.get("evidence")
        if not isinstance(raw_evidence, (list, tuple)):
            raw_evidence = ()
        for item in raw_evidence[:5]:
            if isinstance(item, Mapping):
                evidence.append({key: _text(item.get(key), 256) for key in
                                 ("source", "description", "observed_value", "expected_value")})
        raw_meta = finding.get("metadata")
        meta = raw_meta if isinstance(raw_meta, Mapping) else {}
        scanner_id = (
            _text(meta.get("scanner_id"), 100)
            or _text(finding.get("scanner_id"), 100)
            or _text(finding.get("component"), 100)
            or None
        )
        rule_id = _text(meta.get("rule_id"), 100) or _text(finding.get("rule_id"), 100) or None
        resource_key = meta.get("resource_key") or finding.get("resource_key")
        volume = resource_key if (
            scanner_id == "windows.bitlocker" and isinstance(resource_key, str)
            and re.fullmatch(r"[a-zA-Z]:\\?", resource_key)
        ) else None
        projected.append({
            "finding_id": _text(finding.get("finding_id"), 128) or None,
            "occurrence_id": _text(finding.get("occurrence_id"), 128) or None,
            "severity": severity,
            "title": _text(finding.get("title") or finding.get("name"), 200),
            "description": _text(finding.get("description") or finding.get("details"), 500),
            "scanner_id": scanner_id,
            "rule_id": rule_id,
            "resource_key": volume,
            "evidence": evidence,
        })
    return projected, malformed, max(0, len(raw) - malformed - len(projected))


def _scanner_results(result):
    value = getattr(result, "scanner_results", None)
    if value is None and isinstance(result, Mapping):
        value = result.get("scanner_results")
    if not isinstance(value, (list, tuple)):
        value = ()
    projected = []
    for item in (value or ())[:50]:
        if not isinstance(item, Mapping):
            continue
        status = _text(item.get("status"), 40)
        evidence = item.get("execution_evidence")
        if status == "success" and (
            item.get("error") is not None or item.get("error_category") is not None
            or not isinstance(evidence, Mapping) or evidence.get("completeness") != "complete"
        ):
            status = "unknown"
        findings = item.get("findings")
        projected.append({"scanner_id": _text(item.get("scanner_id"), 100), "status": status,
                          "finding_count": len(findings) if status in {"success", "failed"} and isinstance(findings, (list, tuple)) else 0,
                          "has_error": item.get("error") is not None or item.get("error_category") is not None or status == "unknown",
                          "error_category": _text(item.get("error_category"), 40) or None})
    return projected
