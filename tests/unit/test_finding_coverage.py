from datetime import datetime, timedelta, timezone

from backend.application.control_plane import RemoteAssessment, RemoteAssessmentState
from backend.application.organization.context import OrganizationContext
from backend.application.reporting import (
    CoverageStatus,
    FindingObservationStatus,
    LifecycleEligibilityStatus,
    TenantAssessmentDetailService,
    TenantFindingCoverageService,
    ScannerCoverageContract,
    ScannerCoverageRegistry,
    CoverageGranularity,
    CoverageAttestation,
)
from backend.domain.assessment import AssessmentStatus
from backend.domain.endpoint import Endpoint, EndpointId, PlatformInfo
from backend.domain.organization import OrganizationId
from backend.domain.security import SecurityPrincipal
from backend.domain.user import UserId
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_remote_assessment_repository import InMemoryRemoteAssessmentRepository
from backend.protocol.agent import AssessmentResultPayload, CorrelationId
from backend.domain.scanner import ScannerExecutionEvidence, ExecutionCompleteness, ResourceExecutionEvidence, ResourceEvaluationStatus


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Allow:
    def authorize(self, request):
        return type("Decision", (), {"allowed": True})()


def _world():
    organization = OrganizationId.new()
    endpoint = Endpoint(EndpointId.new(), "coverage-host", PlatformInfo("Windows"), created_at=NOW,
                        organization_id=organization)
    endpoints = InMemoryEndpointRepository()
    endpoints.add(endpoint)
    assessments = InMemoryRemoteAssessmentRepository()
    context = OrganizationContext(organization, "membership", UserId.new())
    principal = SecurityPrincipal.human(context.user_id)
    details = TenantAssessmentDetailService(endpoints, assessments, Allow())
    return organization, endpoint, assessments, context, principal, details


def _add(assessments, endpoint, organization, aid, when, *, findings=(), scanner_results=(), scanner_ids=("windows.firewall",), state=RemoteAssessmentState.COMPLETED):
    scanner_results = tuple({**item, "scanner_version": item.get("scanner_version", "1.0"),
                             "execution_evidence": item.get("execution_evidence", {
                                 "scanner_id": item.get("scanner_id"), "scanner_version": item.get("scanner_version", "1.0"),
                                 "completeness": "complete", "rules_attempted": ["firewall.profile"],
                                 "rules_completed": ["firewall.profile"], "resource_enumeration_complete": True,
                                 "resources_discovered": ["domain", "private", "public"],
                                 "resource_results": [{"resource_key": resource, "status": "evaluated"}
                                                      for resource in ("domain", "private", "public")]})
                             if item.get("scanner_id") == "windows.firewall" and item.get("status") == "success" else item}
                            for item in scanner_results)
    result = AssessmentResultPayload(aid, str(endpoint.endpoint_id), AssessmentStatus.COMPLETED,
                                     when, when, tuple(findings), tuple(scanner_results), None)
    assessments.add(RemoteAssessment(aid, endpoint.endpoint_id, CorrelationId(), tuple(scanner_ids), when,
                                     state, organization_id=organization, result=result,
                                     completed_at=when if state is RemoteAssessmentState.COMPLETED else None))


def _finding(scanner="windows.firewall", rule="firewall.profile"):
    return {"scanner_id": scanner, "rule_id": rule, "resource_key": "Public",
            "title": "Firewall profile", "severity": "high", "description": "profile check"}


def test_firewall_observed_and_strong_absence_are_distinct_and_eligible():
    organization, endpoint, assessments, context, principal, details = _world()
    _add(assessments, endpoint, organization, "observed", NOW, findings=(_finding(),),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": (_finding(),)},))
    source = details.get_detail(principal, context, "observed").findings[0]
    _add(assessments, endpoint, organization, "absent", NOW + timedelta(days=1),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": ()},))
    service = TenantFindingCoverageService(assessments, details, clock=lambda: NOW)
    report = service.history(principal, context, "observed", source.occurrence_id)
    assert [item.observation_status for item in report.observations] == [FindingObservationStatus.OBSERVED, FindingObservationStatus.NOT_OBSERVED]
    assert report.observations[0].coverage_status is CoverageStatus.COVERED
    assert report.observations[1].reason_code == "SCANNER_SUCCESS_COVERED"
    assert report.lifecycle_eligibility is LifecycleEligibilityStatus.ELIGIBLE


def test_skipped_failed_and_legacy_absence_never_claim_not_observed():
    organization, endpoint, assessments, context, principal, details = _world()
    _add(assessments, endpoint, organization, "source", NOW, findings=(_finding(),),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": (_finding(),)},))
    source = details.get_detail(principal, context, "source").findings[0]
    _add(assessments, endpoint, organization, "skipped", NOW + timedelta(days=1),
         scanner_results=({"scanner_id": "windows.firewall", "status": "skipped", "findings": ()},))
    _add(assessments, endpoint, organization, "failed", NOW + timedelta(days=2),
         scanner_results=({"scanner_id": "windows.firewall", "status": "failed", "findings": ()},))
    _add(assessments, endpoint, organization, "legacy", NOW + timedelta(days=3), scanner_results=())
    report = TenantFindingCoverageService(assessments, details).history(principal, context, "source", source.occurrence_id)
    by_id = {item.assessment_id: item for item in report.observations}
    assert by_id["skipped"].observation_status is FindingObservationStatus.NOT_EVALUATED
    assert by_id["failed"].observation_status is FindingObservationStatus.UNKNOWN
    assert by_id["legacy"].observation_status is FindingObservationStatus.UNKNOWN
    assert all(item.observation_status is not FindingObservationStatus.NOT_OBSERVED for item in report.observations[2:])


def test_unselected_scanner_is_not_evaluated_and_history_is_bounded():
    organization, endpoint, assessments, context, principal, details = _world()
    _add(assessments, endpoint, organization, "source", NOW, findings=(_finding(),),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": (_finding(),)},))
    source = details.get_detail(principal, context, "source").findings[0]
    for index in range(1, 4):
        _add(assessments, endpoint, organization, f"later-{index}", NOW + timedelta(days=index),
             scanner_ids=("windows.uac",), scanner_results=({"scanner_id": "windows.uac", "status": "skipped", "findings": ()},))
    report = TenantFindingCoverageService(assessments, details, max_assessments=2).history(
        principal, context, "source", source.occurrence_id)
    assert report.history_complete is False
    assert report.assessments_examined == 3  # bounded recent history plus the requested source
    assert report.observations[0].assessment_id == "source"
    assert report.observations[1].assessment_id == "later-2"
    assert report.observations[1].reason_code == "SCANNER_NOT_SELECTED"


def test_coverage_is_endpoint_and_organization_scoped():
    organization, endpoint, assessments, context, principal, details = _world()
    other_org = OrganizationId.new()
    other_endpoint = Endpoint(EndpointId.new(), "other", PlatformInfo("Windows"), created_at=NOW, organization_id=other_org)
    # The source has no cross-tenant history; the repository query must enforce this.
    _add(assessments, endpoint, organization, "source", NOW, findings=(_finding(),),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": (_finding(),)},))
    _add(assessments, other_endpoint, other_org, "foreign", NOW + timedelta(days=1),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": ()},))
    source = details.get_detail(principal, context, "source").findings[0]
    report = TenantFindingCoverageService(assessments, details).history(principal, context, "source", source.occurrence_id)
    assert [item.assessment_id for item in report.observations] == ["source"]


def test_contract_registry_rejects_duplicates_and_invalid_strong_contracts():
    contract = ScannerCoverageContract("windows.test", CoverageGranularity.RULE,
                                       "one check", rule_ids=("rule-1",), allows_absence_inference=True)
    registry = ScannerCoverageRegistry((contract,))
    assert registry.get("windows.test") is contract
    try:
        registry.register(contract)
        assert False, "duplicate contract registration must fail"
    except ValueError:
        pass
    try:
        ScannerCoverageContract("windows.invalid", CoverageGranularity.RULE, "bad")
        assert False, "rule contract without rules must fail"
    except ValueError:
        pass


def test_contract_version_mismatch_and_partial_success_are_conservative():
    organization, endpoint, assessments, context, principal, details = _world()
    _add(assessments, endpoint, organization, "source", NOW, findings=(_finding(),),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "findings": (_finding(),), "scanner_version": "2.0"},))
    source = details.get_detail(principal, context, "source").findings[0]
    _add(assessments, endpoint, organization, "mismatch", NOW + timedelta(days=1),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "scanner_version": "2.0", "native_metrics": {}},))
    report = TenantFindingCoverageService(
        assessments, details,
        coverage_registry=ScannerCoverageRegistry((ScannerCoverageContract(
            "windows.firewall", CoverageGranularity.RESOURCE, "versioned profile", rule_ids=("firewall.profile",),
            resource_scope=("domain", "private", "public"), scanner_versions=("1.0",), allows_absence_inference=True),)),
    ).history(principal, context, "source", source.occurrence_id)
    assert report.observations[-1].observation_status is FindingObservationStatus.UNKNOWN
    _add(assessments, endpoint, organization, "partial", NOW + timedelta(days=2),
         scanner_results=({"scanner_id": "windows.firewall", "status": "success", "scanner_version": "1.0",
                           "native_metrics": {"partial": True}},))
    report = TenantFindingCoverageService(assessments, details).history(principal, context, "source", source.occurrence_id)
    assert report.observations[-1].reason_code == "PARTIAL_EXECUTION"


def test_attestation_is_json_safe_and_strong_only_for_declared_contract():
    attestation = CoverageAttestation("windows.firewall", "1.0", CoverageGranularity.RESOURCE,
                                      "firewall.profile", "public", "success", 1,
                                      CoverageStatus.COVERED, True, "SCANNER_SUCCESS_COVERED")
    assert attestation.to_dict()["absence_inference_allowed"] is True
    assert attestation.to_dict()["coverage_granularity"] == "resource"


def test_weak_existing_scanners_are_observed_but_never_claim_absence():
    for scanner in ("windows.uac", "windows.bitlocker", "windows.smb"):
        organization, endpoint, assessments, context, principal, details = _world()
        finding = _finding(scanner, f"{scanner}.check")
        _add(assessments, endpoint, organization, "source", NOW, findings=(finding,),
             scanner_ids=(scanner,), scanner_results=({"scanner_id": scanner, "status": "success", "findings": (finding,)},))
        source = details.get_detail(principal, context, "source").findings[0]
        _add(assessments, endpoint, organization, "absent", NOW + timedelta(days=1),
             scanner_ids=(scanner,), scanner_results=({"scanner_id": scanner, "status": "success", "findings": ()},))
        report = TenantFindingCoverageService(assessments, details).history(principal, context, "source", source.occurrence_id)
        assert report.observations[0].observation_status is FindingObservationStatus.OBSERVED
        assert report.observations[1].observation_status is FindingObservationStatus.UNKNOWN


def test_execution_evidence_round_trip_and_bounds():
    evidence = ScannerExecutionEvidence(
        "windows.firewall", "1.0", ExecutionCompleteness.COMPLETE,
        rules_attempted=("firewall.profile",), rules_completed=("firewall.profile",),
        resource_enumeration_complete=True, resources_discovered=("public",),
        resource_results=(ResourceExecutionEvidence("public", ResourceEvaluationStatus.EVALUATED),),
        normalization_status="complete")
    assert ScannerExecutionEvidence.from_dict(evidence.to_dict()) == evidence
    try:
        ScannerExecutionEvidence("windows.firewall", completeness=ExecutionCompleteness.COMPLETE,
                                 rules_attempted=("known",), rules_completed=("made.up",))
        assert False, "completed unknown rule must fail validation"
    except ValueError:
        pass


def test_resource_mismatch_cannot_support_absence():
    contract = ScannerCoverageContract("windows.firewall", CoverageGranularity.RESOURCE, "profile", 
                                       rule_ids=("firewall.profile",), resource_scope=("public",),
                                       allows_absence_inference=True)
    evidence = ScannerExecutionEvidence("windows.firewall", "1.0", ExecutionCompleteness.COMPLETE,
                                        rules_attempted=("firewall.profile",), rules_completed=("firewall.profile",),
                                        resource_enumeration_complete=True, resources_discovered=("private",),
                                        resource_results=(ResourceExecutionEvidence("private", ResourceEvaluationStatus.EVALUATED),))
    fp = {"components": {"scanner_id": "windows.firewall", "rule_id": "firewall.profile", "resource_key": "public"}}
    assert contract.covers(fp, "1.0", evidence) is False
