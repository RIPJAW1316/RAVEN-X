"""Focused regression suite for RAVEN-X AI Analyst fix plan, 24-check accounting, and offline rules."""

from datetime import datetime, timezone
import json
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from backend.agent.windows_scanners import windows_read_only_scanners
from backend.api.tenant_insights import TenantInsightsDependencies, create_tenant_insights_router
from backend.application.ai import TenantLocalAnalysisService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService)
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.application.reporting.fleet_report import TenantFleetReportService
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.presence import EndpointPresence, PresenceState
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_presence_repository import InMemoryEndpointPresenceRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository


NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
PASSWORD = "review demo password"


class AssessmentStore:
    def __init__(self):
        self.items = []

    def list_for_organization(self, organization_id):
        return tuple(item for item in self.items if str(item.organization_id) == str(organization_id))

    def get_for_organization(self, assessment_id, organization_id):
        return next((item for item in self.list_for_organization(organization_id)
                     if item.assessment_id == assessment_id), None)


class MockLocalAIProvider:
    enabled = True
    model = "meta-llama-3.1-8b-instruct"

    def __init__(self, *, fail=False, prioritize_output=None):
        self.prompts = []
        self.prioritize_prompts = []
        self.fail = fail
        self.prioritize_output = prioritize_output

    def analyze(self, facts):
        self.prompts.append(facts)
        if self.fail:
            raise TimeoutError("provider response must not leak")
        return "Advisory: review the finding."

    def prioritize_findings(self, prompt_json: str) -> str:
        self.prioritize_prompts.append(prompt_json)
        if self.fail:
            raise TimeoutError("provider timeout")
        if self.prioritize_output is not None:
            return self.prioritize_output
        # Default behavior: return prompt refs in given order
        data = json.loads(prompt_json)
        refs = [item["ref"] for item in data.get("findings", ())]
        return json.dumps(refs)


def _assessment(endpoint, organization_id, assessment_id, state, requested_at, *, scanner_ids=None, result=None):
    scanners = scanner_ids or ("windows.firewall",)
    return SimpleNamespace(
        endpoint_id=endpoint.endpoint_id,
        organization_id=organization_id,
        assessment_id=assessment_id,
        state=state,
        requested_at=requested_at,
        started_at=requested_at,
        completed_at=requested_at if state == "completed" else None,
        failed_at=requested_at if state == "failed" else None,
        scanner_ids=scanners,
        result=result,
    )


def _world(permissions=("reports.read", "ai.use"), *, provider=None, max_prompt_chars=12000):
    users = InMemoryUserRepository()
    user = HumanIdentityService(users).create_initial_user("operator@example.com", "Operator", PASSWORD)
    organizations = InMemoryOrganizationRepository()
    organization = OrganizationService(organizations).create("Lab")
    foreign_organization = OrganizationService(organizations).create("Other lab")
    memberships = InMemoryOrganizationMembershipRepository()
    membership = OrganizationMembershipService(memberships, organizations, users).create(
        user.user_id, organization.organization_id)
    roles, bindings = InMemoryRoleRepository(), InMemoryRoleBindingRepository()
    role = RoleService(roles).create(organization.organization_id, "Reporter", permissions)
    RoleBindingService(bindings, roles, memberships).create(
        organization.organization_id, membership.membership_id, role.role_id)
    endpoints = InMemoryEndpointRepository()
    presence = InMemoryEndpointPresenceRepository()
    assessments = AssessmentStore()
    authorizer = OrganizationRbacAuthorizer(
        membership_repository=memberships, role_binding_repository=bindings,
        role_repository=roles, organization_repository=organizations,
        endpoint_repository=endpoints)
    report = TenantFleetReportService(endpoints, presence, assessments, authorizer, clock=lambda: NOW)
    ai = TenantLocalAnalysisService(report, authorizer, provider or MockLocalAIProvider(), clock=lambda: NOW,
                                    max_prompt_chars=max_prompt_chars)
    auth = HumanAuthenticationService(users)
    token = auth.authenticate(user.email, PASSWORD).session_token
    context_resolver = OrganizationContextResolver(users, memberships, organizations)
    app = FastAPI()
    app.include_router(create_tenant_insights_router(TenantInsightsDependencies(
        HumanSessionAuthenticator(users), users, context_resolver, report, ai)), prefix="/api/v1")
    return SimpleNamespace(
        client=TestClient(app), token=token, user=user, organization=organization,
        foreign_organization=foreign_organization, endpoints=endpoints,
        presence=presence, assessments=assessments, report=report, ai=ai,
        provider=ai.provider, context=context_resolver.resolve(SecurityPrincipal.human(user.user_id),
                                                                organization.organization_id)
    )


def _headers(world):
    return {"Authorization": "Bearer " + world.token}


def test_full_24_check_assessment_accounts_for_all_checks():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "full-scan-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    world.presence.upsert(EndpointPresence(str(endpoint.endpoint_id), str(org), PresenceState.ONLINE, last_seen_at=NOW))

    all_scanners = [s.manifest.scanner_id for s in windows_read_only_scanners()]
    assert len(all_scanners) == 24

    # 1 finding from firewall, remaining 23 scanners succeed with 0 findings
    findings = [{
        "finding_id": "fw-1",
        "occurrence_id": "scan-full:fw-1",
        "severity": "high",
        "title": "Windows Firewall Profile Disabled",
        "description": "Public firewall profile is disabled.",
        "scanner_id": "windows.firewall",
        "rule_id": "firewall.profile",
        "evidence": [{"observed_value": "off"}],
    }]
    scanner_results = []
    for sid in all_scanners:
        if sid == "windows.firewall":
            scanner_results.append({
                "scanner_id": sid,
                "status": "success",
                "findings": ["fw-1"],
                "execution_evidence": {"completeness": "complete"},
            })
        else:
            scanner_results.append({
                "scanner_id": sid,
                "status": "success",
                "findings": [],
                "execution_evidence": {"completeness": "complete"},
            })

    result = SimpleNamespace(status="completed", findings=findings, scanner_results=scanner_results)
    world.assessments.items.append(
        _assessment(endpoint, org, "scan-full", "completed", NOW, scanner_ids=tuple(all_scanners), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available"
    assert data["fallback_used"] is False

    # Check 24-check accounting
    plan = data["plan"]
    blind_spots = data["blind_spots"]
    out_of_scope = data["out_of_scope_checks"]

    assert len(plan) == 1
    assert plan[0]["scanner_id"] == "windows.firewall"
    assert plan[0]["occurrence_id"] == "scan-full:fw-1"
    assert len(blind_spots) == 0
    assert len(out_of_scope) == 0

    # Narrative checks: contains plain-language and never says "verified clean"
    analysis_text = data["analysis"]
    assert "verified clean" not in analysis_text.lower()
    assert "no finding observed in completed coverage" in analysis_text
    assert "Enable Windows Defender Firewall" in analysis_text


def test_subset_assessment_with_missing_result():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "subset-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)

    # Requested subset: firewall, uac, and smb (3 checks)
    requested_subset = ("windows.firewall", "windows.uac", "windows.smb")
    findings = [{
        "finding_id": "smb-1",
        "occurrence_id": "scan-sub:smb-1",
        "severity": "critical",
        "title": "SMBv1 Protocol Enabled",
        "description": "Legacy SMB1 is enabled on server.",
        "scanner_id": "windows.smb",
        "rule_id": "smb.smb1_enabled",
        "evidence": [{"observed_value": "enabled"}],
    }]
    # firewall succeeds with no findings, smb has finding, uac result is MISSING
    scanner_results = [
        {"scanner_id": "windows.firewall", "status": "success", "findings": [], "execution_evidence": {"completeness": "complete"}},
        {"scanner_id": "windows.smb", "status": "success", "findings": ["smb-1"], "execution_evidence": {"completeness": "complete"}},
        # windows.uac is omitted from scanner_results
    ]

    result = SimpleNamespace(status="completed", findings=findings, scanner_results=scanner_results)
    world.assessments.items.append(
        _assessment(endpoint, org, "scan-sub", "completed", NOW, scanner_ids=requested_subset, result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available"

    # Plan contains smb-1
    assert len(data["plan"]) == 1
    assert data["plan"][0]["scanner_id"] == "windows.smb"

    # windows.uac was requested but has no execution result -> blind spot
    uac_blind_spots = [b for b in data["blind_spots"] if b["scanner_id"] == "windows.uac"]
    assert len(uac_blind_spots) == 1
    assert uac_blind_spots[0]["status"] == "unverified"
    assert "No execution result" in uac_blind_spots[0]["reason"]

    # 21 unrequested checks are out-of-scope
    assert len(data["out_of_scope_checks"]) == 21
    for ooc in data["out_of_scope_checks"]:
        assert ooc["scanner_id"] not in requested_subset
        assert "Not requested" in ooc["reason"]


def test_vm_bitlocker_and_failed_wifi_fixture():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "rehearsal-vm", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)

    # Actual VM rehearsal: BitLocker is 100% encrypted but protection is off.
    # Wi-Fi returns READ_FAILED.
    findings = [{
        "finding_id": "bl-1",
        "occurrence_id": "scan-vm:bl-1",
        "severity": "high",
        "title": "BitLocker Protection Suspended or Off",
        "description": "C: is 100% encrypted; VolumeStatus=FullyEncrypted, ProtectionStatus=Off.",
        "scanner_id": "windows.bitlocker",
        "rule_id": "bitlocker.os_volume",
        "resource_key": "C:",
        "evidence": [{"source": "BitLocker", "observed_value": "FullyEncrypted; ProtectionStatus=Off; EncryptionPercentage=100"}],
    }]
    scanner_results = [
        {"scanner_id": "windows.bitlocker", "status": "success", "findings": ["bl-1"], "execution_evidence": {"completeness": "complete"}},
        {"scanner_id": "windows.wifi", "status": "failed", "error_category": "READ_FAILED", "has_error": True, "findings": []},
    ]

    result = SimpleNamespace(status="completed", findings=findings, scanner_results=scanner_results)
    world.assessments.items.append(
        _assessment(endpoint, org, "scan-vm", "completed", NOW,
                    scanner_ids=("windows.bitlocker", "windows.wifi"), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available"

    # BitLocker recommendation
    plan = data["plan"]
    assert len(plan) == 1
    bl_action = plan[0]["action"]
    assert "The OS volume (C:) is encrypted but protection is off" in bl_action
    assert "Investigate why protection is suspended or disabled before reviewing whether to resume BitLocker protection." in bl_action

    # Wi-Fi blind spot: READ_FAILED -> collection failed and cipher unverified
    wifi_blind_spots = [b for b in data["blind_spots"] if b["scanner_id"] == "windows.wifi"]
    assert len(wifi_blind_spots) == 1
    assert "Wi-Fi collection failed; the active Wi-Fi cipher remains unverified." == wifi_blind_spots[0]["reason"]
    assert "no adapter" not in json.dumps(data).lower()


def test_unsupported_wifi_fixture():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "wired-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)

    scanner_results = [
        {"scanner_id": "windows.wifi", "status": "incompatible", "error_category": "UNSUPPORTED", "findings": []},
    ]
    result = SimpleNamespace(status="completed", findings=[], scanner_results=scanner_results)
    world.assessments.items.append(
        _assessment(endpoint, org, "scan-wired", "completed", NOW, scanner_ids=("windows.wifi",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()

    wifi_blind_spots = [b for b in data["blind_spots"] if b["scanner_id"] == "windows.wifi"]
    assert len(wifi_blind_spots) == 1
    assert wifi_blind_spots[0]["reason"] == "The Wi-Fi cipher could not be verified on this interface."


def test_extended_check_autorun_in_fix_plan():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "autorun-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)

    findings = [{
        "finding_id": "autorun-1",
        "occurrence_id": "scan-autorun:autorun-1",
        "severity": "low",
        "title": "Machine AutoRun Restriction Not Enforced",
        "description": "The machine policy does not disable AutoRun for every drive type.",
        "scanner_id": "windows.autorun",
        "rule_id": "autorun.not_enforced",
        "evidence": [{"observed_value": "NoDriveTypeAutoRun=145"}],
    }]
    scanner_results = [
        {"scanner_id": "windows.autorun", "status": "success", "findings": ["autorun-1"], "execution_evidence": {"completeness": "complete"}},
    ]
    result = SimpleNamespace(status="completed", findings=findings, scanner_results=scanner_results)
    world.assessments.items.append(
        _assessment(endpoint, org, "scan-autorun", "completed", NOW, scanner_ids=("windows.autorun",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["plan"]) == 1
    action = data["plan"][0]["action"]
    assert "Enforce machine policy disabling AutoRun on all drive types" in action


def test_repeated_finding_id_across_two_machines_stays_separated():
    world = _world()
    org = world.organization.organization_id
    ep1 = Endpoint(EndpointId.new(), "machine-alpha", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                   created_at=NOW, organization_id=org)
    ep2 = Endpoint(EndpointId.new(), "machine-beta", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                   created_at=NOW, organization_id=org)
    world.endpoints.add(ep1)
    world.endpoints.add(ep2)

    # Both machines have finding_id="fw-disabled"
    f1 = {
        "finding_id": "fw-disabled",
        "occurrence_id": "scan-alpha:fw-disabled",
        "severity": "high",
        "title": "Firewall Disabled",
        "description": "Domain profile is off",
        "scanner_id": "windows.firewall",
        "rule_id": "firewall.profile",
    }
    f2 = {
        "finding_id": "fw-disabled",
        "occurrence_id": "scan-beta:fw-disabled",
        "severity": "high",
        "title": "Firewall Disabled",
        "description": "Public profile is off",
        "scanner_id": "windows.firewall",
        "rule_id": "firewall.profile",
    }
    r1 = SimpleNamespace(status="completed", findings=[f1], scanner_results=[
        {"scanner_id": "windows.firewall", "status": "success", "findings": ["fw-disabled"], "execution_evidence": {"completeness": "complete"}}])
    r2 = SimpleNamespace(status="completed", findings=[f2], scanner_results=[
        {"scanner_id": "windows.firewall", "status": "success", "findings": ["fw-disabled"], "execution_evidence": {"completeness": "complete"}}])

    world.assessments.items.extend([
        _assessment(ep1, org, "scan-alpha", "completed", NOW, result=r1),
        _assessment(ep2, org, "scan-beta", "completed", NOW, result=r2),
    ])

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    plan = data["plan"]
    assert len(plan) == 2

    # Verify distinct occurrence_ids and endpoint hostnames
    occ_ids = {p["occurrence_id"] for p in plan}
    assert "scan-alpha:fw-disabled" in occ_ids
    assert "scan-beta:fw-disabled" in occ_ids
    hostnames = {p["hostname"] for p in plan}
    assert hostnames == {"machine-alpha", "machine-beta"}


def test_successful_model_ordering_reorders_plan():
    provider = MockLocalAIProvider(prioritize_output=json.dumps(["f2", "f1"]))
    world = _world(provider=provider)
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "priority-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    f1 = {"finding_id": "f-1", "occurrence_id": "scan-1:f-1", "severity": "medium",
          "title": "UAC Configuration", "description": "ConsentPromptBehaviorAdmin is 0", "scanner_id": "windows.uac",
          "rule_id": "uac.configuration"}
    f2 = {"finding_id": "f-2", "occurrence_id": "scan-1:f-2", "severity": "high",
          "title": "Firewall Disabled", "description": "Public profile is off", "scanner_id": "windows.firewall",
          "rule_id": "firewall.profile"}

    result = SimpleNamespace(status="completed", findings=[f1, f2], scanner_results=[
        {"scanner_id": "windows.uac", "status": "success", "findings": ["f-1"], "execution_evidence": {"completeness": "complete"}},
        {"scanner_id": "windows.firewall", "status": "success", "findings": ["f-2"], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-1", "completed", NOW, scanner_ids=("windows.uac", "windows.firewall"), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available"
    assert data["model"] == "meta-llama-3.1-8b-instruct"
    assert data["fallback_used"] is False

    # The model reverses the baseline severity order.
    plan = data["plan"]
    assert len(plan) == 2
    assert plan[0]["occurrence_id"] == "scan-1:f-1"
    assert plan[1]["occurrence_id"] == "scan-1:f-2"


def test_invalid_boolean_returns_422():
    world = _world()
    org = world.organization.organization_id
    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": "not_a_bool"},
        headers=_headers(world),
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "INVALID_REQUEST"

    int_response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": 1},
        headers=_headers(world),
    )
    assert int_response.status_code == 422
    assert int_response.json()["detail"]["code"] == "INVALID_REQUEST"

    # Reject explicit offline_plan: null
    null_response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": None},
        headers=_headers(world),
    )
    assert null_response.status_code == 422
    assert null_response.json()["detail"]["code"] == "INVALID_REQUEST"

    # Enrolled endpoint so analyze can succeed
    ep = Endpoint(EndpointId.new(), "ok-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(
        {"scanner_id": "windows.firewall", "status": "success", "findings": [], "execution_evidence": {"completeness": "complete"}},))
    world.assessments.items.append(_assessment(ep, org, "scan-ok", "completed", NOW, result=result))

    # Omitted offline_plan succeeds (200)
    omitted_resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={},
        headers=_headers(world),
    )
    assert omitted_resp.status_code == 200

    # Explicit offline_plan: false succeeds (200)
    false_resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": False},
        headers=_headers(world),
    )
    assert false_resp.status_code == 200


def test_report_truncation_disclosed():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "truncated-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    findings = [
        {"finding_id": f"f-{i}", "occurrence_id": f"scan-trunc:f-{i}", "severity": "medium",
         "title": f"Finding {i}", "description": f"Details {i}", "scanner_id": "windows.firewall",
         "rule_id": "firewall.profile"}
        for i in range(5)
    ]
    result = SimpleNamespace(status="completed", findings=findings, scanner_results=[
        {"scanner_id": "windows.firewall", "status": "success", "findings": [f["finding_id"] for f in findings],
         "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-trunc", "completed", NOW, scanner_ids=("windows.firewall",), result=result)
    )

    # Monkey patch the report service max findings limit to 2 to force truncation disclosure
    orig_limit = world.report.max_findings_per_endpoint
    world.report.max_findings_per_endpoint = 2
    try:
        response = world.client.post(
            f"/api/v1/organizations/{org}/ai/analyze",
            json={"offline_plan": True},
            headers=_headers(world),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["coverage"]["truncated"] is True
        assert "omitted" in data["analysis"]
    finally:
        world.report.max_findings_per_endpoint = orig_limit


def test_model_failure_and_hallucination_falls_back_to_offline_rules():
    f1 = {"finding_id": "f-1", "occurrence_id": "scan-1:f-1", "severity": "high",
          "title": "Firewall Disabled", "description": "Public profile is off", "scanner_id": "windows.firewall",
          "rule_id": "firewall.profile"}
    result = SimpleNamespace(status="completed", findings=[f1], scanner_results=[
        {"scanner_id": "windows.firewall", "status": "success", "findings": ["f-1"], "execution_evidence": {"completeness": "complete"}},
    ])

    # Case A: Timeout / exception
    provider_fail = MockLocalAIProvider(fail=True)
    world_fail = _world(provider=provider_fail)
    ep_fail = Endpoint(EndpointId.new(), "fail-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       created_at=NOW, organization_id=world_fail.organization.organization_id)
    world_fail.endpoints.add(ep_fail)
    world_fail.assessments.items.append(
        _assessment(ep_fail, world_fail.organization.organization_id, "scan-1", "completed", NOW,
                    scanner_ids=("windows.firewall",), result=result)
    )

    resp_timeout = world_fail.client.post(
        f"/api/v1/organizations/{world_fail.organization.organization_id}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world_fail),
    )
    assert resp_timeout.status_code == 200
    data_timeout = resp_timeout.json()
    assert data_timeout["status"] == "available"
    assert data_timeout["model"] == "Offline rules"
    assert data_timeout["fallback_used"] is True
    assert len(data_timeout["plan"]) == 1

    # Case B: Model hallucinates invented reference
    provider_invent = MockLocalAIProvider(prioritize_output=json.dumps(["invented-ref-999"]))
    world_invent = _world(provider=provider_invent)
    ep_invent = Endpoint(EndpointId.new(), "invent-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                         created_at=NOW, organization_id=world_invent.organization.organization_id)
    world_invent.endpoints.add(ep_invent)
    world_invent.assessments.items.append(
        _assessment(ep_invent, world_invent.organization.organization_id, "scan-1", "completed", NOW,
                    scanner_ids=("windows.firewall",), result=result)
    )
    resp_invent = world_invent.client.post(
        f"/api/v1/organizations/{world_invent.organization.organization_id}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world_invent),
    )
    assert resp_invent.status_code == 200
    data_invent = resp_invent.json()
    assert data_invent["status"] == "available"
    assert data_invent["model"] == "Offline rules"
    assert data_invent["fallback_used"] is True

    # Case C: Model returns duplicate references
    provider_dup = MockLocalAIProvider(prioritize_output=json.dumps(["f1", "f1"]))
    world_dup = _world(provider=provider_dup)
    ep_dup = Endpoint(EndpointId.new(), "dup-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                      created_at=NOW, organization_id=world_dup.organization.organization_id)
    world_dup.endpoints.add(ep_dup)
    world_dup.assessments.items.append(
        _assessment(ep_dup, world_dup.organization.organization_id, "scan-1", "completed", NOW,
                    scanner_ids=("windows.firewall",), result=result)
    )
    resp_dup = world_dup.client.post(
        f"/api/v1/organizations/{world_dup.organization.organization_id}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world_dup),
    )
    assert resp_dup.status_code == 200
    data_dup = resp_dup.json()
    assert data_dup["model"] == "Offline rules"
    assert data_dup["fallback_used"] is True

    # Case D: Model returns non-JSON or malformed output
    provider_malformed = MockLocalAIProvider(prioritize_output="Here are your results: ref-1 is important.")
    world_malformed = _world(provider=provider_malformed)
    ep_malformed = Endpoint(EndpointId.new(), "malformed-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                            created_at=NOW, organization_id=world_malformed.organization.organization_id)
    world_malformed.endpoints.add(ep_malformed)
    world_malformed.assessments.items.append(
        _assessment(ep_malformed, world_malformed.organization.organization_id, "scan-1", "completed", NOW,
                    scanner_ids=("windows.firewall",), result=result)
    )
    resp_malformed = world_malformed.client.post(
        f"/api/v1/organizations/{world_malformed.organization.organization_id}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world_malformed),
    )
    assert resp_malformed.status_code == 200
    data_malformed = resp_malformed.json()
    assert data_malformed["model"] == "Offline rules"
    assert data_malformed["fallback_used"] is True


def test_cross_tenant_isolation_preserved():
    world = _world()
    org = world.organization.organization_id
    foreign_org = world.foreign_organization.organization_id
    foreign_ep = Endpoint(EndpointId.new(), "foreign-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                          created_at=NOW, organization_id=foreign_org)
    world.endpoints.add(foreign_ep)

    # Attempting to analyze an endpoint from another tenant returns 404
    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"endpoint_id": str(foreign_ep.endpoint_id), "offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 404


def test_legacy_behavior_preserved_when_offline_plan_omitted():
    provider_disabled = MockLocalAIProvider()
    provider_disabled.enabled = False
    world_disabled = _world(provider=provider_disabled)
    org = world_disabled.organization.organization_id
    ep = Endpoint(EndpointId.new(), "legacy-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world_disabled.endpoints.add(ep)
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(
        {"scanner_id": "windows.firewall", "status": "success", "findings": [], "execution_evidence": {"completeness": "complete"}},))
    world_disabled.assessments.items.append(_assessment(ep, org, "scan-legacy", "completed", NOW, result=result))

    # Omitted offline_plan -> preserves LOCAL_AI_DISABLED
    resp = world_disabled.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={}, headers=_headers(world_disabled))
    assert resp.status_code == 200
    assert resp.json()["reason_code"] == "LOCAL_AI_DISABLED"

    # offline_plan: False -> also preserves LOCAL_AI_DISABLED
    resp_false = world_disabled.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"offline_plan": False}, headers=_headers(world_disabled))
    assert resp_false.status_code == 200
    assert resp_false.json()["reason_code"] == "LOCAL_AI_DISABLED"

    # Provider failure with offline_plan omitted -> preserves LOCAL_AI_UNAVAILABLE
    provider_fail = MockLocalAIProvider(fail=True)
    world_fail = _world(provider=provider_fail)
    ep_fail = Endpoint(EndpointId.new(), "legacy-fail-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       created_at=NOW, organization_id=world_fail.organization.organization_id)
    world_fail.endpoints.add(ep_fail)
    world_fail.assessments.items.append(_assessment(ep_fail, world_fail.organization.organization_id, "scan-legacy-fail", "completed", NOW, result=result))
    resp_unavailable = world_fail.client.post(f"/api/v1/organizations/{world_fail.organization.organization_id}/ai/analyze", json={}, headers=_headers(world_fail))
    assert resp_unavailable.status_code == 200
    assert resp_unavailable.json()["reason_code"] == "LOCAL_AI_UNAVAILABLE"

    # Empty scope -> preserves NO_COMPLETED_EVIDENCE (both with and without offline_plan)
    world_empty = _world()
    resp_empty_legacy = world_empty.client.post(
        f"/api/v1/organizations/{world_empty.organization.organization_id}/ai/analyze", json={}, headers=_headers(world_empty))
    assert resp_empty_legacy.status_code == 200
    assert resp_empty_legacy.json()["reason_code"] == "NO_COMPLETED_EVIDENCE"

    resp_empty_offline = world_empty.client.post(
        f"/api/v1/organizations/{world_empty.organization.organization_id}/ai/analyze", json={"offline_plan": True}, headers=_headers(world_empty))
    assert resp_empty_offline.status_code == 200
    assert resp_empty_offline.json()["reason_code"] == "NO_COMPLETED_EVIDENCE"


def test_real_wire_shape_preserves_scanner_and_rule_metadata_without_toplevel_scanner_id():
    """Agent wire puts scanner_id and rule_id inside metadata, with no top-level scanner_id."""
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "defender-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    # Real agent wire finding for Defender Real-Time Protection Off
    # Note: no top-level scanner_id; metadata contains scanner_id and rule_id
    wire_finding = {
        "finding_id": "def-rt-1",
        "occurrence_id": "scan-def:def-rt-1",
        "severity": "high",
        "category": "Antivirus",
        "title": "Defender Real-Time Protection Off",
        "details": "Defender reports that real-time protection is disabled.",
        "component": "Antivirus",
        "metadata": {
            "scanner_id": "windows.defender",
            "rule_id": "defender.realtime_off",
            "resource_key": "local",
        },
        "evidence": [{"source": "Get-MpComputerStatus", "description": "Real-time off", "observed_value": "False"}],
    }
    result = SimpleNamespace(status="completed", findings=[wire_finding], scanner_results=[
        {"scanner_id": "windows.defender", "status": "success", "findings": ["def-rt-1"], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-def", "completed", NOW, scanner_ids=("windows.defender",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    plan = data["plan"]
    assert len(plan) == 1
    assert plan[0]["rule_id"] == "defender.realtime_off"
    # MUST get the real-time protection action, NOT the antivirus-engine action
    assert plan[0]["action"] == "Enable Microsoft Defender Real-Time Protection."
    assert "antivirus engine" not in plan[0]["action"].lower()


def test_defender_antivirus_off_gets_antivirus_engine_action():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "av-off-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    wire_finding = {
        "finding_id": "def-av-1",
        "occurrence_id": "scan-av:def-av-1",
        "severity": "high",
        "category": "Antivirus",
        "title": "Microsoft Defender Antivirus Off",
        "details": "Defender reports that its antivirus engine is disabled.",
        "component": "Antivirus",
        "metadata": {
            "scanner_id": "windows.defender",
            "rule_id": "defender.antivirus_off",
            "resource_key": "local",
        },
        "evidence": [{"source": "Get-MpComputerStatus", "observed_value": "False"}],
    }
    result = SimpleNamespace(status="completed", findings=[wire_finding], scanner_results=[
        {"scanner_id": "windows.defender", "status": "success", "findings": ["def-av-1"], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-av", "completed", NOW, scanner_ids=("windows.defender",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    plan = data["plan"]
    assert len(plan) == 1
    assert plan[0]["action"] == "Enable the Microsoft Defender Antivirus engine."


def test_fully_decrypted_bitlocker_volume_not_called_encrypted():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "decrypted-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    wire_finding = {
        "finding_id": "bl-decrypted",
        "occurrence_id": "scan-dec:bl-decrypted",
        "severity": "high",
        "category": "Disk Encryption",
        "title": "BitLocker Not Enabled",
        "details": "C: is 0% encrypted; VolumeStatus=FullyDecrypted, ProtectionStatus=Off.",
        "component": "BitLocker",
        "metadata": {
            "scanner_id": "windows.bitlocker",
            "rule_id": "bitlocker.os_volume",
            "resource_key": "c:",
        },
        "evidence": [{"source": "Get-BitLockerVolume", "observed_value": "FullyDecrypted; ProtectionStatus=Off; EncryptionPercentage=0"}],
    }
    result = SimpleNamespace(status="completed", findings=[wire_finding], scanner_results=[
        {"scanner_id": "windows.bitlocker", "status": "success", "findings": ["bl-decrypted"], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-dec", "completed", NOW, scanner_ids=("windows.bitlocker",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    plan = data["plan"]
    assert len(plan) == 1
    action = plan[0]["action"]
    # Fully decrypted volume must NOT be called encrypted
    assert "is encrypted but protection is off" not in action
    assert "Enable BitLocker drive encryption on The OS volume (C:)." == action
    assert "unencrypted and unprotected" in plan[0]["rationale"]


def test_non_c_drive_bitlocker_volume_accurate():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "data-drive-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    wire_finding = {
        "finding_id": "bl-d-drive",
        "occurrence_id": "scan-d:bl-d-drive",
        "severity": "high",
        "category": "Disk Encryption",
        "title": "BitLocker Protection Suspended or Off",
        "details": "D: is 100% encrypted; VolumeStatus=FullyEncrypted, ProtectionStatus=Off.",
        "component": "BitLocker",
        "metadata": {
            "scanner_id": "windows.bitlocker",
            "rule_id": "bitlocker.os_volume",
            "resource_key": "d:",
        },
        "evidence": [{"source": "Get-BitLockerVolume", "observed_value": "FullyEncrypted; ProtectionStatus=Off; EncryptionPercentage=100"}],
    }
    result = SimpleNamespace(status="completed", findings=[wire_finding], scanner_results=[
        {"scanner_id": "windows.bitlocker", "status": "success", "findings": ["bl-d-drive"], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-d", "completed", NOW, scanner_ids=("windows.bitlocker",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    plan = data["plan"]
    assert len(plan) == 1
    # Accurately names The D: volume, does NOT call it OS volume (C:)
    assert "The D: volume is encrypted but protection is off." in plan[0]["action"]
    assert "(C:)" not in plan[0]["action"]


def test_unknown_legacy_rule_receives_generic_review():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "legacy-rule-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    wire_finding = {
        "finding_id": "custom-1",
        "occurrence_id": "scan-custom:custom-1",
        "severity": "medium",
        "category": "Custom",
        "title": "Custom Organization Check",
        "details": "Specific custom setting is out of compliance.",
        "component": "CustomChecker",
        "metadata": {
            "scanner_id": "custom.unknown_scanner",
            "rule_id": "custom.unknown_rule",
            "resource_key": "local",
        },
        "evidence": [],
    }
    result = SimpleNamespace(status="completed", findings=[wire_finding], scanner_results=[
        {"scanner_id": "custom.unknown_scanner", "status": "success", "findings": ["custom-1"], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-custom", "completed", NOW, scanner_ids=("custom.unknown_scanner",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    plan = data["plan"]
    assert len(plan) == 1
    # Generic review action without substring or prefix inference
    assert "Review and remediate Custom Organization Check on the endpoint" in plan[0]["action"]
    assert "Observed finding: Specific custom setting is out of compliance." in plan[0]["rationale"]


def test_truthful_status_when_no_findings_and_no_model_call():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "clean-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    result = SimpleNamespace(status="completed", findings=[], scanner_results=[
        {"scanner_id": "windows.firewall", "status": "success", "findings": [], "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-clean", "completed", NOW, scanner_ids=("windows.firewall",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available"
    # When no findings exist, no model inference was run; status is truthfully Offline rules
    assert data["model"] == "Offline rules"
    assert data["provider"] == "offline"
    assert data["fallback_used"] is False
    assert len(world.provider.prioritize_prompts) == 0


def test_genuinely_size_bounded_prompt_fits_max_chars_and_preserves_remaining_actions():
    world = _world(max_prompt_chars=2000)
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "many-findings-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    findings = [
        {
            "finding_id": f"f-{i}",
            "occurrence_id": f"scan-bound:f-{i}",
            "severity": "high",
            "title": f"Finding Title Number {i}",
            "details": "Detailed finding explanation describing security posture. " * 9,
            "scanner_id": "windows.firewall",
            "rule_id": "firewall.profile",
        }
        for i in range(10)
    ]
    result = SimpleNamespace(status="completed", findings=findings, scanner_results=[
        {"scanner_id": "windows.firewall", "status": "success", "findings": [f["finding_id"] for f in findings],
         "execution_evidence": {"completeness": "complete"}},
    ])
    world.assessments.items.append(
        _assessment(ep, org, "scan-bound", "completed", NOW, scanner_ids=("windows.firewall",), result=result)
    )

    response = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"offline_plan": True},
        headers=_headers(world),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "available"
    assert len(world.provider.prioritize_prompts) == 1
    sent_prompt = world.provider.prioritize_prompts[0]
    assert len(sent_prompt) <= 2000
    assert 0 < len(json.loads(sent_prompt)["findings"]) < 10
    assert data["coverage"]["truncated"] is False

    # Even though prompt only held a subset of findings, ALL 10 plan actions must be preserved!
    plan = data["plan"]
    assert len(plan) == 10
    assert [p["priority"] for p in plan] == list(range(1, 11))
