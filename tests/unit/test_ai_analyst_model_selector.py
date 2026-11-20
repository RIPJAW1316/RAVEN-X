"""Focused unit and API tests for AI Analyst Model Selector and Gemini Cloud Demo."""

from datetime import datetime, timezone
import json
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from backend.api.tenant_insights import TenantInsightsDependencies, create_tenant_insights_router
from backend.application.ai import TenantLocalAnalysisService
from backend.application.ai.synthetic_demo import (
    CANONICAL_DEMO_GEMINI_ITEMS,
    CANONICAL_DEMO_REFS,
    DEMO_REF_TO_FINDING_ID,
    WINDOWS_HARDENING_DEMO_ID,
    build_synthetic_windows_demo_report,
)
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService)
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.application.reporting.fleet_report import TenantFleetReportService
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.security import SecurityPrincipal
from backend.infrastructure.ai import CloudGeminiConfig, CloudGeminiProvider, LocalAIConfig, LocalOpenAIProvider
from backend.infrastructure.persistence.in_memory_endpoint_repository import InMemoryEndpointRepository
from backend.infrastructure.persistence.in_memory_membership_repository import InMemoryOrganizationMembershipRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_presence_repository import InMemoryEndpointPresenceRepository
from backend.infrastructure.persistence.in_memory_rbac_repository import InMemoryRoleBindingRepository, InMemoryRoleRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository


NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
PASSWORD = "review demo password"


@pytest.fixture(autouse=True)
def isolate_test_credentials():
    """Ensure all tests in this module run against an isolated in-memory store."""
    from backend.infrastructure.security.windows_credentials import InMemoryCredentialStore, set_active_store
    store = InMemoryCredentialStore("TEST/IsolatedModelSelector")
    set_active_store(store)
    yield store
    set_active_store(None)


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
            raise TimeoutError("provider timeout")
        return "Advisory: review findings."

    def prioritize_findings(self, prompt_json: str) -> str:
        self.prioritize_prompts.append(prompt_json)
        if self.fail:
            raise TimeoutError("provider timeout")
        if self.prioritize_output is not None:
            return self.prioritize_output
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


def _world(permissions=("reports.read", "ai.use"), *, local_provider=None, cloud_provider=None):
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
    cloud_ai_provider = cloud_provider or CloudGeminiProvider(
        CloudGeminiConfig(enabled=True, project="demo-event-project")
    )
    analysis_service = TenantLocalAnalysisService(
        report, authorizer, local_provider or MockLocalAIProvider(),
        cloud_provider=cloud_ai_provider,
        clock=lambda: NOW,
    )
    auth = HumanAuthenticationService(users)
    token = auth.authenticate(user.email, PASSWORD).session_token
    context_resolver = OrganizationContextResolver(users, memberships, organizations)
    app = FastAPI()
    app.include_router(create_tenant_insights_router(TenantInsightsDependencies(
        HumanSessionAuthenticator(users), users, context_resolver, report, analysis_service)), prefix="/api/v1")
    return SimpleNamespace(
        client=TestClient(app), token=token, user=user, organization=organization,
        foreign_organization=foreign_organization, endpoints=endpoints,
        presence=presence, assessments=assessments, report=report, ai=analysis_service,
        provider=analysis_service.provider, cloud_provider=cloud_ai_provider,
    )


def _headers(world):
    return {"Authorization": "Bearer " + world.token}


def _make_google_wire_response(refs: list[str], finish_reason: str = "STOP") -> bytes:
    """Build a compliant Google Vertex AI generateContent response envelope."""
    return json.dumps({
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": json.dumps(refs)}],
                },
                "finishReason": finish_reason,
            }
        ]
    }).encode("utf-8")


# -----------------------------------------------------------------------------
# 1. Legacy Behavior & Conflict Rule
# -----------------------------------------------------------------------------

def test_legacy_omitted_model_and_offline_plan_preserves_behavior():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "legacy-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(
        {"scanner_id": "windows.firewall", "status": "success", "findings": [], "execution_evidence": {"completeness": "complete"}},))
    world.assessments.items.append(_assessment(ep, org, "scan-legacy", "completed", NOW, result=result))

    # Omitted model and omitted offline_plan -> legacy behavior
    resp = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={}, headers=_headers(world))
    assert resp.status_code == 200
    data = resp.json()
    assert data["model"] == "meta-llama-3.1-8b-instruct"
    assert data["analysis"] == "Advisory: review findings."
    assert "plan" not in data

    # Explicit offline_plan: false -> legacy behavior
    resp_false = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"offline_plan": False}, headers=_headers(world))
    assert resp_false.status_code == 200
    assert "plan" not in resp_false.json()

    # Legacy offline_plan: true without model -> prioritized fix plan via LM Studio
    resp_legacy_plan = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"offline_plan": True}, headers=_headers(world))
    assert resp_legacy_plan.status_code == 200
    data_plan = resp_legacy_plan.json()
    assert "plan" in data_plan
    assert data_plan["provider"] == "offline" or data_plan["provider"] == "lm_studio"


def test_conflict_rule_rejects_model_combined_with_legacy_offline_plan():
    """Explicit model cannot be combined with legacy offline_plan (prefer rejecting)."""
    world = _world()
    org = world.organization.organization_id

    # lm_studio + offline_plan -> 422
    resp1 = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "lm_studio", "offline_plan": True},
        headers=_headers(world),
    )
    assert resp1.status_code == 422
    assert resp1.json()["detail"]["code"] == "INVALID_REQUEST"

    # offline + offline_plan -> 422
    resp2 = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "offline", "offline_plan": False},
        headers=_headers(world),
    )
    assert resp2.status_code == 422
    assert resp2.json()["detail"]["code"] == "INVALID_REQUEST"

    # gemini + offline_plan -> 422
    resp3 = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini", "offline_plan": True},
        headers=_headers(world),
    )
    assert resp3.status_code == 422
    assert resp3.json()["detail"]["code"] == "INVALID_REQUEST"


def test_explicit_lm_studio_is_self_contained_on_real_scope():
    """Explicit model='lm_studio' returns the prioritized fix plan on real scope without offline_plan."""
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "prod-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)
    findings = [{
        "finding_id": "fw-1",
        "occurrence_id": "scan-1:fw-1",
        "severity": "critical",
        "title": "Windows Firewall Disabled",
        "description": "Firewall is off for the public profile.",
        "scanner_id": "windows.firewall",
        "rule_id": "firewall.profile",
        "evidence": [{"source": "Get-NetFirewallProfile", "observed_value": "OFF"}],
    }]
    scanner_results = [
        {"scanner_id": "windows.firewall", "status": "success", "findings": ["fw-1"], "execution_evidence": {"completeness": "complete"}},
    ]
    result = SimpleNamespace(status="completed", findings=findings, scanner_results=scanner_results)
    world.assessments.items.append(_assessment(ep, org, "scan-1", "completed", NOW, result=result))

    # Send ONLY model plus source
    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "lm_studio", "endpoint_id": str(ep.endpoint_id)},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "meta-llama-3.1-8b-instruct"
    assert data["provider"] == "lm_studio"
    assert data["fallback_used"] is False
    assert "plan" in data
    assert len(data["plan"]) == 1
    assert data["plan"][0]["scanner_id"] == "windows.firewall"


def test_blank_and_unknown_model_requests_fail():
    world = _world()
    org = world.organization.organization_id

    # Blank string
    resp_blank = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"model": ""}, headers=_headers(world))
    assert resp_blank.status_code == 422
    assert resp_blank.json()["detail"]["code"] == "INVALID_REQUEST"

    # Whitespace only
    resp_ws = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"model": "   "}, headers=_headers(world))
    assert resp_ws.status_code == 422

    # Unknown model name
    resp_unknown = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"model": "gpt-4-turbo"}, headers=_headers(world))
    assert resp_unknown.status_code == 422

    # Non-string model
    resp_type = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"model": 123}, headers=_headers(world))
    assert resp_type.status_code == 422

    # Non-bool offline_plan
    resp_nonbool = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={"offline_plan": "true"}, headers=_headers(world))
    assert resp_nonbool.status_code == 422


# -----------------------------------------------------------------------------
# 2. Scope & Demo Mutual Exclusivity
# -----------------------------------------------------------------------------

def test_demo_id_mutually_exclusive_with_endpoint_and_assessment():
    world = _world()
    org = world.organization.organization_id

    resp_ep = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "endpoint_id": "ep-1"},
        headers=_headers(world),
    )
    assert resp_ep.status_code == 422
    assert resp_ep.json()["detail"]["code"] == "INVALID_REQUEST"

    resp_assess = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "assessment_ids": ["scan-1"]},
        headers=_headers(world),
    )
    assert resp_assess.status_code == 422
    assert resp_assess.json()["detail"]["code"] == "INVALID_REQUEST"


def test_unsupported_demo_id_rejected():
    world = _world()
    org = world.organization.organization_id
    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": "unsupported-demo-v99"},
        headers=_headers(world),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "INVALID_REQUEST"


# -----------------------------------------------------------------------------
# 3. Security Boundary & Anti-Forgery
# -----------------------------------------------------------------------------

def test_gemini_on_real_endpoint_fails_closed_before_report_or_credentials():
    world = _world()
    org = world.organization.organization_id
    ep = Endpoint(EndpointId.new(), "secret-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "gemini", "endpoint_id": str(ep.endpoint_id)},
        headers=_headers(world),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "INVALID_REQUEST"


def test_gemini_on_fleet_scope_without_demo_id_fails_closed():
    world = _world()
    org = world.organization.organization_id
    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "INVALID_REQUEST"
    assert "Allow Gemini on live assessments" in resp.json()["detail"]["message"]



@pytest.mark.parametrize("order, expected_provider", [
    (["f2", "f1"], "google_cloud"),
    (["f1", "invented"], "offline"),
])
def test_opt_in_real_gemini_prioritizes_minimized_tenant_findings(order, expected_provider):
    outbound = []

    def transport(**request):
        outbound.append(json.loads(request["body"]))
        return _make_google_wire_response(order)

    provider = CloudGeminiProvider(
        CloudGeminiConfig(enabled=True, live_enabled=True, auth_mode="api_key", api_key="test-key"),
        transport=transport,
    )
    world = _world(cloud_provider=provider)
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "private-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    findings = [
        {"finding_id": "fw-1", "title": "sensitive-title", "severity": "high",
         "description": "private-description", "scanner_id": "windows.firewall",
         "evidence": [{"observed_value": "private-evidence"}]},
        {"finding_id": "uac-1", "title": "UAC", "severity": "medium",
         "scanner_id": "windows.uac"},
    ]
    result = SimpleNamespace(status="completed", findings=findings, scanner_results=[])
    world.assessments.items.append(_assessment(endpoint, org, "private-assessment", "completed", NOW,
                                               result=result))
    path = f"/api/v1/organizations/{org}/ai/analyze"
    response = world.client.post(path, json={"model": "gemini", "endpoint_id": str(endpoint.endpoint_id)},
                                 headers=_headers(world))
    assert response.status_code == 200, response.text
    assert len(outbound) == 1
    prompt = outbound[0]["contents"][0]["parts"][0]["text"]
    assert json.loads(prompt.split("Findings: ", 1)[1]) == [
        {"ref": "f1", "check": "windows.firewall", "severity": "high"},
        {"ref": "f2", "check": "windows.uac", "severity": "medium"},
    ]
    data = response.json()
    assert data["provider"] == expected_provider
    assert data["fallback_used"] == (expected_provider == "offline")
    assert data["source"]["assessment_ids"] == ["private-assessment"]
    assert len(data["plan"]) == 2
    assert data["plan"][0]["finding_id"] == ("uac-1" if expected_provider == "google_cloud" else "fw-1")

    foreign = Endpoint(EndpointId.new(), "other-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       created_at=NOW, organization_id=world.foreign_organization.organization_id)
    world.endpoints.add(foreign)
    response = world.client.post(path, json={"model": "gemini", "endpoint_id": str(foreign.endpoint_id)},
                                 headers=_headers(world))
    assert response.status_code == 404
    assert len(outbound) == 1

def test_cloud_provider_rejects_unauthorized_fixture_id():
    config = CloudGeminiConfig(enabled=True, project="test-project")
    provider = CloudGeminiProvider(config)
    with pytest.raises(ValueError, match="only supports allowlisted demo fixture"):
        provider.prioritize_synthetic_demo(fixture_id="unauthorized-fixture")


# -----------------------------------------------------------------------------
# 4. Documented Envelope, Nontrivial Ordering & Permutation
# -----------------------------------------------------------------------------

def test_gemini_nontrivial_ordering_maps_every_finding_id_correctly():
    """Verify Gemini returning nontrivial order (f2 first, then f4) correctly reorders every finding_id."""
    nontrivial_order = ["f2", "f4", "f1", "f5", "f3"]
    # f2 = demo-bl-1 (BitLocker)
    # f4 = demo-smb-1 (SMB)
    # f1 = demo-fw-1 (Firewall)
    # f5 = demo-autorun-1 (AutoRun)
    # f3 = demo-uac-1 (UAC)
    expected_fids = ["demo-bl-1", "demo-smb-1", "demo-fw-1", "demo-autorun-1", "demo-uac-1"]

    def mock_transport(url, headers, body):
        assert "gemini-3.5-flash-lite:generateContent" in url
        assert "locations/global" in url
        # Verify generationConfig bounds output tokens and omits temperature
        parsed_body = json.loads(body.decode("utf-8"))
        gen_config = parsed_body["generationConfig"]
        assert gen_config["maxOutputTokens"] == 256
        assert "temperature" not in gen_config
        return _make_google_wire_response(nontrivial_order, finish_reason="STOP")

    cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "gemini-3.5-flash-lite"
    assert data["provider"] == "google_cloud"
    assert data["fallback_used"] is False

    plan = data["plan"]
    assert len(plan) == 5
    actual_fids = [item["finding_id"] for item in plan]
    assert actual_fids == expected_fids

    # Verify priority sequential numbering and check identities
    for idx, expected_fid in enumerate(expected_fids, start=1):
        item = plan[idx - 1]
        assert item["priority"] == idx
        assert item["finding_id"] == expected_fid

    # Priority 1 is BitLocker
    assert plan[0]["scanner_id"] == "windows.bitlocker"
    assert plan[0]["rule_id"] == "bitlocker.os_volume"
    # Priority 2 is SMB
    assert plan[1]["scanner_id"] == "windows.smb"
    assert plan[1]["rule_id"] == "smb.smb1_enabled"


def test_fixture_scanner_ownership_source_label_and_unverified_schema():
    """Verify 24-check accounting, scanner results ownership, source descriptor, and unverified schema."""
    world = _world()
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "offline"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()

    # Source descriptor has bundled_demo provenance without fabricated links
    assert data["source"]["kind"] == "bundled_demo"
    assert data["source"]["demo_id"] == WINDOWS_HARDENING_DEMO_ID
    assert data["source"]["organization_id"] == "bundled-demo-organization"
    assert data["source"]["assessment_ids"] == []

    # Blind spots schema: exactly 1 unverified Wi-Fi observation
    assert len(data["blind_spots"]) == 1
    spot = data["blind_spots"][0]
    assert spot["scanner_id"] == "windows.wifi"
    assert spot["status"] == "failed"
    assert spot["error_category"] == "READ_FAILED"
    assert "Wi-Fi collection failed; the active Wi-Fi cipher remains unverified." in spot["reason"]

    # Coverage accounts for all 24 checks: 5 findings + 1 unverified + 18 clean
    assert len(data["plan"]) == 5
    # Verify scanner ownership on every finding
    expected_scanners = {
        "demo-fw-1": "windows.firewall",
        "demo-bl-1": "windows.bitlocker",
        "demo-uac-1": "windows.uac",
        "demo-smb-1": "windows.smb",
        "demo-autorun-1": "windows.autorun",
    }
    for item in data["plan"]:
        assert item["scanner_id"] == expected_scanners[item["finding_id"]]


def test_cloud_adapter_finish_reason_stop_required_and_rejects_max_tokens_or_safety():
    """Adapter strictly requires finishReason='STOP' and rejects MAX_TOKENS / SAFETY."""
    for bad_finish_reason in ("MAX_TOKENS", "SAFETY", "RECITATION"):
        def mock_transport(url, headers, body):
            return _make_google_wire_response(list(CANONICAL_DEMO_REFS), finish_reason=bad_finish_reason)

        cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
        cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
        world = _world(cloud_provider=cloud_provider)
        org = world.organization.organization_id

        resp = world.client.post(
            f"/api/v1/organizations/{org}/ai/analyze",
            json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
            headers=_headers(world),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["model"] == "Offline rules"
        assert data["provider"] == "offline"
        assert data["fallback_used"] is True
        assert f"finishReason is '{bad_finish_reason}'" in data["fallback_reason"]


def test_cloud_adapter_missing_or_invalid_project_fails_closed():
    """Missing or invalid project ID causes offline fallback before credentials or transport."""
    for bad_project in ("", "   ", "UPPERCASE_NOT_ALLOWED", "invalid/slash", "a"):
        def failing_transport(url, headers, body):
            raise AssertionError("Transport should never be called when project is invalid")

        cloud_config = CloudGeminiConfig(enabled=True, project=bad_project)
        cloud_provider = CloudGeminiProvider(cloud_config, transport=failing_transport)
        world = _world(cloud_provider=cloud_provider)
        org = world.organization.organization_id

        resp = world.client.post(
            f"/api/v1/organizations/{org}/ai/analyze",
            json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
            headers=_headers(world),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["model"] == "Offline rules"
        assert data["provider"] == "offline"
        assert data["fallback_used"] is True
        assert "project" in data["fallback_reason"].lower()


def test_adc_wrapper_passes_timeout_without_touching_global_socket_state(monkeypatch):
    """Verify timeout is passed via the auth Request wrapper without modifying global socket defaults."""
    import socket
    from backend.infrastructure.ai.cloud_gemini import _TimeoutAuthRequest, _get_adc_bearer_token

    initial_socket_timeout = socket.getdefaulttimeout()

    # Verify _TimeoutAuthRequest enforces default timeout when none provided
    class FakeUnderlyingRequest:
        def __init__(self, session=None):
            self.calls = []

        def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
            self.calls.append({"url": url, "timeout": timeout})
            return SimpleNamespace(status_code=200, data=b"ok")

    fake_underlying = FakeUnderlyingRequest()
    wrapper = _TimeoutAuthRequest(timeout_seconds=7)
    wrapper._request = fake_underlying

    # Call without timeout -> uses 7
    wrapper("https://oauth2.googleapis.com/token", method="POST")
    assert len(fake_underlying.calls) == 1
    assert fake_underlying.calls[0]["timeout"] == 7

    # Call with explicit timeout -> respects explicit
    wrapper("https://oauth2.googleapis.com/token", method="POST", timeout=3)
    assert len(fake_underlying.calls) == 2
    assert fake_underlying.calls[1]["timeout"] == 3

    # Global socket default timeout must be untouched
    assert socket.getdefaulttimeout() == initial_socket_timeout


def test_adc_import_error_reports_missing_dependency(monkeypatch):
    """Missing google-auth dependency reports a clear error without probing credential paths."""
    import sys
    from backend.infrastructure.ai.cloud_gemini import _get_adc_bearer_token

    # Simulate google.auth not installed
    monkeypatch.setitem(sys.modules, "google.auth", None)

    with pytest.raises(RuntimeError, match="Optional cloud dependency 'google-auth' is required"):
        _get_adc_bearer_token(timeout_seconds=10)


def test_gemini_incomplete_permutation_rejects_and_falls_back():
    def mock_transport(url, headers, body):
        # 4 out of 5 refs
        return _make_google_wire_response(["f1", "f2", "f3", "f4"])

    cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "Offline rules"
    assert data["provider"] == "offline"
    assert data["fallback_used"] is True
    assert "incomplete permutation" in data["fallback_reason"].lower()
    assert len(data["plan"]) == len(CANONICAL_DEMO_REFS)


def test_gemini_duplicate_refs_rejects_and_falls_back():
    def mock_transport(url, headers, body):
        return _make_google_wire_response(["f1", "f1", "f2", "f3", "f4"])

    cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["model"] == "Offline rules"
    assert data["fallback_used"] is True


def test_gemini_invented_refs_rejects_and_falls_back():
    def mock_transport(url, headers, body):
        return _make_google_wire_response(["f1", "f2", "f3", "f4", "f999"])

    cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["model"] == "Offline rules"
    assert data["fallback_used"] is True


def test_gemini_timeout_or_500_falls_back_cleanly():
    def mock_transport(url, headers, body):
        raise TimeoutError("cloud transport timeout")

    cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "Offline rules"
    assert data["fallback_used"] is True
    assert "unavailable or timed out" in data["fallback_reason"]


# -----------------------------------------------------------------------------
# 5. Comparing Same Fixture Across All 3 Model Options
# -----------------------------------------------------------------------------

def test_same_demo_fixture_selectable_across_all_three_model_options():
    def mock_transport(url, headers, body):
        return _make_google_wire_response(list(reversed(CANONICAL_DEMO_REFS)))

    cloud_config = CloudGeminiConfig(enabled=True, project="demo-event-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    # 1. Option: offline rules
    resp_off = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "offline"},
        headers=_headers(world),
    )
    assert resp_off.status_code == 200
    data_off = resp_off.json()
    assert data_off["model"] == "Offline rules"
    assert data_off["provider"] == "offline"
    assert data_off["fallback_used"] is False

    # 2. Option: local LM Studio
    resp_local = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "lm_studio"},
        headers=_headers(world),
    )
    assert resp_local.status_code == 200
    data_local = resp_local.json()
    assert data_local["model"] == "meta-llama-3.1-8b-instruct"
    assert data_local["provider"] == "lm_studio"
    assert data_local["fallback_used"] is False

    # 3. Option: Gemini cloud demo
    resp_cloud = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp_cloud.status_code == 200
    data_cloud = resp_cloud.json()
    assert data_cloud["model"] == "gemini-3.5-flash-lite"
    assert data_cloud["provider"] == "google_cloud"
    assert data_cloud["fallback_used"] is False

    # All three options operated on the EXACT same findings and blind spots
    assert len(data_off["plan"]) == len(data_local["plan"]) == len(data_cloud["plan"]) == 5
    assert len(data_off["blind_spots"]) == len(data_local["blind_spots"]) == len(data_cloud["blind_spots"]) == 1
    # Wi-Fi is unverified blind spot in all three
    assert data_off["blind_spots"][0]["scanner_id"] == "windows.wifi"


# -----------------------------------------------------------------------------
# 6. Auth & RBAC on Demo Scope
# -----------------------------------------------------------------------------

def test_demo_requires_ai_use_and_reports_read_permissions():
    # User missing ai.use
    world_no_ai = _world(permissions=("reports.read",))
    resp_no_ai = world_no_ai.client.post(
        f"/api/v1/organizations/{world_no_ai.organization.organization_id}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "offline"},
        headers=_headers(world_no_ai),
    )
    assert resp_no_ai.status_code == 403

    # User missing reports.read
    world_no_rep = _world(permissions=("ai.use",))
    resp_no_rep = world_no_rep.client.post(
        f"/api/v1/organizations/{world_no_rep.organization.organization_id}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "offline"},
        headers=_headers(world_no_rep),
    )
    assert resp_no_rep.status_code == 403

    # Unauthenticated
    world_unauth = _world()
    resp_unauth = world_unauth.client.post(
        f"/api/v1/organizations/{world_unauth.organization.organization_id}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID},
    )
    assert resp_unauth.status_code == 401


# -----------------------------------------------------------------------------
# 7. Gemini Developer API Key Mode (Google AI Studio)
# -----------------------------------------------------------------------------

def test_gemini_api_key_mode_endpoint_and_header_separation():
    """Verify Developer API key mode uses generativelanguage endpoint, x-goog-api-key header, and responseJsonSchema."""
    fake_key = "fake-secret-key-12345"
    recorded_calls = []

    def mock_transport(url, headers, body):
        recorded_calls.append({"url": url, "headers": headers, "body": body})
        assert url == "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent"
        assert headers.get("x-goog-api-key") == fake_key
        assert "Authorization" not in headers
        assert "aiplatform.googleapis.com" not in url

        parsed_body = json.loads(body.decode("utf-8"))
        gen_config = parsed_body["generationConfig"]
        assert gen_config["maxOutputTokens"] == 256
        assert gen_config["responseMimeType"] == "application/json"
        assert gen_config["responseJsonSchema"] == {"type": "array", "items": {"type": "string"}}
        assert "responseSchema" not in gen_config
        assert "temperature" not in gen_config

        return _make_google_wire_response(["f2", "f4", "f1", "f5", "f3"], finish_reason="STOP")

    cloud_config = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key=fake_key)
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    assert len(recorded_calls) == 1
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "gemini-3.5-flash-lite"
    assert data["provider"] == "google_cloud"
    assert data["fallback_used"] is False

    # BitLocker (f2) first, SMB (f4) second
    assert data["plan"][0]["finding_id"] == "demo-bl-1"
    assert data["plan"][1]["finding_id"] == "demo-smb-1"


def test_gemini_adc_mode_endpoint_and_header_separation():
    """Verify ADC mode uses aiplatform endpoint, Authorization Bearer header, and responseSchema."""
    fake_token = "fake-adc-token-999"
    recorded_calls = []

    def mock_transport(url, headers, body):
        recorded_calls.append({"url": url, "headers": headers, "body": body})
        assert "https://aiplatform.googleapis.com/v1/projects/test-project/locations/global" in url
        assert "models/gemini-3.5-flash-lite:generateContent" in url
        assert headers.get("Authorization") == f"Bearer {fake_token}"
        assert "x-goog-api-key" not in headers
        assert "generativelanguage.googleapis.com" not in url

        parsed_body = json.loads(body.decode("utf-8"))
        gen_config = parsed_body["generationConfig"]
        assert gen_config["maxOutputTokens"] == 256
        assert gen_config["responseMimeType"] == "application/json"
        assert gen_config["responseSchema"] == {"type": "ARRAY", "items": {"type": "STRING"}}
        assert "responseJsonSchema" not in gen_config
        assert "temperature" not in gen_config

        return _make_google_wire_response(["f1", "f2", "f3", "f4", "f5"], finish_reason="STOP")

    cloud_config = CloudGeminiConfig(enabled=True, auth_mode="adc", project="test-project")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=mock_transport, adc_token_provider=lambda: fake_token)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    assert len(recorded_calls) == 1
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "gemini-3.5-flash-lite"
    assert data["provider"] == "google_cloud"
    assert data["fallback_used"] is False


def test_gemini_api_key_mode_disabled_makes_no_requests():
    """When cloud Gemini is disabled, api_key mode makes no requests and falls back to offline rules."""
    def fail_transport(url, headers, body):
        raise AssertionError("Transport should never be called when cloud Gemini is disabled")

    cloud_config = CloudGeminiConfig(enabled=False, auth_mode="api_key", api_key="fake-key")
    cloud_provider = CloudGeminiProvider(cloud_config, transport=fail_transport)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "available"
    assert data["model"] == "Offline rules"
    assert data["provider"] == "offline"
    assert data["fallback_used"] is True
    assert data["fallback_reason"] == "Gemini cloud demo inference is disabled"


def test_gemini_api_key_mode_missing_or_blank_key_makes_no_requests():
    """Missing or blank API key in api_key mode makes zero requests and falls back with a clear reason."""
    def fail_transport(url, headers, body):
        raise AssertionError("Transport should never be called when API key is missing")

    # Empty key
    cloud_config_empty = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key="")
    cloud_provider_empty = CloudGeminiProvider(cloud_config_empty, transport=fail_transport)
    world_empty = _world(cloud_provider=cloud_provider_empty)
    org = world_empty.organization.organization_id

    resp1 = world_empty.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world_empty),
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["model"] == "Offline rules"
    assert data1["fallback_used"] is True
    assert data1["fallback_reason"] in ("Gemini API key is missing", "Gemini API key is unconfigured")

    # Whitespace-only key
    cloud_config_ws = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key="   \t\n")
    cloud_provider_ws = CloudGeminiProvider(cloud_config_ws, transport=fail_transport)
    world_ws = _world(cloud_provider=cloud_provider_ws)

    resp2 = world_ws.client.post(
        f"/api/v1/organizations/{world_ws.organization.organization_id}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world_ws),
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["model"] == "Offline rules"
    assert data2["fallback_used"] is True
    assert data2["fallback_reason"] in ("Gemini API key is missing", "Gemini API key is unconfigured")


def test_gemini_api_key_unsafe_header_characters_rejected_without_request():
    """Keys with newlines, control characters or non-ASCII fail validation without sending network requests."""
    def fail_transport(url, headers, body):
        raise AssertionError("Transport should never be called when key contains unsafe header characters")

    unsafe_keys = [
        "fake-key\nInjected-Header: evil",
        "fake-key\rInjected-Header: evil",
        "fake-key\x00nullbyte",
        "fake-key with spaces",
        "fake-key-with-\t-tab",
    ]

    for bad_key in unsafe_keys:
        cloud_config = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key=bad_key)
        cloud_provider = CloudGeminiProvider(cloud_config, transport=fail_transport)
        world = _world(cloud_provider=cloud_provider)
        org = world.organization.organization_id

        resp = world.client.post(
            f"/api/v1/organizations/{org}/ai/analyze",
            json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
            headers=_headers(world),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["model"] == "Offline rules"
        assert data["fallback_used"] is True
        assert data["fallback_reason"] == "Gemini API key contains unsafe header characters"
        # The bad key itself must NEVER appear in the response
        assert bad_key not in resp.text


def test_gemini_api_key_omitted_from_repr_fallback_and_errors(isolate_test_credentials):
    """Verify the API key is never exposed in config repr, error messages, fallback reasons, or API responses."""
    secret = "secret-fake-ai-studio-key-9876543210"

    # 1. Config repr must redact the key
    config = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key=secret)
    repr_str = repr(config)
    assert secret not in repr_str
    assert "[REDACTED]" in repr_str

    # 2. Config from_config with environment does not set or expose key
    env_config = CloudGeminiConfig.from_config(environ={
        "RAVENX_CLOUD_GEMINI_ENABLED": "true",
        "RAVENX_CLOUD_GEMINI_AUTH_MODE": "api_key",
    })
    assert secret not in repr(env_config)

    # 3. Direct provider error does not expose key
    provider = CloudGeminiProvider(config)
    with pytest.raises(ValueError) as exc_info:
        provider.prioritize_synthetic_demo(fixture_id="unauthorized-fixture")
    assert secret not in str(exc_info.value)

    # 4. Fallback reason on network failure does not expose key
    def failing_transport(url, headers, body):
        raise RuntimeError("Simulated network timeout connecting to generativelanguage.googleapis.com")

    provider_failing = CloudGeminiProvider(config, transport=failing_transport)
    world = _world(cloud_provider=provider_failing)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    assert secret not in resp.text
    assert secret not in resp.json().get("fallback_reason", "")


def test_gemini_api_key_mode_does_not_require_project_or_adc(isolate_test_credentials):
    """Developer API key mode does not require Google Cloud project configuration or ADC dependencies."""
    fake_key = "fake-valid-key-abcdef"
    isolate_test_credentials.set_key(fake_key)

    # Notice: project is empty!
    env_config = CloudGeminiConfig.from_config(environ={
        "RAVENX_CLOUD_GEMINI_ENABLED": "true",
        "RAVENX_CLOUD_GEMINI_AUTH_MODE": "api_key",
    })
    assert env_config.project == ""
    assert env_config.auth_mode == "api_key"

    def mock_transport(url, headers, body):
        assert "generativelanguage.googleapis.com" in url
        assert headers.get("x-goog-api-key") == fake_key
        return _make_google_wire_response(["f1", "f2", "f3", "f4", "f5"])

    provider = CloudGeminiProvider(env_config, transport=mock_transport)
    world = _world(cloud_provider=provider)
    org = world.organization.organization_id

    resp = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"demo_id": WINDOWS_HARDENING_DEMO_ID, "model": "gemini"},
        headers=_headers(world),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["model"] == "gemini-3.5-flash-lite"
    assert data["fallback_used"] is False


def test_gemini_auth_mode_validation():
    """Unsupported auth_mode fails during config validation and execution."""
    with pytest.raises(ValueError, match="invalid cloud Gemini auth_mode 'unsupported'"):
        CloudGeminiConfig.from_config(environ={"RAVENX_CLOUD_GEMINI_AUTH_MODE": "unsupported"})

    invalid_config = CloudGeminiConfig(enabled=True, auth_mode="unsupported")
    provider = CloudGeminiProvider(invalid_config)
    with pytest.raises(ValueError, match="Unsupported cloud Gemini auth_mode 'unsupported'"):
        provider.prioritize_synthetic_demo(fixture_id=WINDOWS_HARDENING_DEMO_ID)


def test_gemini_api_key_mode_restricted_to_synthetic_demo():
    """Developer API key mode maintains the strict synthetic demo security boundary."""
    cloud_config = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key="fake-key-123")
    cloud_provider = CloudGeminiProvider(cloud_config)
    world = _world(cloud_provider=cloud_provider)
    org = world.organization.organization_id

    # Real endpoint scope fails closed
    ep = Endpoint(EndpointId.new(), "prod-laptop", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                  created_at=NOW, organization_id=org)
    world.endpoints.add(ep)
    resp1 = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "gemini", "endpoint_id": str(ep.endpoint_id)},
        headers=_headers(world),
    )
    assert resp1.status_code == 422
    assert resp1.json()["detail"]["code"] == "INVALID_REQUEST"

    # Fleet scope without demo_id fails closed
    resp2 = world.client.post(
        f"/api/v1/organizations/{org}/ai/analyze",
        json={"model": "gemini"},
        headers=_headers(world),
    )
    assert resp2.status_code == 422
    assert resp2.json()["detail"]["code"] == "INVALID_REQUEST"
