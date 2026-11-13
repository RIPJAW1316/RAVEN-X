"""Real-record report semantics and tenant/permission gates for local analysis."""

from datetime import datetime, timedelta, timezone
import csv
from io import StringIO
import json
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from backend.api.tenant_insights import TenantInsightsDependencies, create_tenant_insights_router
from backend.application.ai import TenantLocalAnalysisService
from backend.application.identity import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                              OrganizationService)
from backend.application.rbac import OrganizationRbacAuthorizer, RoleBindingService, RoleService
from backend.application.reporting.fleet_report import TenantFleetReportService
from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from backend.domain.presence import EndpointPresence, PresenceState
from backend.domain.security import AuthorizationAction, SecurityPrincipal
from backend.infrastructure.ai import LocalAIConfig, LocalOpenAIProvider
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


class FakeProvider:
    enabled = True
    model = "local-test-model"

    def __init__(self, *, fail=False):
        self.prompts = []
        self.fail = fail

    def analyze(self, facts):
        self.prompts.append(facts)
        if self.fail:
            raise TimeoutError("provider response must not leak")
        return "Advisory: review the firewall finding."


def _assessment(endpoint, organization_id, assessment_id, state, requested_at, *, result=None):
    return SimpleNamespace(endpoint_id=endpoint.endpoint_id, organization_id=organization_id,
                           assessment_id=assessment_id, state=state, requested_at=requested_at,
                           started_at=requested_at, completed_at=requested_at if state == "completed" else None,
                           failed_at=requested_at if state == "failed" else None,
                           scanner_ids=("windows.firewall",), result=result)


def _world(permissions=("reports.read", "ai.use"), *, provider=None):
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
    ai = TenantLocalAnalysisService(report, authorizer, provider or FakeProvider(), clock=lambda: NOW)
    auth = HumanAuthenticationService(users)
    token = auth.authenticate(user.email, PASSWORD).session_token
    context_resolver = OrganizationContextResolver(users, memberships, organizations)
    app = FastAPI()
    app.include_router(create_tenant_insights_router(TenantInsightsDependencies(
        HumanSessionAuthenticator(users), users, context_resolver, report, ai)), prefix="/api/v1")
    return SimpleNamespace(client=TestClient(app), token=token, user=user, organization=organization,
                           foreign_organization=foreign_organization, endpoints=endpoints,
                           presence=presence, assessments=assessments, report=report, ai=ai,
                           provider=ai.provider, context=context_resolver.resolve(SecurityPrincipal.human(user.user_id),
                                                                                   organization.organization_id))


def _headers(world):
    return {"Authorization": "Bearer " + world.token}


def test_local_ai_rejects_large_request_before_parsing_or_model_call():
    world = _world()
    response = world.client.post(
        f"/api/v1/organizations/{world.organization.organization_id}/ai/analyze",
        content=json.dumps({"endpoint_id": "x" * (16 * 1024)}),
        headers={**_headers(world), "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert world.provider.prompts == []


def test_fleet_report_counts_real_scanned_failed_pending_and_unscanned_endpoints():
    world = _world()
    org = world.organization.organization_id
    scanned = Endpoint(EndpointId.new(), "scanned-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       created_at=NOW, organization_id=org)
    failed = Endpoint(EndpointId.new(), "failed-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                      created_at=NOW, organization_id=org)
    pending = Endpoint(EndpointId.new(), "pending-pc", PlatformInfo("Windows"), EndpointStatus.NEW,
                       created_at=NOW, organization_id=org)
    foreign = Endpoint(EndpointId.new(), "foreign-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       created_at=NOW, organization_id=world.foreign_organization.organization_id)
    for endpoint in (scanned, failed, pending, foreign):
        world.endpoints.add(endpoint)
    world.presence.upsert(EndpointPresence(str(scanned.endpoint_id), str(org), PresenceState.ONLINE,
                                          last_seen_at=NOW))
    world.presence.upsert(EndpointPresence(str(failed.endpoint_id), str(org), PresenceState.OFFLINE,
                                          last_seen_at=NOW - timedelta(hours=1)))
    evidence = {"source": "firewall", "description": "Public firewall disabled",
                "observed_value": "off", "raw_metadata": {"secret": "DO_NOT_EXPOSE"}}
    result = SimpleNamespace(status="completed", findings=({"finding_id": "f-1", "severity": "high",
                                        "title": "Firewall disabled", "description": "Public profile is off",
                                        "scanner_id": "windows.firewall", "evidence": [evidence],
                                        "powershell": "DO_NOT_EXPOSE"},),
                             scanner_results=({"scanner_id": "windows.firewall", "status": "success",
                                               "findings": ["f-1"], "execution_evidence": {"completeness": "complete"}},))
    world.assessments.items.extend((
        _assessment(scanned, org, "scan-1", "completed", NOW, result=result),
        _assessment(failed, org, "scan-2", "failed", NOW),
        _assessment(foreign, world.foreign_organization.organization_id, "foreign-1", "completed", NOW, result=result),
    ))

    path = f"/api/v1/organizations/{org}/reports/fleet"
    response = world.client.get(path, headers=_headers(world))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    report = response.json()
    assert report["summary"]["total_enrolled"] == 3
    assert report["summary"]["approved"] == 2
    assert report["summary"]["scanned"] == 1
    assert report["summary"]["not_scanned"] == 2
    assert report["summary"]["failed"] == 1
    assert report["summary"]["pending_approval"] == 1
    assert report["summary"]["presence"] == {"online": 1, "stale": 0, "offline": 1, "unknown": 1}
    assert {row["hostname"]: row["scan_status"] for row in report["endpoints"]} == {
        "scanned-pc": "scanned", "failed-pc": "failed", "pending-pc": "not_scanned"}
    row = next(row for row in report["endpoints"] if row["hostname"] == "scanned-pc")
    assert row["findings"][0]["evidence"][0]["observed_value"] == "off"
    assert "DO_NOT_EXPOSE" not in json.dumps(report)
    assert response.json()["endpoints"][0]["latest_assessment"] is not None

    # An explicit selection cannot import another tenant's assessment.
    foreign_response = world.client.get(path + "?assessment_id=foreign-1", headers=_headers(world))
    assert foreign_response.status_code == 404
    endpoint_response = world.client.get(
        f"/api/v1/organizations/{org}/endpoints/{foreign.endpoint_id}/report", headers=_headers(world))
    assert endpoint_response.status_code == 404


def test_report_and_ai_require_session_membership_and_separate_grants():
    world = _world(permissions=("ai.use",))
    path = f"/api/v1/organizations/{world.organization.organization_id}/reports/fleet"
    assert world.client.get(path).status_code == 401
    assert world.client.get(path, headers=_headers(world)).status_code == 403
    other_path = f"/api/v1/organizations/{world.foreign_organization.organization_id}/reports/fleet"
    assert world.client.get(other_path, headers=_headers(world)).status_code == 403
    ai_path = f"/api/v1/organizations/{world.organization.organization_id}/ai/analyze"
    assert world.client.post(ai_path, json={}, headers=_headers(world)).status_code == 403
    assert world.provider.prompts == []
    reporter = _world(permissions=("reports.read",))
    reporter_path = f"/api/v1/organizations/{reporter.organization.organization_id}/reports/fleet"
    reporter_ai_path = f"/api/v1/organizations/{reporter.organization.organization_id}/ai/analyze"
    assert reporter.client.get(reporter_path, headers=_headers(reporter)).status_code == 200
    assert reporter.client.post(reporter_ai_path, json={}, headers=_headers(reporter)).status_code == 403


def test_local_ai_uses_only_bounded_completed_evidence_and_degrades_cleanly():
    provider = FakeProvider()
    world = _world(provider=provider)
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "lab-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    result = SimpleNamespace(status="completed", findings=({"finding_id": "one", "severity": "high",
                                        "title": "Firewall disabled", "description": "Review firewall",
                                        "evidence": [{"source": "firewall", "description": "Off",
                                                      "raw_metadata": {"password": "DO_NOT_EXPOSE"}}]},),
                             scanner_results=({"scanner_id": "windows.firewall", "status": "success",
                                               "execution_evidence": {"completeness": "complete"}},))
    world.assessments.items.append(_assessment(endpoint, org, "scan-ai", "completed", NOW, result=result))
    path = f"/api/v1/organizations/{org}/ai/analyze"
    response = world.client.post(path, json={"endpoint_id": str(endpoint.endpoint_id)}, headers=_headers(world))
    assert response.status_code == 200
    assert response.json()["status"] == "available"
    assert response.json()["advisory"] is True
    assert response.json()["source"]["assessment_ids"] == ["scan-ai"]
    assert "DO_NOT_EXPOSE" not in provider.prompts[0]
    assert len(provider.prompts[0]) <= 12000

    provider.fail = True
    degraded = world.client.post(path, json={}, headers=_headers(world))
    assert degraded.status_code == 200
    assert degraded.json()["status"] == "unavailable"
    assert degraded.json()["reason_code"] == "LOCAL_AI_UNAVAILABLE"
    assert "provider response" not in json.dumps(degraded.json())


def test_local_ai_configuration_rejects_remote_or_redirect_destinations():
    assert LocalAIConfig.from_config({"ai": {"lm_studio": {"url": "http://localhost:1234/v1",
                                                         "max_tokens": 4000}}}).max_output_tokens == 1024
    assert not LocalAIConfig.from_config().enabled
    for url in ("http://example.com/v1", "http://127.0.0.1.evil.com/v1",
                "http://user:secret@127.0.0.1:1234/v1", "http://127.0.0.1:1234/v1?next=evil"):
        with pytest.raises(ValueError):
            LocalAIConfig(enabled=True, base_url=url)
    with pytest.raises(ValueError):
        LocalAIConfig(enabled=True, model=" ")
    with pytest.raises(ValueError):
        LocalAIConfig(enabled=True, timeout_seconds=0)
    provider = LocalOpenAIProvider(LocalAIConfig(enabled=True))

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, *_):
            return json.dumps({"choices": [{"message": {"content": "Local advisory"}}]}).encode()

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "http://127.0.0.1:1234/v1/chat/completions"
            assert timeout == 30
            body = json.loads(request.data)
            assert "tools" not in body and body["stream"] is False
            return Response()

    provider._opener = Opener()
    assert provider.analyze("{}") == "Local advisory"


def test_completed_assessment_with_skipped_scanner_is_partial_not_clean():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "partial-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(
        {"scanner_id": "windows.firewall", "status": "skipped", "error": "unsupported"},))
    world.assessments.items.append(_assessment(endpoint, org, "partial-1", "completed", NOW, result=result))
    response = world.client.get(f"/api/v1/organizations/{org}/reports/fleet", headers=_headers(world))
    assert response.status_code == 200
    report = response.json()
    assert report["summary"]["scanned"] == 0
    assert report["summary"]["partial"] == 1
    assert report["summary"]["not_scanned"] == 0
    assert report["endpoints"][0]["scan_status"] == "partial"
    assert report["endpoints"][0]["scanner_results"][0]["status"] == "skipped"
    assert report["endpoints"][0]["partial_evidence"] is True
    ai_response = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={}, headers=_headers(world))
    assert ai_response.status_code == 200
    assert json.loads(world.provider.prompts[0])["scanned_endpoints"][0]["scan_status"] == "partial"


@pytest.mark.parametrize("anomaly", [
    {},
    {"execution_evidence": {"completeness": "partial"}},
    {"error": "SECRET_CANARY"},
    {"error_category": "READ_FAILED"},
])
def test_fleet_report_does_not_call_inconsistent_success_fully_scanned(anomaly):
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "incomplete-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    scanner_result = {"scanner_id": "windows.firewall", "status": "success", "findings": [], **anomaly}
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(scanner_result,))
    world.assessments.items.append(_assessment(endpoint, org, "incomplete-1", "completed", NOW, result=result))
    report = world.client.get(f"/api/v1/organizations/{org}/reports/fleet", headers=_headers(world)).json()
    assert report["summary"]["scanned"] == 0
    assert report["summary"]["partial"] == 1
    assert report["endpoints"][0]["scanner_results"][0]["status"] == "unknown"
    assert "SECRET_CANARY" not in json.dumps(report)


@pytest.mark.parametrize("status", ["skipped", "incompatible"])
def test_fleet_report_does_not_count_findings_from_uncollected_scanners(status):
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "uncollected-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(
        {"scanner_id": "windows.firewall", "status": status, "findings": [{"title": "unconfirmed"}]},))
    world.assessments.items.append(_assessment(endpoint, org, "uncollected-1", "completed", NOW, result=result))
    report = world.client.get(f"/api/v1/organizations/{org}/reports/fleet", headers=_headers(world)).json()
    assert report["endpoints"][0]["scan_status"] == "partial"
    assert report["endpoints"][0]["scanner_results"][0]["finding_count"] == 0


def test_completed_without_result_is_failed_and_ai_stays_unavailable():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "missing-result-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    world.assessments.items.append(_assessment(endpoint, org, "empty-result", "completed", NOW))
    report = world.client.get(f"/api/v1/organizations/{org}/reports/fleet", headers=_headers(world)).json()
    assert report["summary"]["scanned"] == 0
    assert report["summary"]["failed"] == 1
    assert report["endpoints"][0]["scan_status"] == "failed"
    ai = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={}, headers=_headers(world))
    assert ai.status_code == 200
    assert ai.json()["reason_code"] == "NO_COMPLETED_EVIDENCE"
    assert world.provider.prompts == []


def test_malformed_completed_evidence_is_partial_without_report_failure():
    world = _world()
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "malformed-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    result = SimpleNamespace(status="completed", findings="invalid-finding-list",
                             scanner_results=({"scanner_id": "windows.firewall", "status": "success",
                                               "findings": 123},))
    world.assessments.items.append(_assessment(endpoint, org, "malformed-result", "completed", NOW,
                                               result=result))
    response = world.client.get(f"/api/v1/organizations/{org}/reports/fleet", headers=_headers(world))
    assert response.status_code == 200
    row = response.json()["endpoints"][0]
    assert row["scan_status"] == "partial"
    assert row["malformed_findings"] == 1
    assert row["scanner_results"][0]["finding_count"] == 0


def test_disabled_local_ai_returns_explicit_unavailable_state():
    provider = FakeProvider()
    provider.enabled = False
    world = _world(provider=provider)
    org = world.organization.organization_id
    endpoint = Endpoint(EndpointId.new(), "scanned-pc", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                        created_at=NOW, organization_id=org)
    world.endpoints.add(endpoint)
    result = SimpleNamespace(status="completed", findings=(), scanner_results=(
        {"scanner_id": "windows.firewall", "status": "success",
         "execution_evidence": {"completeness": "complete"}},))
    world.assessments.items.append(_assessment(endpoint, org, "scan-disabled-ai", "completed", NOW, result=result))
    response = world.client.post(f"/api/v1/organizations/{org}/ai/analyze", json={}, headers=_headers(world))
    assert response.status_code == 200
    assert response.json()["reason_code"] == "LOCAL_AI_DISABLED"
    assert provider.prompts == []


def test_fleet_csv_export_is_tenant_scoped_and_excel_formula_safe():
    world = _world()
    org = world.organization.organization_id
    world.endpoints.add(Endpoint(EndpointId.new(), '=WEBSERVICE("http://evil")', PlatformInfo("Windows"),
                                 EndpointStatus.NEW, created_at=NOW, organization_id=org))
    world.endpoints.add(Endpoint(EndpointId.new(), "other-pc", PlatformInfo("Windows"),
                                 EndpointStatus.NEW, created_at=NOW,
                                 organization_id=world.foreign_organization.organization_id))
    response = world.client.get(f"/api/v1/organizations/{org}/reports/fleet.csv", headers=_headers(world))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.DictReader(StringIO(response.text.lstrip("\ufeff"))))
    assert len(rows) == 1
    assert rows[0]["hostname"].startswith("'=WEBSERVICE")
    assert rows[0]["scan_status"] == "not_scanned"


def test_local_provider_enforces_prompt_response_and_failure_bounds():
    provider = LocalOpenAIProvider(LocalAIConfig(enabled=True))
    with pytest.raises(ValueError):
        provider.analyze("X" * 12001)

    class Response:
        status = 200

        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, *_):
            return self.body

    class Opener:
        def __init__(self, body=None, error=None):
            self.body, self.error = body, error

        def open(self, *_args, **_kwargs):
            if self.error:
                raise self.error
            return Response(self.body)

    provider._opener = Opener(b"{invalid")
    with pytest.raises(RuntimeError, match="invalid local AI response"):
        provider.analyze("{}")
    provider._opener = Opener(b"X" * 65537)
    with pytest.raises(RuntimeError, match="exceeds bound"):
        provider.analyze("{}")
    provider._opener = Opener(error=TimeoutError("private provider detail"))
    with pytest.raises(RuntimeError, match="local AI provider unavailable") as error:
        provider.analyze("{}")
    assert "private provider detail" not in str(error.value)
    provider._opener = Opener(json.dumps({"choices": [{"message": {"content": "A" * 13000}}]}).encode())
    with pytest.raises(RuntimeError, match="output exceeds bound"):
        provider.analyze("{}")

    # urllib's opener has no inherited proxy settings and its redirect
    # handler refuses a move to an attacker-controlled destination.
    from urllib.request import ProxyHandler
    from backend.infrastructure.ai.local_openai import _NoRedirect
    fresh = LocalOpenAIProvider(LocalAIConfig(enabled=True))
    assert not any(isinstance(handler, ProxyHandler) for handler in fresh._opener.handlers)
    assert _NoRedirect().redirect_request(None, None, 302, "redirect", {}, "http://example.com") is None
