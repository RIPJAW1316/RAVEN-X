from types import SimpleNamespace

from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from test_tenant_insights import NOW, _assessment, _headers, _world


def test_pdf_exports_use_tenant_and_report_permissions():
    world = _world()
    org = world.organization.organization_id
    headers = _headers(world)
    fleet_path = f"/api/v1/organizations/{org}/reports/fleet.pdf"
    pdf = world.client.get(fleet_path, headers=headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["cache-control"] == "no-store"
    assert world.client.get(fleet_path).status_code == 401
    assert world.client.get(f"/api/v1/organizations/{world.foreign_organization.organization_id}/reports/fleet.pdf",
                            headers=headers).status_code == 403
    machine = Endpoint(EndpointId.new(), "lab-vm", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       organization_id=org)
    world.endpoints.add(machine)
    machine_path = f"/api/v1/organizations/{org}/endpoints/{machine.endpoint_id}/report.pdf"
    machine_pdf = world.client.get(machine_path, headers=headers)
    assert machine_pdf.status_code == 200 and machine_pdf.content.startswith(b"%PDF-")
    assert "ravenx-machine-report.pdf" in machine_pdf.headers["content-disposition"]
    assert world.client.get(f"/api/v1/organizations/{org}/endpoints/{EndpointId.new()}/report.pdf",
                            headers=headers).status_code == 404
    no_reports = _world(permissions=("ai.use",))
    assert no_reports.client.get(f"/api/v1/organizations/{no_reports.organization.organization_id}/reports/fleet.pdf",
                                 headers=_headers(no_reports)).status_code == 403


def test_reviewed_reports_use_scoped_evidence_and_explain_fallback(monkeypatch):
    world = _world()
    org = world.organization.organization_id
    machine = Endpoint(EndpointId.new(), "review-vm", PlatformInfo("Windows"), EndpointStatus.ACTIVE,
                       organization_id=org)
    world.endpoints.add(machine)
    result = SimpleNamespace(
        status="completed",
        findings=[{"finding_id": "fw-1", "severity": "high", "title": "Firewall profile is off",
                   "description": "The public profile is disabled.", "scanner_id": "windows.firewall",
                   "rule_id": "firewall.profile"}],
        scanner_results=[{"scanner_id": "windows.firewall", "status": "success", "findings": ["fw-1"]}],
    )
    world.assessments.items.append(_assessment(machine, org, "review-assessment", "completed", NOW, result=result))
    calls = []

    def prioritize(prompt):
        calls.append(prompt)
        return '["f1"]'

    monkeypatch.setattr(world.provider, "prioritize_findings", prioritize, raising=False)
    path = f"/api/v1/organizations/{org}/reports/review"
    scope = {"endpoint_id": str(machine.endpoint_id)}
    response = world.client.post(path, params=scope, headers=_headers(world))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    report = response.json()
    assert report["report"]["scope"]["endpoint_id"] == str(machine.endpoint_id)
    assert report["review"]["provider"] == "lm_studio"
    assert report["review"]["model"] == "local-test-model"
    assert report["review"]["finding_count"] == 1
    assert report["review"]["priorities"][0]["assessment_id"] == "review-assessment"
    assert len(calls) == 1

    pdf = world.client.post(path, params={**scope, "format": "pdf"}, headers=_headers(world))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
    assert "ravenx-machine-reviewed-report.pdf" in pdf.headers["content-disposition"]
    assert len(calls) == 2

    fallback = world.client.post(path, params={**scope, "model": "gemini"}, headers=_headers(world)).json()["review"]
    assert fallback["provider"] == "offline"
    assert "disabled" in fallback["note"]
    assert len(calls) == 2
    assert world.client.post(path, params={"endpoint_id": str(EndpointId.new())}, headers=_headers(world)).status_code == 404
    assert world.client.post(path).status_code == 401

    restricted = _world(permissions=("reports.read",))
    restricted_path = f"/api/v1/organizations/{restricted.organization.organization_id}/reports/review"
    assert restricted.client.post(restricted_path, headers=_headers(restricted)).status_code == 403
