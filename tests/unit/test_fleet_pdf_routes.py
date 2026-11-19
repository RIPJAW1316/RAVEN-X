from backend.domain.endpoint import Endpoint, EndpointId, EndpointStatus, PlatformInfo
from test_tenant_insights import _headers, _world


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
