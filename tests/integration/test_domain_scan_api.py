"""FastAPI → use case → domain → SQLAlchemy integration tests with fake scans."""

import asyncio
from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.api.main import app
from backend.api.v1 import scan as scan_api
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.assessment.local_runner import LocalAssessmentRunner
from backend.application.scanner import LocalTargetCapabilityProvider, ScannerRegistry
from backend.application.scanner.legacy_adapters import FIREWALL_MANIFEST, LegacyMethodScannerAdapter
from backend.core.database.database import DatabaseManager


def _manager(tmp_path):
    database_path = tmp_path / "domain_api.db"
    config_path = tmp_path / "domain_api.yaml"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  sqlite_path: '{database_path.as_posix()}'\n",
        encoding="utf-8",
    )
    manager = DatabaseManager(str(config_path))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def _override_database(manager):
    async def override():
        async with manager.get_async_db() as session:
            yield session

    return override


def test_default_start_route_uses_domain_runner_and_preserves_response(tmp_path, monkeypatch):
    manager = _manager(tmp_path)

    class FakeScanner:
        system_info = {"hostname": "api-test-host"}

        def scan_all(self, progress_callback=None):
            return [
                {
                    "severity": "high",
                    "category": "Firewall",
                    "title": "Windows Firewall Disabled",
                    "details": "The public profile is disabled.",
                    "component": "Windows Defender Firewall",
                    "remediation": "Enable the firewall.",
                    "powershell_command": "Set-NetFirewallProfile -Enabled True",
                }
            ]

    monkeypatch.setattr(scan_api, "db_manager", manager)
    monkeypatch.setattr(scan_api, "local_assessment_runner", LocalAssessmentRunner(FakeScanner))
    app.dependency_overrides[scan_api.get_async_db_session] = _override_database(manager)

    try:
        client = TestClient(app, client=("127.0.0.1", 50000))
        response = client.post("/api/v1/scan/start", json={"scan_type": "full", "deep_scan": True})

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"scan_id", "status", "message", "estimated_duration"}
        assert body["status"] == "started"
        assert body["estimated_duration"] == 300

        status = client.get(f"/api/v1/scan/status/{body['scan_id']}")
        assert status.status_code == 200
        assert status.json()["status"] == "completed"
        assert status.json()["vulnerabilities_found"] == 1

        results = client.get(f"/api/v1/scan/results/{body['scan_id']}")
        assert results.status_code == 200
        assert results.json()["vulnerabilities"][0]["title"] == "Windows Firewall Disabled"
    finally:
        app.dependency_overrides.clear()
        manager.close()
        asyncio.run(manager.close_async())


def test_default_start_route_persists_scanner_failure(tmp_path, monkeypatch):
    manager = _manager(tmp_path)

    class FailingScanner:
        system_info = {}

        def scan_all(self, progress_callback=None):
            raise RuntimeError("test scanner failure")

    monkeypatch.setattr(scan_api, "db_manager", manager)
    monkeypatch.setattr(scan_api, "local_assessment_runner", LocalAssessmentRunner(FailingScanner))
    app.dependency_overrides[scan_api.get_async_db_session] = _override_database(manager)

    try:
        client = TestClient(app, client=("127.0.0.1", 50000))
        response = client.post("/api/v1/scan/start", json={"scan_type": "full", "deep_scan": True})
        assert response.status_code == 200

        status = client.get(f"/api/v1/scan/status/{response.json()['scan_id']}")
        assert status.status_code == 200
        assert status.json()["status"] == "failed"
    finally:
        app.dependency_overrides.clear()
        manager.close()
        asyncio.run(manager.close_async())


def test_selected_firewall_route_uses_registry_adapter_and_persists_result(tmp_path, monkeypatch):
    manager = _manager(tmp_path)

    class SelectedTargetRunner:
        def resolve_target(self):
            from backend.domain.assessment import AssessmentTarget

            return AssessmentTarget("local:selected", "selected-host", "Windows")

        def run(self, target, options=None):
            raise AssertionError("scanner selection must not use the legacy full scan")

    class FakeFirewallScanner:
        def __init__(self):
            self.vulnerabilities = []

        def check_firewall(self):
            self.vulnerabilities.append(
                {
                    "severity": "high",
                    "category": "Firewall",
                    "title": "Windows Firewall Disabled",
                    "details": "The public profile is disabled.",
                    "component": "Windows Defender Firewall",
                    "remediation": "Enable the firewall.",
                }
            )

    firewall_adapter = LegacyMethodScannerAdapter(FIREWALL_MANIFEST, "check_firewall", FakeFirewallScanner)
    orchestrator = LocalAssessmentOrchestrator(
        ScannerRegistry((firewall_adapter,)),
        LocalTargetCapabilityProvider().capabilities_for,
    )
    monkeypatch.setattr(scan_api, "db_manager", manager)
    monkeypatch.setattr(scan_api, "local_assessment_runner", SelectedTargetRunner())
    monkeypatch.setattr(scan_api, "local_assessment_orchestrator", orchestrator)
    app.dependency_overrides[scan_api.get_async_db_session] = _override_database(manager)

    try:
        client = TestClient(app, client=("127.0.0.1", 50000))
        response = client.post(
            "/api/v1/scan/start",
            json={"scan_type": "full", "deep_scan": True, "scanner_ids": ["windows.firewall"]},
        )

        assert response.status_code == 200
        scan_id = response.json()["scan_id"]
        status = client.get(f"/api/v1/scan/status/{scan_id}")
        assert status.json()["status"] == "completed"
        assert status.json()["vulnerabilities_found"] == 1

        results = client.get(f"/api/v1/scan/results/{scan_id}")
        assert results.json()["vulnerabilities"][0]["title"] == "Windows Firewall Disabled"

        unknown = client.post(
            "/api/v1/scan/start",
            json={"scan_type": "full", "deep_scan": True, "scanner_ids": ["windows.unknown"]},
        )
        unknown_status = client.get(f"/api/v1/scan/status/{unknown.json()['scan_id']}")
        assert unknown.status_code == 200
        assert unknown_status.json()["status"] == "completed"
        assert unknown_status.json()["vulnerabilities_found"] == 0
    finally:
        app.dependency_overrides.clear()
        manager.close()
        asyncio.run(manager.close_async())


def test_scanner_selection_rejects_ambiguous_legacy_options(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(scan_api, "db_manager", manager)
    app.dependency_overrides[scan_api.get_async_db_session] = _override_database(manager)

    try:
        client = TestClient(app, client=("127.0.0.1", 50000))
        response = client.post(
            "/api/v1/scan/start",
            json={"scan_type": "quick", "scanner_ids": ["windows.firewall"]},
        )

        assert response.status_code == 422
        assert response.json()["detail"] == "scanner_ids can only be combined with the default full local scan options"
    finally:
        app.dependency_overrides.clear()
        manager.close()
        asyncio.run(manager.close_async())
