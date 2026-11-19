"""RC7 catalogue through authenticated loopback HTTPS and persisted reporting.

This uses disposable server state and the real read-only Windows collectors.
It does not install a service, change a task, or use a live enrollment token.
"""

from pathlib import Path
import platform
import socket
import ssl
import sys

import httpx
import pytest

from test_https_windows_golden_path import _certificates, _https_server, _isolated_app

from backend.agent.runtime import (
    AgentConfig, AgentCredential, InMemoryAgentCredentialStore,
    InMemoryAgentIdentityStore, RavenXAgent,
)
from backend.agent.windows_scanners import windows_read_only_scanners
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.scanner.local_capabilities import LocalTargetCapabilityProvider
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.enrollment import CredentialId
from backend.infrastructure.transport.http import HttpAgentTransport, HttpTransportConfig
from backend.infrastructure.transport.http.client import HttpAgentEnrollmentClient


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows collectors")


def test_all_rc7_windows_collectors_cross_authenticated_https(tmp_path: Path):
    ca_path, cert_path, key_path = _certificates(tmp_path)
    trust = ssl.create_default_context(cafile=str(ca_path))
    trust.verify_flags |= ssl.VERIFY_X509_STRICT
    app, db, organization, _, _, _ = _isolated_app(tmp_path)
    try:
        with _https_server(app, cert_path, key_path) as base_url:
            transport_config = HttpTransportConfig(base_url, verify=trust, timeout_seconds=60)
            with httpx.Client(verify=trust, trust_env=False, timeout=60) as human:
                login = human.post(base_url + "/api/v1/auth/login", json={
                    "email": "golden-owner@example.com", "password": "GOLDEN_PASSWORD_SENTINEL",
                })
                assert login.status_code == 200
                headers = {"Authorization": "Bearer " + login.json()["session_token"]}
                tenant = f"{base_url}/api/v1/organizations/{organization.organization_id}"
                issued = human.post(tenant + "/enrollment-tokens", headers=headers,
                                    json={"ttl_minutes": 10, "label": "RC7 catalogue"})
                assert issued.status_code == 201
                token = issued.json()
                enrollment = HttpAgentEnrollmentClient(transport_config)
                try:
                    grant = enrollment.enroll(
                        enrollment_id=token["enrollment_id"],
                        bootstrap_token=token["enrollment_token"],
                        hostname=socket.gethostname(), platform_name="Windows",
                        platform_version=platform.version(), architecture=platform.machine(),
                        agent_version="1.0.0-rc7", protocol_version="1.0",
                    )
                finally:
                    enrollment.close()
                approved = human.post(tenant + f"/endpoints/{grant.endpoint_id}/approve", headers=headers)
                assert approved.status_code == 200

                credentials = InMemoryAgentCredentialStore(AgentCredential(
                    CredentialId(grant.credential_id), grant.credential_secret,
                ))
                transport = HttpAgentTransport(transport_config, credentials, endpoint_id=grant.endpoint_id)
                registry = ScannerRegistry(windows_read_only_scanners())
                capabilities = LocalTargetCapabilityProvider()
                agent = RavenXAgent(
                    config=AgentConfig(hostname=socket.gethostname(), platform="Windows",
                                       platform_version=platform.version(), architecture=platform.machine()),
                    identity_store=InMemoryAgentIdentityStore(grant.endpoint_id),
                    credential_store=credentials, capability_provider=capabilities,
                    scanner_registry=registry,
                    assessment_orchestrator=LocalAssessmentOrchestrator(registry, capabilities.capabilities_for),
                    sender=transport,
                )
                try:
                    assert agent.start().value == "ready"
                    agent.emit_startup_messages()
                    requested_ids = [scanner.manifest.scanner_id for scanner in windows_read_only_scanners()]
                    assert len(requested_ids) == 39
                    requested = human.post(tenant + "/assessments", headers=headers,
                                           json={"endpoint_id": str(grant.endpoint_id),
                                                 "scanner_ids": requested_ids})
                    assert requested.status_code == 200
                    assessment_id = requested.json()["assessment_id"]
                    leased = transport.poll_work()
                    assert leased is not None
                    agent.receive_leased_work(leased)
                    response = human.get(tenant + f"/assessments/{assessment_id}", headers=headers)
                    assert response.status_code == 200
                    report = response.json()
                    assert report["state"] == "completed"
                    results = report["result"]["scanner_results"]
                    assert {item["scanner_id"] for item in results} == set(requested_ids)
                    assert len(results) == len(requested_ids)
                    assert all(item["status"] in {"success", "failed", "incompatible"} for item in results)
                    detail = human.get(tenant + f"/assessments/{assessment_id}/details", headers=headers)
                    assert detail.status_code == 200
                    assert {item["scanner_id"] for item in detail.json()["scanner_results"]} == set(requested_ids)
                finally:
                    agent.stop()
                    transport.close()
    finally:
        db.close()
