"""Tests that remediation baseline paths do not mutate the host unintentionally."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import backend.core.remediation.auto_fixer as auto_fixer_module
from backend.api.v1.remediation import RemediationRequest, fix_vulnerabilities
from backend.core.remediation.auto_fixer import AutoFixer


def test_unknown_remediation_does_not_execute_a_command(monkeypatch):
    def command_must_not_run(*args, **kwargs):
        raise AssertionError("Unsupported remediation attempted host mutation")

    monkeypatch.setattr(auto_fixer_module.subprocess, "run", command_must_not_run)

    result = asyncio.run(AutoFixer().apply_fix({"category": "Unknown", "title": "Unknown Finding"}))

    assert result["success"] is False
    assert result["error"] == "No automated fix available for this vulnerability type"


def test_known_remediation_routes_only_through_mocked_subprocess(monkeypatch):
    calls = []

    def mocked_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(auto_fixer_module.subprocess, "run", mocked_run)
    result = asyncio.run(AutoFixer().apply_fix({"category": "Firewall", "title": "Firewall Disabled"}))

    assert result["success"] is True
    assert calls[0][0] == "netsh advfirewall set allprofiles state on"


def test_api_rejects_destructive_remediation_without_explicit_permission():
    vulnerability = SimpleNamespace(
        id="v-1",
        severity="high",
        category="Firewall",
        title="Firewall Disabled",
        details="test",
        component="Firewall",
        remediation="Enable the firewall",
        scan_id="s-1",
    )

    class FakeResult:
        def scalars(self):
            return SimpleNamespace(all=lambda: [vulnerability])

    class FakeSession:
        async def execute(self, statement):
            return FakeResult()

    request = RemediationRequest(
        vulnerability_ids=["v-1"],
        auto_fix=True,
        allow_destructive=False,
        dry_run=False,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(fix_vulnerabilities(request, background_tasks=None, db=FakeSession()))

    assert error.value.status_code == 403
