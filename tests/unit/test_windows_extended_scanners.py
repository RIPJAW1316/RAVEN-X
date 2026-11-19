"""Contract tests for the remote Windows checks adapted from scanner.py."""

import json
from dataclasses import asdict
from subprocess import CompletedProcess, run
import sys

import pytest

from backend.agent.windows_extended_checks import CHECKS
from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import AssessmentTarget
from backend.domain.scanner import ScannerCapability, ScannerExecutionStatus, TargetCapabilities
from backend.protocol.agent import AssessmentResultPayload


TARGET = AssessmentTarget("endpoint:test", "workstation", "Windows")
CAPABILITIES = TargetCapabilities(frozenset({ScannerCapability("windows.powershell")}))
MANIFESTS = {scanner.manifest.scanner_id: scanner.manifest for scanner in windows_read_only_scanners()}


def _execute(scanner_id, raw):
    return WindowsReadOnlyScanner(
        MANIFESTS[scanner_id],
        runner=lambda argv, **kwargs: CompletedProcess(argv, 0, raw, "private-canary"),
    ).execute(TARGET, CAPABILITIES)


def test_extended_catalogue_has_unique_registered_identifiers():
    assert len(MANIFESTS) == 39
    assert set(CHECKS).issubset(MANIFESTS)
    assert len(CHECKS) == 35


@pytest.mark.parametrize("scanner_id", CHECKS)
def test_each_extended_check_reports_confirmed_and_clean_states(scanner_id):
    rule_id = next(iter(CHECKS[scanner_id].rules))
    confirmed = _execute(scanner_id, json.dumps({"CollectionStatus": "ok", "Issues": [rule_id]}))
    assert confirmed.status is ScannerExecutionStatus.SUCCESS
    assert len(confirmed.findings) == 1
    assert confirmed.findings[0].metadata["rule_id"] == rule_id
    assert confirmed.execution_evidence.rules_completed == tuple(CHECKS[scanner_id].rules)
    assert "private-canary" not in str(asdict(confirmed.findings[0]))

    clean = _execute(scanner_id, '{"CollectionStatus":"ok","Issues":[]}')
    assert clean.status is ScannerExecutionStatus.SUCCESS
    assert clean.findings == ()


@pytest.mark.parametrize("raw", [
    '{"CollectionStatus":"ok","Issues":["private-canary"]}',
    '{"CollectionStatus":"ok","Issues":[],"Issues":[]}',
    '{"CollectionStatus":"ok","Issues":[null]}',
    '{"CollectionStatus":"ok","Issues":{},"nested":{"x":1,"x":2}}',
    '{"CollectionStatus":"ok","Issues":NaN}',
    '{"CollectionStatus":"unsupported","Issues":["updates.disabled"]}',
    '{"CollectionStatus":"unknown","Issues":[]}',
])
def test_malformed_extended_collection_fails_closed_and_sanitizes(raw):
    result = _execute("windows.updates", raw)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.findings == ()
    assert "private-canary" not in result.error


def test_unsupported_extended_collection_is_not_clean():
    result = _execute("windows.updates", '{"CollectionStatus":"unsupported","Issues":[]}')
    assert result.status is ScannerExecutionStatus.INCOMPATIBLE
    assert result.execution_evidence.completeness.value == "unknown"


def test_confirmed_rdp_finding_survives_incomplete_nla_collection():
    result = _execute("windows.rdp", '{"CollectionStatus":"partial","Issues":["rdp.enabled"]}')
    assert result.status is ScannerExecutionStatus.FAILED
    assert [finding.title for finding in result.findings] == ["Remote Desktop Enabled"]
    assert result.execution_evidence.completeness.value == "partial"
    assert result.execution_evidence.rules_completed == ()


def test_partial_extended_finding_survives_remote_assessment_wire_contract():
    scanner = WindowsReadOnlyScanner(
        MANIFESTS["windows.rdp"],
        runner=lambda argv, **kwargs: CompletedProcess(
            argv, 0, '{"CollectionStatus":"partial","Issues":["rdp.enabled"]}', ""),
    )
    assessment = LocalAssessmentOrchestrator(
        ScannerRegistry((scanner,)), lambda target: CAPABILITIES,
    ).run(TARGET, ("windows.rdp",))
    wire = AssessmentResultPayload.from_assessment_result(assessment).to_dict()
    assert wire["status"] == "completed"
    assert len(wire["findings"]) == 1
    assert wire["findings"][0]["metadata"]["rule_id"] == "rdp.enabled"
    assert wire["scanner_results"][0]["status"] == "failed"
    assert wire["scanner_results"][0]["execution_evidence"]["completeness"] == "partial"


def test_extended_scripts_are_fixed_and_do_not_disclose_raw_names_or_secrets():
    from backend.agent.windows_extended_checks import script_for

    scripts = [script_for(check) for check in CHECKS.values()]
    for script in scripts:
        assert "ConvertTo-Json" in script
        assert "Invoke-Expression" not in script
        assert "DefaultPassword" not in script
        assert "key=clear" not in script
        assert "Set-ItemProperty" not in script
        assert "Remove-" not in script


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell collectors")
@pytest.mark.parametrize("scanner_id,fixture,status,issues", [
    ("windows.smb-client-signing",
     "function Get-SmbClientConfiguration {[pscustomobject]@{RequireSecuritySignature=$false}}",
     "ok", ["smb.client_signing_not_required"]),
    ("windows.smb-client-signing",
     "function Get-SmbClientConfiguration {[pscustomobject]@{RequireSecuritySignature=$true}}",
     "ok", []),
    ("windows.defender-exclusion-scope",
     r"""function Get-MpComputerStatus {[pscustomobject]@{AMRunningMode='Normal'}}
         function Get-MpPreference {[pscustomobject]@{ExclusionPath=@('C:\Users\private-canary\Downloads')}}""",
     "ok", ["defender.user_path_excluded"]),
    ("windows.defender-signature-age",
     "function Get-MpComputerStatus {[pscustomobject]@{AMRunningMode='Passive'}}",
     "unsupported", []),
    ("windows.hotfix-recency",
     "function Get-HotFix {[pscustomobject]@{InstalledOn=(Get-Date).AddDays(-70)}; "
     "[pscustomobject]@{InstalledOn=(Get-Date).AddDays(-4)}}",
     "ok", []),
    ("windows.hotfix-recency",
     "function Get-HotFix {[pscustomobject]@{InstalledOn=(Get-Date).AddDays(-70)}}",
     "ok", ["updates.hotfix_inventory_old"]),
    ("windows.hotfix-recency",
     "function Get-HotFix {[pscustomobject]@{InstalledOn=(Get-Date).AddDays(-70)}; "
     "[pscustomobject]@{InstalledOn=$null}}",
     "partial", []),
])
def test_new_collectors_evaluate_observed_powershell_values(scanner_id, fixture, status, issues):
    from backend.agent.windows_extended_checks import script_for

    result = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                  fixture + "\n" + script_for(CHECKS[scanner_id])],
                 text=True, capture_output=True, timeout=15, check=True)
    assert json.loads(result.stdout) == {"CollectionStatus": status, "Issues": issues}
    assert "private-canary" not in result.stdout
