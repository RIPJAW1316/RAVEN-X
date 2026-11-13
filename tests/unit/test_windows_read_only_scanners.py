import json
import re
from contextlib import nullcontext
from subprocess import CompletedProcess, TimeoutExpired
import sys
from types import SimpleNamespace

import pytest

from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners
from backend.application.assessment.local_orchestrator import LocalAssessmentOrchestrator
from backend.application.scanner.registry import ScannerRegistry
from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, FindingSeverity
from backend.domain.scanner import ScannerCapability, ScannerExecutionStatus, TargetCapabilities
from backend.protocol.agent import AssessmentResultPayload


TARGET = AssessmentTarget("endpoint:1", "workstation", "Windows")
CAPABILITIES = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read"),
                                             ScannerCapability("windows.registry.read"),
                                             ScannerCapability("windows.powershell")}))


def _scanner(scanner_id, **kwargs):
    manifest = next(x.manifest for x in windows_read_only_scanners() if x.manifest.scanner_id == scanner_id)
    return WindowsReadOnlyScanner(manifest, **kwargs)


def _collect(scanner_id, data):
    return _scanner(scanner_id, runner=lambda argv, **kwargs: CompletedProcess(
        argv, 0, json.dumps(data, ensure_ascii=False), "")).execute(TARGET, CAPABILITIES)


def _wire(result):
    assessment = AssessmentResult(
        "assessment-1", TARGET, AssessmentStatus.COMPLETED, result.started_at,
        result.completed_at, findings=result.findings, scanner_results=(result,),
    )
    payload = AssessmentResultPayload.from_assessment_result(assessment).to_dict()
    return json.loads(json.dumps(payload))["scanner_results"][0]


def _bitlocker(**changes):
    return {"CollectionStatus": "ok", "OSVolume": "D:\\", "MountPoint": "D:",
            "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On", "EncryptionPercentage": 100,
            **changes}


@pytest.mark.parametrize("disabled", [None, "Domain", "Private", "Public"])
def test_firewall_reads_effective_structured_profiles_independent_of_display_language(disabled):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        data = [{"Name": name, "Enabled": "False" if name == disabled else "True",
                 "DisplayName": "公開ネットワーク / Réseau public"}
                for name in ("Domain", "Private", "Public")]
        return CompletedProcess(argv, 0, json.dumps(data, ensure_ascii=False), "")

    result = _scanner("windows.firewall", runner=run).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert len(result.findings) == (0 if disabled is None else 1)
    if disabled:
        expected = FindingSeverity.CRITICAL if disabled == "Public" else FindingSeverity.HIGH
        assert result.findings[0].severity is expected
        assert result.findings[0].metadata["resource_key"] == disabled.lower()
    assert len(calls) == 1
    assert "Get-NetFirewallProfile -PolicyStore ActiveStore" in calls[0][0][-1]
    assert calls[0][1]["shell"] is False
    assert result.execution_evidence.resources_discovered == ("domain", "private", "public")


@pytest.mark.parametrize("enabled,consent,desktop,finds", [
    (0, 2, 1, True), (1, 2, 1, False),
    *[(1, consent, 1, True) for consent in (0, 1, 3, 4, 5)], (1, 2, 0, True),
])
def test_uac_enablement_and_prompt_policy_findings_are_serialized(enabled, consent, desktop, finds):
    requested = []

    def read(name):
        requested.append(name)
        return {"EnableLUA": enabled, "ConsentPromptBehaviorAdmin": consent, "PromptOnSecureDesktop": desktop}[name]

    result = _scanner("windows.uac", registry_reader=read).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert len(result.findings) == int(finds)
    assert requested == ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"]
    wire = _wire(result)
    assert wire["status"] == "success"
    assert wire["execution_evidence"]["completeness"] == "complete"
    assert wire["execution_evidence"]["rules_completed"] == ["uac.configuration"]
    if finds:
        finding = wire["findings"][0]
        assert finding["severity"] == FindingSeverity.HIGH.value
        assert finding["title"] == ("UAC Disabled" if enabled == 0 else "UAC Not at Maximum Security")
        assert finding["metadata"]["rule_id"] == "uac.configuration"
        assert f"EnableLUA={enabled}" in finding["evidence"][0]["observed_value"]


@pytest.mark.parametrize("name,bad", [
    ("EnableLUA", -1), ("EnableLUA", 2), ("EnableLUA", True), ("EnableLUA", "1"),
    ("ConsentPromptBehaviorAdmin", -1), ("ConsentPromptBehaviorAdmin", 6),
    ("ConsentPromptBehaviorAdmin", False), ("ConsentPromptBehaviorAdmin", None),
    ("PromptOnSecureDesktop", 2), ("PromptOnSecureDesktop", True), ("PromptOnSecureDesktop", "1"),
])
def test_malformed_uac_value_is_incomplete_not_clean(name, bad):
    values = {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 2, "PromptOnSecureDesktop": 1, name: bad}
    result = _scanner("windows.uac", registry_reader=values.__getitem__).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "READ_FAILED"
    assert result.findings == ()
    assert result.execution_evidence.rules_completed == ()
    assert _wire(result)["execution_evidence"]["completeness"] == "partial"


@pytest.mark.parametrize("name", ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"])
@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError])
def test_missing_or_denied_uac_read_never_reports_healthy_or_leaks_exception(name, error):
    def read(key):
        if key == name:
            raise error("sensitive-canary")
        return {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 2, "PromptOnSecureDesktop": 1}[key]

    result = _scanner("windows.uac", registry_reader=read).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error == "local read incomplete"
    assert "sensitive-canary" not in json.dumps(_wire(result))


def test_uac_disabled_observation_survives_an_unreadable_prompt_policy():
    values = {"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 2}
    result = _scanner("windows.uac", registry_reader=values.__getitem__).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.findings[0].title == "UAC Disabled"
    assert result.execution_evidence.rules_completed == ()
    assert _wire(result)["findings"][0]["severity"] == FindingSeverity.HIGH.value


@pytest.mark.parametrize("kind,expected", [(4, ScannerExecutionStatus.SUCCESS),
                                         (1, ScannerExecutionStatus.FAILED), (11, ScannerExecutionStatus.FAILED)])
def test_registry_collection_reads_hklm_dword_policy_values_only(monkeypatch, kind, expected):
    calls = []

    def open_key(hive, path):
        calls.append((hive, path))
        return nullcontext(object())

    values = {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 2, "PromptOnSecureDesktop": 1}
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        HKEY_LOCAL_MACHINE="HKLM", REG_DWORD=4, OpenKey=open_key,
        QueryValueEx=lambda key, name: (values[name], kind)))
    result = _scanner("windows.uac").execute(TARGET, CAPABILITIES)
    assert result.status is expected
    assert calls == [("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")] * 3


@pytest.mark.parametrize("volume,protection,percent,reason,title", [
    ("FullyEncrypted", "On", 100, "fully_encrypted_protection_on", None),
    ("FullyEncrypted", "Off", 100, "fully_encrypted_protection_off", "BitLocker Protection Suspended or Off"),
    ("EncryptionInProgress", "On", 50, "encryption_in_progress_protection_on", "BitLocker Encryption In Progress"),
    ("EncryptionInProgress", "Off", 50, "encryption_in_progress_protection_off", "BitLocker Encryption In Progress"),
    ("DecryptionInProgress", "Off", 50, "decryption_in_progress_protection_off", "BitLocker Decryption In Progress"),
    ("FullyDecrypted", "Off", 0, "unencrypted_protection_off", "BitLocker Not Enabled"),
    ("EncryptionPaused", "Off", 40, "encryption_paused_protection_off", "BitLocker Encryption Paused"),
    ("DecryptionPaused", "Off", 40, "decryption_paused_protection_off", "BitLocker Decryption Paused"),
])
def test_bitlocker_posture_requires_complete_encryption_and_active_protection(volume, protection, percent, reason, title):
    result = _collect("windows.bitlocker", _bitlocker(
        VolumeStatus=volume, ProtectionStatus=protection, EncryptionPercentage=percent))
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert len(result.findings) == (0 if title is None else 1)
    wire = _wire(result)
    assert wire["execution_evidence"]["resources_discovered"] == ["d:"]
    assert wire["execution_evidence"]["resource_results"][0]["reason_code"] == reason
    if title:
        assert wire["findings"][0]["title"] == title
        assert wire["findings"][0]["severity"] == FindingSeverity.HIGH.value
        assert wire["findings"][0]["metadata"]["resource_key"] == "d:"
        assert f"ProtectionStatus={protection}" in wire["findings"][0]["evidence"][0]["observed_value"]


def test_bitlocker_missing_cmdlet_is_incompatible_not_a_clean_assessment():
    result = _collect("windows.bitlocker", {"CollectionStatus": "unsupported"})
    wire = _wire(result)
    assert wire["status"] == "incompatible"
    assert wire["error_category"] == "UNSUPPORTED"
    assert wire["execution_evidence"]["completeness"] == "unknown"
    assert wire["execution_evidence"]["rules_completed"] == []
    assert result.findings == ()


@pytest.mark.parametrize("changes", [
    {"ProtectionStatus": "Unknown"}, {"ProtectionStatus": None}, {"ProtectionStatus": 1},
    {"VolumeStatus": "sensitive-canary"}, {"VolumeStatus": []},
    {"EncryptionPercentage": True}, {"EncryptionPercentage": "100"},
    {"EncryptionPercentage": 101}, {"EncryptionPercentage": -1}, {"EncryptionPercentage": 50},
    {"MountPoint": "C:"}, {"OSVolume": "sensitive-canary"}, {"OSVolume": None},
    {"CollectionStatus": "unknown"}, {"VolumeStatus": "FullyDecrypted", "EncryptionPercentage": 0},
])
def test_ambiguous_or_inconsistent_bitlocker_state_fails_closed(changes):
    result = _collect("windows.bitlocker", _bitlocker(**changes))
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "READ_FAILED"
    assert result.execution_evidence.rules_completed == ()
    assert "sensitive-canary" not in json.dumps(_wire(result))


@pytest.mark.parametrize("missing", ["CollectionStatus", "OSVolume", "MountPoint", "VolumeStatus", "ProtectionStatus", "EncryptionPercentage"])
def test_missing_bitlocker_fields_fail_closed(missing):
    data = _bitlocker()
    del data[missing]
    assert _collect("windows.bitlocker", data).status is ScannerExecutionStatus.FAILED


@pytest.mark.parametrize("data", [[], {}, [{"Name": "Domain", "Enabled": "True"}],
    [{"Name": name, "Enabled": "NotConfigured"} for name in ("Domain", "Private", "Public")],
    [{"Name": "Domain", "Enabled": "True"}] * 3])
def test_firewall_missing_duplicate_or_unknown_profile_states_are_not_clean(data):
    result = _collect("windows.firewall", data)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.execution_evidence.rules_completed == ()


@pytest.mark.parametrize("scanner_id", ["windows.bitlocker", "windows.firewall", "windows.smb"])
@pytest.mark.parametrize("failure", ["exit", "permission", "timeout", "localized_text"])
def test_command_failures_are_sanitized_and_not_healthy(scanner_id, failure):
    def run(argv, **kwargs):
        if failure == "permission":
            raise PermissionError("sensitive-canary")
        if failure == "timeout":
            raise TimeoutExpired(argv, 15, output="sensitive-canary")
        return CompletedProcess(argv, 1 if failure == "exit" else 0,
                                "État ACTIVÉ sensitive-canary", "sensitive-canary")

    result = _scanner(scanner_id, runner=run).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error == "local read failed"
    assert "sensitive-canary" not in json.dumps(_wire(result))


def test_powershell_checks_read_structured_values_and_fail_closed():
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "Get-BitLockerVolume" in argv[-1]:
            return CompletedProcess(argv, 0, json.dumps(_bitlocker()), "")
        return CompletedProcess(argv, 0, '{"EnableSMB1Protocol":true}', "")

    bitlocker = _scanner("windows.bitlocker", runner=run).execute(TARGET, CAPABILITIES)
    smb = _scanner("windows.smb", runner=run).execute(TARGET, CAPABILITIES)
    assert bitlocker.status is ScannerExecutionStatus.SUCCESS
    assert bitlocker.findings == ()
    assert smb.status is ScannerExecutionStatus.SUCCESS
    assert len(smb.findings) == 1
    assert all("Set-" not in argv[-1] for argv in calls)

    malformed = _scanner("windows.smb", runner=lambda argv, **kw: CompletedProcess(argv, 0, "{}", ""))
    failed = malformed.execute(TARGET, CAPABILITIES)
    assert failed.status is ScannerExecutionStatus.FAILED
    assert failed.error == "local read failed"


def test_fixed_collection_scripts_only_invoke_read_and_serialization_operations():
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "Get-NetFirewallProfile" in argv[-1]:
            data = [{"Name": n, "Enabled": "True"} for n in ("Domain", "Private", "Public")]
        else:
            data = _bitlocker() if "Get-BitLockerVolume" in argv[-1] else {"EnableSMB1Protocol": False}
        return CompletedProcess(argv, 0, json.dumps(data), "")

    for scanner_id in ("windows.firewall", "windows.bitlocker", "windows.smb"):
        assert _scanner(scanner_id, runner=run).execute(TARGET, CAPABILITIES).status is ScannerExecutionStatus.SUCCESS
    allowed = {"Get-NetFirewallProfile", "Get-Command", "Get-BitLockerVolume", "Get-SmbServerConfiguration",
               "ConvertTo-Json", "ForEach-Object", "Select-Object"}
    for argv, kwargs in calls:
        assert argv[:4] == ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command")
        assert set(re.findall(r"\b[A-Za-z]+-[A-Za-z]+\b", argv[-1])) <= allowed
        assert ">" not in argv[-1]
        assert kwargs["shell"] is False and kwargs["timeout"] == 15
    bitlocker = next(argv[-1] for argv, _ in calls if "Get-BitLockerVolume" in argv[-1])
    assert "GetPathRoot([Environment]::SystemDirectory)" in bitlocker
    assert "-MountPoint $osVolume" in bitlocker
    assert "C:" not in bitlocker and "KeyProtector" not in bitlocker


def test_four_check_findings_survive_orchestration_and_existing_wire_contract():
    def run(argv, **kwargs):
        if "Get-NetFirewallProfile" in argv[-1]:
            data = [{"Name": n, "Enabled": "False" if n == "Public" else "True"}
                    for n in ("Domain", "Private", "Public")]
        else:
            data = _bitlocker(ProtectionStatus="Off") if "Get-BitLockerVolume" in argv[-1] else {"EnableSMB1Protocol": False}
        return CompletedProcess(argv, 0, json.dumps(data), "")

    values = {"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 2, "PromptOnSecureDesktop": 1}
    scanners = tuple(WindowsReadOnlyScanner(x.manifest, runner=run, registry_reader=values.__getitem__)
                     for x in windows_read_only_scanners())
    result = LocalAssessmentOrchestrator(ScannerRegistry(scanners), lambda target: CAPABILITIES).run(
        TARGET, tuple(x.manifest.scanner_id for x in scanners))
    wire = json.loads(json.dumps(AssessmentResultPayload.from_assessment_result(result).to_dict()))
    assert wire["status"] == "completed"
    assert len(wire["scanner_results"]) == 4
    assert all(x["status"] == "success" for x in wire["scanner_results"])
    assert {x["metadata"]["rule_id"] for x in wire["findings"]} == {
        "firewall.profile", "uac.configuration", "bitlocker.os_volume"}
    assert next(x for x in wire["findings"] if x["metadata"]["rule_id"] == "bitlocker.os_volume")["metadata"]["resource_key"] == "d:"


# Raw strings deliberately retain duplicate properties, including escaped keys.
_RAW_BITLOCKER = ('{"CollectionStatus":"ok","OSVolume":"D:\\\\","MountPoint":"D:",'
                  '"VolumeStatus":"FullyEncrypted","ProtectionStatus":"On","EncryptionPercentage":100}')
_RAW_FIREWALL = ('[{"Name":"Domain","Enabled":"True"},{"Name":"Private","Enabled":"True"},'
                 '{"Name":"Public","Enabled":"True"}]')


@pytest.mark.parametrize("scanner_id,raw", [
    ("windows.bitlocker", _RAW_BITLOCKER.replace('"ProtectionStatus":"On"', replacement))
    for replacement in (
        '"ProtectionStatus":"Off","ProtectionStatus":"On"',
        '"ProtectionStatus":"On","ProtectionStatus":"Off"',
        '"ProtectionStatus":"On","ProtectionStatus":"On"',
        r'"ProtectionStatus":"Off","Protection\u0053tatus":"On"',
    )
] + [
    ("windows.bitlocker", _RAW_BITLOCKER.replace('"EncryptionPercentage":100', replacement))
    for replacement in ('"EncryptionPercentage":0,"EncryptionPercentage":100',
                        '"EncryptionPercentage":100,"EncryptionPercentage":0')
] + [
    ("windows.bitlocker", _RAW_BITLOCKER.replace('"VolumeStatus":"FullyEncrypted"',
        '"VolumeStatus":"FullyDecrypted","VolumeStatus":"FullyEncrypted"')),
    ("windows.bitlocker", _RAW_BITLOCKER.replace('"CollectionStatus":"ok"',
        '"CollectionStatus":"unsupported","CollectionStatus":"ok"')),
    ("windows.bitlocker", _RAW_BITLOCKER[:-1] + ',"extra":{"value":1,"value":2}}'),
    ("windows.bitlocker", _RAW_BITLOCKER[:-1] + ',"extra":{"deeper":{"key":"sensitive-canary","key":0}}}'),
    ("windows.firewall", _RAW_FIREWALL.replace('"Name":"Public","Enabled":"True"',
        '"Name":"Public","Enabled":"False","Enabled":"True"')),
    ("windows.firewall", _RAW_FIREWALL.replace('"Name":"Public","Enabled":"True"',
        '"Name":"Public","Enabled":"True","Enabled":"False"')),
    ("windows.firewall", _RAW_FIREWALL.replace('"Name":"Public"', '"Name":"Private","Name":"Public"')),
    ("windows.firewall", _RAW_FIREWALL.replace('"Name":"Public","Enabled":"True"',
        r'"Name":"Public","Enabled":"False","\u0045nabled":"True"')),
    ("windows.smb", '{"EnableSMB1Protocol":true,"EnableSMB1Protocol":false}'),
])
def test_raw_duplicate_collection_properties_fail_closed_at_any_depth(scanner_id, raw):
    result = _scanner(scanner_id, runner=lambda argv, **kwargs: CompletedProcess(argv, 0, raw, "sensitive-canary")).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "READ_FAILED"
    assert result.execution_evidence.completeness.value == "unknown"
    assert result.execution_evidence.rules_completed == ()
    assert result.findings == ()
    assert "sensitive-canary" not in json.dumps(_wire(result))


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_numeric_constants_fail_closed(constant):
    raw = _RAW_BITLOCKER[:-1] + ',"extra":' + constant + '}'
    result = _scanner("windows.bitlocker", runner=lambda argv, **kwargs: CompletedProcess(argv, 0, raw, "")).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.FAILED
    assert result.error_category == "READ_FAILED"


@pytest.mark.parametrize("scanner_id,raw", [("windows.bitlocker", _RAW_BITLOCKER),
                                         ("windows.firewall", _RAW_FIREWALL),
                                         ("windows.smb", '{"EnableSMB1Protocol":false}')])
def test_raw_unique_collection_properties_remain_supported(scanner_id, raw):
    result = _scanner(scanner_id, runner=lambda argv, **kwargs: CompletedProcess(argv, 0, raw, "")).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert result.findings == ()
    assert result.execution_evidence.completeness.value == "complete"
