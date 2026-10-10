from subprocess import CompletedProcess

from backend.agent.windows_scanners import WindowsReadOnlyScanner, windows_read_only_scanners
from backend.domain.assessment import AssessmentTarget, FindingSeverity
from backend.domain.scanner import ScannerCapability, ScannerExecutionStatus, TargetCapabilities


TARGET = AssessmentTarget("endpoint:1", "workstation", "Windows")
CAPABILITIES = TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read"),
                                             ScannerCapability("windows.registry.read"),
                                             ScannerCapability("windows.powershell")}))


def _scanner(scanner_id, **kwargs):
    manifest = next(x.manifest for x in windows_read_only_scanners() if x.manifest.scanner_id == scanner_id)
    return WindowsReadOnlyScanner(manifest, **kwargs)


def test_firewall_reads_fixed_profiles_without_shell_or_remediation():
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return CompletedProcess(argv, 0, "State OFF" if "public" in argv else "State ON", "")

    result = _scanner("windows.firewall", runner=run).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0].severity is FindingSeverity.CRITICAL
    assert [call[0][3] for call in calls] == ["domain", "private", "public"]
    assert all(call[1]["shell"] is False for call in calls)
    assert all("set" not in call[0] for call in calls)


def test_uac_uses_read_only_registry_values():
    requested = []

    def read(name):
        requested.append(name)
        return {"ConsentPromptBehaviorAdmin": 5, "PromptOnSecureDesktop": 1}[name]

    result = _scanner("windows.uac", registry_reader=read).execute(TARGET, CAPABILITIES)
    assert result.status is ScannerExecutionStatus.SUCCESS
    assert len(result.findings) == 1
    assert requested == ["ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"]


def test_powershell_checks_read_structured_values_and_fail_closed():
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "Get-BitLockerVolume" in argv[-1]:
            return CompletedProcess(argv, 0, '{"VolumeStatus":"FullyEncrypted","EncryptionPercentage":100}', "")
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
