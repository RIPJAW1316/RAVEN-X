"""Small, read-only Windows agent checks adapted from personal scanner.py.

The personal GUI and its AI/remediation imports are intentionally absent here.
Every external command is a fixed argument vector; dispatched data is never a
command or script. An unreadable result is FAILED, never a clean assessment.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import subprocess
from typing import Callable

from ..application.scanner.compatibility import evaluate_compatibility
from ..domain.assessment import Evidence, Finding, FindingSeverity
from ..domain.scanner import (
    CompatibilityStatus, ExecutionCompleteness, ResourceEvaluationStatus,
    ResourceExecutionEvidence, ScannerCapability, ScannerExecutionEvidence,
    ScannerExecutionResult, ScannerExecutionStatus, ScannerManifest,
)


_FIREWALL = ScannerManifest(
    "windows.firewall", "Windows Firewall Configuration",
    "Reads the state of all Windows Defender Firewall profiles.", "Firewall", "1.0",
    frozenset({ScannerCapability("windows.firewall.read")}),
)
_UAC = ScannerManifest(
    "windows.uac", "Windows User Account Control",
    "Reads the two local UAC elevation policy values.", "User Account Control", "1.0",
    frozenset({ScannerCapability("windows.registry.read")}),
)
_BITLOCKER = ScannerManifest(
    "windows.bitlocker", "Windows BitLocker",
    "Reads encryption state of the operating system volume.", "Disk Encryption", "1.0",
    frozenset({ScannerCapability("windows.powershell")}),
)
_SMB = ScannerManifest(
    "windows.smb", "Windows SMB Protocol",
    "Reads the SMBv1 server protocol setting.", "Network", "1.0",
    frozenset({ScannerCapability("windows.powershell")}),
)

_SCRIPTS = {
    "windows.bitlocker": (
        "$ErrorActionPreference='Stop'; "
        "$volume=Get-BitLockerVolume -MountPoint C: -ErrorAction Stop; "
        "if ($null -eq $volume) { throw 'volume unavailable' }; "
        "[pscustomobject]@{VolumeStatus=[string]$volume.VolumeStatus; "
        "EncryptionPercentage=[int]$volume.EncryptionPercentage} | ConvertTo-Json -Compress"
    ),
    "windows.smb": (
        "$ErrorActionPreference='Stop'; Get-SmbServerConfiguration -ErrorAction Stop | "
        "Select-Object EnableSMB1Protocol,EnableSMB2Protocol | ConvertTo-Json -Compress"
    ),
}


class WindowsReadOnlyScanner:
    def __init__(self, manifest: ScannerManifest, *, runner: Callable = subprocess.run,
                 registry_reader: Callable | None = None):
        self.manifest = manifest
        self._runner = runner
        self._registry_reader = registry_reader or _read_registry

    def execute(self, target, target_capabilities) -> ScannerExecutionResult:
        started = datetime.now(timezone.utc)
        compatibility = evaluate_compatibility(self.manifest, target, target_capabilities)
        if compatibility.status is not CompatibilityStatus.COMPATIBLE:
            return ScannerExecutionResult(
                self.manifest.scanner_id, ScannerExecutionStatus.INCOMPATIBLE,
                started, datetime.now(timezone.utc),
                error="; ".join(compatibility.reasons),
                scanner_version=self.manifest.version,
            )
        try:
            if self.manifest.scanner_id == "windows.firewall":
                findings, evidence = self._firewall()
            elif self.manifest.scanner_id == "windows.uac":
                findings, evidence = self._uac()
            elif self.manifest.scanner_id == "windows.bitlocker":
                findings, evidence = self._bitlocker()
            elif self.manifest.scanner_id == "windows.smb":
                findings, evidence = self._smb()
            else:
                raise ValueError("scanner is not an allowlisted Windows check")
            return ScannerExecutionResult(
                self.manifest.scanner_id, ScannerExecutionStatus.SUCCESS,
                started, datetime.now(timezone.utc), findings=tuple(findings),
                native_metrics={"findings_produced": len(findings)},
                scanner_version=self.manifest.version, execution_evidence=evidence,
            )
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            # Do not return stderr, registry values, or an arbitrary exception
            # string to the control plane; those can contain local machine data.
            return ScannerExecutionResult(
                self.manifest.scanner_id, ScannerExecutionStatus.FAILED,
                started, datetime.now(timezone.utc), error="local read failed",
                scanner_version=self.manifest.version, error_category="READ_FAILED",
                execution_evidence=_evidence(self.manifest, (), (), ExecutionCompleteness.UNKNOWN,
                                             "local read failed"),
            )

    def _firewall(self):
        profiles = (("domain", "DomainProfile"), ("private", "PrivateProfile"), ("public", "PublicProfile"))
        findings = []
        for profile, label in profiles:
            output = self._command(("netsh", "advfirewall", "show", profile, "state"), 6)
            match = re.search(r"(?im)^\s*state\s+(ON|OFF)\s*$", output)
            if match is None:
                raise ValueError("firewall profile state was not readable")
            if match.group(1).upper() == "OFF":
                findings.append(_finding(
                    self.manifest.scanner_id, "firewall.profile", profile,
                    FindingSeverity.CRITICAL if profile == "public" else FindingSeverity.HIGH,
                    "Firewall", f"Windows Firewall Disabled – {label}",
                    f"Firewall is off for the {profile} profile.", "Windows Defender Firewall",
                    "netsh", "OFF", "ON",
                ))
        evidence = _evidence(self.manifest, ("firewall.profile",), ("firewall.profile",),
                             ExecutionCompleteness.COMPLETE, resources=tuple(p for p, _ in profiles))
        return findings, evidence

    def _uac(self):
        consent = self._registry_reader("ConsentPromptBehaviorAdmin")
        desktop = self._registry_reader("PromptOnSecureDesktop")
        if not isinstance(consent, int) or not isinstance(desktop, int):
            raise ValueError("UAC values must be integers")
        findings = []
        if consent != 2 or desktop != 1:
            findings.append(_finding(
                self.manifest.scanner_id, "uac.configuration", "local",
                FindingSeverity.HIGH, "User Account Control", "UAC Not at Maximum Security",
                f"ConsentPromptBehaviorAdmin={consent}, PromptOnSecureDesktop={desktop}.",
                "UAC", "Windows registry", f"{consent},{desktop}", "2,1",
            ))
        return findings, _evidence(self.manifest, ("uac.configuration",), ("uac.configuration",),
                                   ExecutionCompleteness.COMPLETE)

    def _bitlocker(self):
        data = self._powershell_json("windows.bitlocker")
        if not isinstance(data, dict) or "VolumeStatus" not in data:
            raise ValueError("BitLocker response was not structured")
        status = data["VolumeStatus"]
        if not isinstance(status, str) or not status:
            raise ValueError("BitLocker volume status was absent")
        findings = []
        if status != "FullyEncrypted":
            percent = data.get("EncryptionPercentage")
            if not isinstance(percent, (int, float)) or isinstance(percent, bool) or not 0 <= percent <= 100:
                raise ValueError("BitLocker encryption percentage was invalid")
            findings.append(_finding(
                self.manifest.scanner_id, "bitlocker.os_volume", "c:",
                FindingSeverity.HIGH, "Disk Encryption", "BitLocker Not Fully Enabled",
                f"C: drive is {percent}% encrypted (status {status}).",
                "BitLocker", "Get-BitLockerVolume", status, "FullyEncrypted",
            ))
        evidence = _evidence(self.manifest, ("bitlocker.os_volume",), ("bitlocker.os_volume",),
                             ExecutionCompleteness.COMPLETE, resources=("c:",))
        return findings, evidence

    def _smb(self):
        data = self._powershell_json("windows.smb")
        if not isinstance(data, dict) or not isinstance(data.get("EnableSMB1Protocol"), bool):
            raise ValueError("SMB response was not structured")
        findings = []
        if data["EnableSMB1Protocol"]:
            findings.append(_finding(
                self.manifest.scanner_id, "smb.smb1_enabled", "local",
                FindingSeverity.CRITICAL, "Network", "SMBv1 Protocol Enabled",
                "SMBv1 server protocol is enabled.", "SMB Protocol",
                "Get-SmbServerConfiguration", "enabled", "disabled",
            ))
        return findings, _evidence(self.manifest, ("smb.smb1_enabled",), ("smb.smb1_enabled",),
                                   ExecutionCompleteness.COMPLETE)

    def _powershell_json(self, scanner_id):
        output = self._command(("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                _SCRIPTS[scanner_id]), 15)
        return json.loads(output)

    def _command(self, argv, timeout):
        result = self._runner(argv, capture_output=True, text=True, timeout=timeout, shell=False)
        if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 16384:
            raise ValueError("read command failed")
        return result.stdout


def _read_registry(value_name: str) -> int:
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
        value, _ = winreg.QueryValueEx(key, value_name)
    return value


def _finding(scanner_id, rule, resource, severity, category, title, details, component,
             source, observed, expected):
    finding_id = hashlib.sha256(f"{scanner_id}|{rule}|{resource}".encode("utf-8")).hexdigest()
    return Finding(
        finding_id, severity, category, title, details, component,
        evidence=(Evidence(source, details, str(observed), str(expected)),),
        metadata={"scanner_id": scanner_id, "rule_id": rule, "resource_key": resource},
    )


def _evidence(manifest, attempted, completed, completeness, partial_reason=None, resources=()):
    return ScannerExecutionEvidence(
        manifest.scanner_id, manifest.version, completeness,
        rules_attempted=tuple(attempted), rules_completed=tuple(completed),
        resource_enumeration_complete=True if resources else None,
        resources_discovered=tuple(resources),
        resource_results=tuple(ResourceExecutionEvidence(r, ResourceEvaluationStatus.EVALUATED)
                               for r in resources),
        normalization_status="complete" if completeness is ExecutionCompleteness.COMPLETE else "unknown",
        partial_reason=partial_reason,
    )


def windows_read_only_scanners():
    return tuple(WindowsReadOnlyScanner(manifest) for manifest in (_FIREWALL, _UAC, _BITLOCKER, _SMB))
