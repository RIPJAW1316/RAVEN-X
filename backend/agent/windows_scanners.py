"""Small, read-only Windows agent checks adapted from personal scanner.py.

The personal GUI and its AI/remediation imports are intentionally absent here.
Every external command is a fixed argument vector; dispatched data is never a
command or script. Unreadable results are FAILED; unavailable BitLocker tooling
is INCOMPATIBLE. Neither condition is a clean assessment.
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
    frozenset({ScannerCapability("windows.firewall.read"), ScannerCapability("windows.powershell")}),
)
_UAC = ScannerManifest(
    "windows.uac", "Windows User Account Control",
    "Reads UAC enablement and local elevation prompt policies.", "User Account Control", "1.0",
    frozenset({ScannerCapability("windows.registry.read")}),
)
_BITLOCKER = ScannerManifest(
    "windows.bitlocker", "Windows BitLocker",
    "Reads encryption and protection state of the operating system volume.", "Disk Encryption", "1.0",
    frozenset({ScannerCapability("windows.powershell")}),
)
_SMB = ScannerManifest(
    "windows.smb", "Windows SMB Protocol",
    "Reads the SMBv1 server protocol setting.", "Network", "1.0",
    frozenset({ScannerCapability("windows.powershell")}),
)

_SCRIPTS = {
    "windows.firewall": (
        "$ErrorActionPreference='Stop'; "
        "@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | "
        "ForEach-Object { [pscustomobject]@{Name=[string]$_.Name; Enabled=[string]$_.Enabled} }) | "
        "ConvertTo-Json -Compress"
    ),
    "windows.bitlocker": (
        "$ErrorActionPreference='Stop'; "
        "if ($null -eq (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { "
        "[pscustomobject]@{CollectionStatus='unsupported'} | ConvertTo-Json -Compress "
        "} else { "
        "$osVolume=[IO.Path]::GetPathRoot([Environment]::SystemDirectory); "
        "if (-not $osVolume) { throw 'OS volume unavailable' }; "
        "$volumes=@(Get-BitLockerVolume -MountPoint $osVolume -ErrorAction Stop); "
        "if ($volumes.Count -ne 1) { throw 'volume unavailable' }; $volume=$volumes[0]; "
        "[pscustomobject]@{CollectionStatus='ok'; OSVolume=$osVolume; "
        "MountPoint=[string]$volume.MountPoint; VolumeStatus=[string]$volume.VolumeStatus; "
        "ProtectionStatus=[string]$volume.ProtectionStatus; "
        "EncryptionPercentage=$volume.EncryptionPercentage} | ConvertTo-Json -Compress }"
    ),
    "windows.smb": (
        "$ErrorActionPreference='Stop'; Get-SmbServerConfiguration -ErrorAction Stop | "
        "Select-Object EnableSMB1Protocol,EnableSMB2Protocol | ConvertTo-Json -Compress"
    ),
}


# A successful collection is not a healthy posture. Only the complete encrypted,
# actively protected state satisfies this policy; all other known states produce
# findings. Unknown values fail collection instead of being treated as healthy.
_BITLOCKER_STATES = {
    "FullyEncrypted": ("fully_encrypted", "BitLocker Protection Suspended or Off"),
    "FullyDecrypted": ("unencrypted", "BitLocker Not Enabled"),
    "EncryptionInProgress": ("encryption_in_progress", "BitLocker Encryption In Progress"),
    "DecryptionInProgress": ("decryption_in_progress", "BitLocker Decryption In Progress"),
    "EncryptionPaused": ("encryption_paused", "BitLocker Encryption Paused"),
    "DecryptionPaused": ("decryption_paused", "BitLocker Decryption Paused"),
}


class _UnsupportedCollection(ValueError):
    pass


def _unique_collection_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate collection property")
        result[key] = value
    return result


def _invalid_json_constant(_value):
    raise ValueError("invalid collection number")


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
            complete = evidence.completeness is ExecutionCompleteness.COMPLETE
            return ScannerExecutionResult(
                self.manifest.scanner_id, ScannerExecutionStatus.SUCCESS if complete else ScannerExecutionStatus.FAILED,
                started, datetime.now(timezone.utc), findings=tuple(findings),
                native_metrics={"findings_produced": len(findings)},
                scanner_version=self.manifest.version, execution_evidence=evidence,
                error=None if complete else "local read incomplete",
                error_category=None if complete else "READ_FAILED",
            )
        except _UnsupportedCollection:
            return ScannerExecutionResult(
                self.manifest.scanner_id, ScannerExecutionStatus.INCOMPATIBLE,
                started, datetime.now(timezone.utc), error="BitLocker collection unavailable",
                scanner_version=self.manifest.version, error_category="UNSUPPORTED",
                execution_evidence=_evidence(self.manifest, (), (), ExecutionCompleteness.UNKNOWN,
                                             "BitLocker collection unavailable"),
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
        data = self._powershell_json("windows.firewall")
        if not isinstance(data, list) or len(data) != 3:
            raise ValueError("firewall profiles were not readable")
        states = {}
        for item in data:
            if not isinstance(item, dict) or item.get("Name") not in {"Domain", "Private", "Public"}:
                raise ValueError("firewall profile was invalid")
            name, enabled = item["Name"].lower(), item.get("Enabled")
            if enabled not in ("True", "False") or name in states:
                raise ValueError("firewall state was invalid")
            states[name] = enabled == "True"
        profiles = (("domain", "DomainProfile"), ("private", "PrivateProfile"), ("public", "PublicProfile"))
        findings = []
        for profile, label in profiles:
            if not states[profile]:
                findings.append(_finding(
                    self.manifest.scanner_id, "firewall.profile", profile,
                    FindingSeverity.CRITICAL if profile == "public" else FindingSeverity.HIGH,
                    "Firewall", f"Windows Firewall Disabled – {label}",
                    f"Firewall is off for the {profile} profile.", "Windows Defender Firewall",
                    "Get-NetFirewallProfile", "OFF", "ON",
                ))
        evidence = _evidence(self.manifest, ("firewall.profile",), ("firewall.profile",),
                             ExecutionCompleteness.COMPLETE, resources=tuple(p for p, _ in profiles))
        return findings, evidence

    def _uac(self):
        values = {}
        for name, valid in (("EnableLUA", range(2)), ("ConsentPromptBehaviorAdmin", range(6)),
                            ("PromptOnSecureDesktop", range(2))):
            try:
                value = self._registry_reader(name)
                if type(value) is int and value in valid:
                    values[name] = value
            except (OSError, KeyError, ValueError, TypeError, ImportError):
                pass  # Missing observations produce incomplete evidence, never a clean result.
        enabled = values.get("EnableLUA")
        consent, desktop = values.get("ConsentPromptBehaviorAdmin"), values.get("PromptOnSecureDesktop")
        findings = []
        if enabled == 0 or (consent is not None and desktop is not None and (consent != 2 or desktop != 1)):
            observed = ", ".join(f"{name}={values.get(name, 'unavailable')}" for name in
                                 ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"))
            findings.append(_finding(
                self.manifest.scanner_id, "uac.configuration", "local",
                FindingSeverity.HIGH, "User Account Control",
                "UAC Disabled" if enabled == 0 else "UAC Not at Maximum Security",
                observed + ".", "UAC", "Windows registry", observed,
                "EnableLUA=1, ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1",
            ))
        if len(values) != 3:
            return findings, _evidence(self.manifest, ("uac.configuration",), (),
                                       ExecutionCompleteness.PARTIAL if values else ExecutionCompleteness.UNKNOWN,
                                       "UAC policy read incomplete")
        return findings, _evidence(self.manifest, ("uac.configuration",), ("uac.configuration",),
                                   ExecutionCompleteness.COMPLETE)

    def _bitlocker(self):
        data = self._powershell_json("windows.bitlocker")
        if not isinstance(data, dict):
            raise ValueError("BitLocker response was not structured")
        if data.get("CollectionStatus") == "unsupported":
            raise _UnsupportedCollection()
        if data.get("CollectionStatus") != "ok":
            raise ValueError("BitLocker collection was incomplete")
        mount, os_volume = data.get("MountPoint"), data.get("OSVolume")
        if any(not isinstance(x, str) or re.fullmatch(r"[A-Za-z]:\\?", x) is None for x in (mount, os_volume)):
            raise ValueError("BitLocker OS volume was invalid")
        resource = mount.rstrip("\\").lower()
        if resource != os_volume.rstrip("\\").lower():
            raise ValueError("BitLocker response did not identify the OS volume")
        status, protection, percent = data.get("VolumeStatus"), data.get("ProtectionStatus"), data.get("EncryptionPercentage")
        if (not isinstance(status, str) or status not in _BITLOCKER_STATES or protection not in ("On", "Off")
                or type(percent) is not int or not 0 <= percent <= 100
                or (status == "FullyEncrypted" and percent != 100)
                or (status == "FullyDecrypted" and (percent != 0 or protection != "Off"))):
            raise ValueError("BitLocker state was not readable")
        state_code, title = _BITLOCKER_STATES[status]
        findings = []
        if status != "FullyEncrypted" or protection != "On":
            findings.append(_finding(
                self.manifest.scanner_id, "bitlocker.os_volume", resource,
                FindingSeverity.HIGH, "Disk Encryption", title,
                f"{resource.upper()} is {percent}% encrypted; VolumeStatus={status}, ProtectionStatus={protection}.",
                "BitLocker", "Get-BitLockerVolume", f"{status}; ProtectionStatus={protection}; EncryptionPercentage={percent}",
                "FullyEncrypted; ProtectionStatus=On; EncryptionPercentage=100",
            ))
        evidence = _evidence(self.manifest, ("bitlocker.os_volume",), ("bitlocker.os_volume",),
                             ExecutionCompleteness.COMPLETE, resources=(resource,),
                             resource_reason=f"{state_code}_protection_{protection.lower()}")
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
        return json.loads(output, object_pairs_hook=_unique_collection_object,
                          parse_constant=_invalid_json_constant)

    def _command(self, argv, timeout):
        result = self._runner(argv, capture_output=True, text=True, timeout=timeout, shell=False)
        if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 16384:
            raise ValueError("read command failed")
        return result.stdout


def _read_registry(value_name: str) -> int:
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
        value, kind = winreg.QueryValueEx(key, value_name)
    if kind != winreg.REG_DWORD:
        raise ValueError("UAC policy has an unexpected registry type")
    return value


def _finding(scanner_id, rule, resource, severity, category, title, details, component,
             source, observed, expected):
    finding_id = hashlib.sha256(f"{scanner_id}|{rule}|{resource}".encode("utf-8")).hexdigest()
    return Finding(
        finding_id, severity, category, title, details, component,
        evidence=(Evidence(source, details, str(observed), str(expected)),),
        metadata={"scanner_id": scanner_id, "rule_id": rule, "resource_key": resource},
    )


def _evidence(manifest, attempted, completed, completeness, partial_reason=None, resources=(), resource_reason=""):
    return ScannerExecutionEvidence(
        manifest.scanner_id, manifest.version, completeness,
        rules_attempted=tuple(attempted), rules_completed=tuple(completed),
        resource_enumeration_complete=True if resources else None,
        resources_discovered=tuple(resources),
        resource_results=tuple(ResourceExecutionEvidence(r, ResourceEvaluationStatus.EVALUATED, resource_reason)
                               for r in resources),
        normalization_status="complete" if completeness is ExecutionCompleteness.COMPLETE else "unknown",
        partial_reason=partial_reason,
    )


def windows_read_only_scanners():
    return tuple(WindowsReadOnlyScanner(manifest) for manifest in (_FIREWALL, _UAC, _BITLOCKER, _SMB))
