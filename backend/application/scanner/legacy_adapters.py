"""Narrow local runtime adapters around existing legacy scanner methods."""

from dataclasses import replace
from datetime import datetime
import threading
from typing import Any, Callable, Tuple, Union

from scanner import VulnerabilityScanner
import scanner as legacy_scanner_module

from ...application.assessment.normalizer import normalize_legacy_findings
from ...domain.assessment import AssessmentTarget
from ...domain.scanner import (
    ScannerCapability,
    CompatibilityStatus,
    ScannerExecutionResult,
    ScannerExecutionStatus,
    ScannerImplementationStatus,
    ScannerManifest,
    TargetCapabilities,
    ExecutionCompleteness, ResourceEvaluationStatus, ResourceExecutionEvidence, ScannerExecutionEvidence,
)
from .compatibility import evaluate_compatibility


_RUN_PS_LOCK = threading.RLock()


FIREWALL_MANIFEST = ScannerManifest(
    scanner_id="windows.firewall",
    name="Windows Firewall Configuration",
    description="Checks the state of Windows Defender Firewall profiles.",
    category="Firewall",
    version="1.0",
    required_capabilities=frozenset({ScannerCapability("windows.firewall.read")}),
)

UAC_MANIFEST = ScannerManifest(
    scanner_id="windows.uac",
    name="Windows User Account Control",
    description="Checks local UAC registry policy values.",
    category="User Account Control",
    version="1.0",
    required_capabilities=frozenset({ScannerCapability("windows.registry.read")}),
)

BITLOCKER_MANIFEST = ScannerManifest(
    scanner_id="windows.bitlocker",
    name="Windows BitLocker",
    description="Checks the C: volume encryption state through PowerShell.",
    category="Disk Encryption",
    version="1.0",
    required_capabilities=frozenset({ScannerCapability("windows.powershell")}),
)

SMB_MANIFEST = ScannerManifest(
    scanner_id="windows.smb",
    name="Windows SMB Protocol",
    description="Checks whether SMBv1 is enabled through PowerShell.",
    category="Network",
    version="1.0",
    required_capabilities=frozenset({ScannerCapability("windows.powershell")}),
)


class LegacyMethodScannerAdapter:
    """Invoke one existing, read-only legacy check and normalize its output."""

    def __init__(self, manifest: ScannerManifest, method_name: str, scanner_factory: Callable[[], Any] = VulnerabilityScanner):
        self.manifest = manifest
        self._method_name = method_name
        self._scanner_factory = scanner_factory

    def execute(self, target: AssessmentTarget, target_capabilities: TargetCapabilities) -> ScannerExecutionResult:
        started_at = datetime.utcnow()
        compatibility = evaluate_compatibility(self.manifest, target, target_capabilities)
        if compatibility.status is not CompatibilityStatus.COMPATIBLE:
            return ScannerExecutionResult(
                scanner_id=self.manifest.scanner_id,
                status=ScannerExecutionStatus.INCOMPATIBLE,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="; ".join(compatibility.reasons),
                scanner_version=self.manifest.version,
            )
        if self.manifest.status is not ScannerImplementationStatus.AVAILABLE:
            return ScannerExecutionResult(
                scanner_id=self.manifest.scanner_id,
                status=ScannerExecutionStatus.SKIPPED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="scanner implementation is not independently available",
                scanner_version=self.manifest.version,
            )

        try:
            scanner = self._scanner_factory()
            if self.manifest.scanner_id == "windows.uac":
                return self._execute_uac(scanner, started_at)
            if self.manifest.scanner_id in {"windows.smb", "windows.bitlocker"}:
                return self._execute_power_shell(scanner, started_at)
            getattr(scanner, self._method_name)()
            findings, issues = normalize_legacy_findings(getattr(scanner, "vulnerabilities", ()))
            if self.manifest.scanner_id == "windows.firewall":
                evidence = ScannerExecutionEvidence(
                    self.manifest.scanner_id, self.manifest.version,
                    ExecutionCompleteness.PARTIAL if issues else ExecutionCompleteness.COMPLETE,
                    rules_attempted=("firewall.profile",), rules_completed=("firewall.profile",),
                    resource_enumeration_complete=True,
                    resources_discovered=("domain", "private", "public"),
                    resource_results=tuple(ResourceExecutionEvidence(item, ResourceEvaluationStatus.EVALUATED)
                                           for item in ("domain", "private", "public")),
                    normalization_status="partial" if issues else "complete",
                    partial_reason="legacy finding normalization reported issues" if issues else None,
                )
                return self._success(started_at, findings, issues, "firewall.profile", evidence)
            return ScannerExecutionResult(
                scanner_id=self.manifest.scanner_id,
                status=ScannerExecutionStatus.SUCCESS,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                findings=findings,
                native_metrics={
                    "findings_produced": len(findings),
                    "normalization_issue_count": len(issues),
                },
                scanner_version=self.manifest.version,
                execution_evidence=ScannerExecutionEvidence(
                    self.manifest.scanner_id, self.manifest.version, ExecutionCompleteness.UNKNOWN,
                    normalization_status="unknown", partial_reason="legacy adapter does not expose complete execution evidence"),
            )
        except Exception as error:
            return ScannerExecutionResult(
                scanner_id=self.manifest.scanner_id,
                status=ScannerExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error=str(error),
                scanner_version=self.manifest.version,
                error_category="UNKNOWN_ERROR",
            )

    def _execute_uac(self, scanner, started_at):
        if not hasattr(scanner, "_reg_read"):
            getattr(scanner, self._method_name)()
            findings, issues = normalize_legacy_findings(getattr(scanner, "vulnerabilities", ()))
            return self._success(started_at, findings, issues, "uac.configuration", ScannerExecutionEvidence(
                self.manifest.scanner_id, self.manifest.version, ExecutionCompleteness.UNKNOWN,
                normalization_status="unknown", partial_reason="legacy test/runtime object exposes no read boundary"))
        reads = []
        original = scanner._reg_read
        def read(hive, path, key):
            try:
                value = original(hive, path, key)
                reads.append((key, True, value))
                return value
            except Exception:
                reads.append((key, False, None))
                raise
        scanner._reg_read = read
        scanner.check_uac()
        findings, issues = normalize_legacy_findings(getattr(scanner, "vulnerabilities", ()))
        if any(not success for _, success, _ in reads):
            return self._failed(started_at, "REGISTRY_READ_FAILED", "uac.configuration", findings=(),
                                evidence=ScannerExecutionEvidence(self.manifest.scanner_id, self.manifest.version,
                                    ExecutionCompleteness.PARTIAL, rules_attempted=("uac.configuration",),
                                    normalization_status="unknown", partial_reason="one or more UAC policy reads failed"))
        return self._success(started_at, findings, issues, "uac.configuration",
                             ScannerExecutionEvidence(self.manifest.scanner_id, self.manifest.version,
                                 ExecutionCompleteness.COMPLETE, rules_attempted=("uac.configuration",),
                                 rules_completed=("uac.configuration",), normalization_status="partial" if issues else "complete",
                                 partial_reason="legacy finding normalization reported issues" if issues else None))

    def _execute_power_shell(self, scanner, started_at):
        if scanner.__class__.__module__ != legacy_scanner_module.__name__:
            getattr(scanner, self._method_name)()
            findings, issues = normalize_legacy_findings(getattr(scanner, "vulnerabilities", ()))
            rule = "smb.smb1_enabled" if self.manifest.scanner_id == "windows.smb" else "bitlocker.os_volume"
            return self._success(started_at, findings, issues, rule, ScannerExecutionEvidence(
                self.manifest.scanner_id, self.manifest.version, ExecutionCompleteness.UNKNOWN,
                normalization_status="unknown", partial_reason="legacy test/runtime object exposes no execution boundary"))
        calls = []
        original = legacy_scanner_module.run_ps
        def run_ps(*args, **kwargs):
            value = original(*args, **kwargs)
            calls.append(value)
            return value
        with _RUN_PS_LOCK:
            legacy_scanner_module.run_ps = run_ps
            try:
                getattr(scanner, self._method_name)()
            finally:
                legacy_scanner_module.run_ps = original
        findings, issues = normalize_legacy_findings(getattr(scanner, "vulnerabilities", ()))
        rule = "smb.smb1_enabled" if self.manifest.scanner_id == "windows.smb" else "bitlocker.os_volume"
        if not calls or any(value is None for value in calls):
            category = "COMMAND_FAILED"
            evidence = ScannerExecutionEvidence(self.manifest.scanner_id, self.manifest.version,
                ExecutionCompleteness.UNKNOWN, rules_attempted=(rule,), normalization_status="unknown",
                partial_reason="external read returned no structured result")
            return self._failed(started_at, category, rule, findings=(), evidence=evidence)
        if self.manifest.scanner_id == "windows.bitlocker" and any(not isinstance(value, dict) or "VolumeStatus" not in value for value in calls):
            evidence = ScannerExecutionEvidence(self.manifest.scanner_id, self.manifest.version,
                ExecutionCompleteness.PARTIAL, rules_attempted=(rule,), normalization_status="unknown",
                partial_reason="BitLocker output could not be parsed")
            return self._failed(started_at, "OUTPUT_PARSE_FAILED", rule, findings=(), evidence=evidence)
        evidence = ScannerExecutionEvidence(self.manifest.scanner_id, self.manifest.version,
            ExecutionCompleteness.COMPLETE, rules_attempted=(rule,), rules_completed=(rule,),
            resource_enumeration_complete=True if self.manifest.scanner_id == "windows.bitlocker" else None,
            resources_discovered=("c:",) if self.manifest.scanner_id == "windows.bitlocker" else (),
            resource_results=(ResourceExecutionEvidence("c:", ResourceEvaluationStatus.EVALUATED),) if self.manifest.scanner_id == "windows.bitlocker" else (),
            normalization_status="partial" if issues else "complete",
            partial_reason="legacy finding normalization reported issues" if issues else None)
        return self._success(started_at, findings, issues, rule, evidence)

    def _success(self, started_at, findings, issues, rule, evidence):
        findings = _with_identity(findings, self.manifest.scanner_id, rule, "c:" if self.manifest.scanner_id == "windows.bitlocker" else None)
        return ScannerExecutionResult(self.manifest.scanner_id, ScannerExecutionStatus.SUCCESS, started_at, datetime.utcnow(),
            findings=findings, native_metrics={"findings_produced": len(findings), "normalization_issue_count": len(issues)},
            scanner_version=self.manifest.version, execution_evidence=evidence)

    def _failed(self, started_at, category, rule, *, findings=(), evidence=None):
        return ScannerExecutionResult(self.manifest.scanner_id, ScannerExecutionStatus.FAILED, started_at, datetime.utcnow(),
            findings=_with_identity(findings, self.manifest.scanner_id, rule), error=category,
            scanner_version=self.manifest.version, execution_evidence=evidence, error_category=category)


class MetadataOnlyLegacyScannerAdapter:
    """Expose a legacy manifest without pretending its check is independently runnable."""

    def __init__(self, manifest: ScannerManifest):
        self.manifest = manifest

    def execute(self, target: AssessmentTarget, target_capabilities: TargetCapabilities) -> ScannerExecutionResult:
        started_at = datetime.utcnow()
        compatibility = evaluate_compatibility(self.manifest, target, target_capabilities)
        if compatibility.status is not CompatibilityStatus.COMPATIBLE:
            return ScannerExecutionResult(
                scanner_id=self.manifest.scanner_id,
                status=ScannerExecutionStatus.INCOMPATIBLE,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error="; ".join(compatibility.reasons),
                scanner_version=self.manifest.version,
            )
        return ScannerExecutionResult(
            scanner_id=self.manifest.scanner_id,
            status=ScannerExecutionStatus.SKIPPED,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            error="legacy-only scanner is not independently executable yet",
            scanner_version=self.manifest.version,
        )


def legacy_scanner_adapters(
    scanner_factory: Callable[[], Any] = VulnerabilityScanner,
) -> Tuple[Union[LegacyMethodScannerAdapter, MetadataOnlyLegacyScannerAdapter], ...]:
    """Return the small, truthful initial catalog of legacy scanner runtimes."""
    return (
        LegacyMethodScannerAdapter(FIREWALL_MANIFEST, "check_firewall", scanner_factory),
        LegacyMethodScannerAdapter(UAC_MANIFEST, "check_uac", scanner_factory),
        LegacyMethodScannerAdapter(BITLOCKER_MANIFEST, "check_bitlocker_status", scanner_factory),
        LegacyMethodScannerAdapter(SMB_MANIFEST, "check_smb_protocol", scanner_factory),
    )


def _with_identity(findings, scanner_id, rule_id, resource_key=None):
    output = []
    for finding in findings:
        metadata = dict(finding.metadata or {})
        metadata.update({"scanner_id": scanner_id, "rule_id": rule_id})
        if resource_key:
            metadata["resource_key"] = resource_key
        output.append(replace(finding, metadata=metadata))
    return tuple(output)
