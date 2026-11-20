"""Server-owned synthetic Windows demo assessment fixture.

Single versioned fixture 'windows-hardening-v1' providing canonical synthetic
evidence for the 24-check Windows security baseline. Used by local LM Studio,
offline rules, and Google Cloud Gemini 3.5 Flash-Lite so operators can compare
interpretations across all three providers on identical evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...agent.windows_scanners import windows_read_only_scanners


WINDOWS_HARDENING_DEMO_ID = "windows-hardening-v1"

# Canonical fixed items passed to Google Cloud Gemini.
# The Gemini provider accepts NO user-supplied facts or report text;
# it references only these immutable constants.
CANONICAL_DEMO_REFS = ("f1", "f2", "f3", "f4", "f5")

CANONICAL_DEMO_GEMINI_ITEMS = (
    {
        "ref": "f1",
        "severity": "critical",
        "description": "Public firewall profile is disabled.",
    },
    {
        "ref": "f2",
        "severity": "high",
        "description": "OS volume (C:) is encrypted but protection is off.",
    },
    {
        "ref": "f3",
        "severity": "high",
        "description": "UAC elevation prompts disabled on secure desktop.",
    },
    {
        "ref": "f4",
        "severity": "critical",
        "description": "Legacy SMBv1 server protocol enabled.",
    },
    {
        "ref": "f5",
        "severity": "medium",
        "description": "AutoRun is enabled for removable drives.",
    },
)

DEMO_REF_TO_FINDING_ID = {
    "f1": "demo-fw-1",
    "f2": "demo-bl-1",
    "f3": "demo-uac-1",
    "f4": "demo-smb-1",
    "f5": "demo-autorun-1",
}
DEMO_FINDING_ID_TO_REF = {v: k for k, v in DEMO_REF_TO_FINDING_ID.items()}


def build_synthetic_windows_demo_report() -> dict[str, Any]:
    """Construct complete synthetic fleet report for 'windows-hardening-v1'."""
    all_scanners = [s.manifest.scanner_id for s in windows_read_only_scanners()]

    findings = [
        {
            "finding_id": "demo-fw-1",
            "occurrence_id": "demo:fw-1",
            "severity": "critical",
            "title": "Windows Firewall Disabled – PublicProfile",
            "description": "Firewall is off for the public profile.",
            "scanner_id": "windows.firewall",
            "rule_id": "firewall.profile",
            "metadata": {"scanner_id": "windows.firewall", "rule_id": "firewall.profile"},
            "evidence": [{"source": "Get-NetFirewallProfile", "observed_value": "OFF", "expected_value": "ON"}],
        },
        {
            "finding_id": "demo-bl-1",
            "occurrence_id": "demo:bl-1",
            "severity": "high",
            "title": "BitLocker Protection Suspended or Off",
            "description": "C: is 100% encrypted; VolumeStatus=FullyEncrypted, ProtectionStatus=Off.",
            "scanner_id": "windows.bitlocker",
            "rule_id": "bitlocker.os_volume",
            "resource_key": "C:",
            "metadata": {"scanner_id": "windows.bitlocker", "rule_id": "bitlocker.os_volume", "resource_key": "C:"},
            "evidence": [{"source": "Get-BitLockerVolume", "observed_value": "FullyEncrypted; ProtectionStatus=Off; EncryptionPercentage=100"}],
        },
        {
            "finding_id": "demo-uac-1",
            "occurrence_id": "demo:uac-1",
            "severity": "high",
            "title": "UAC Elevation Security Reduced",
            "description": "PromptOnSecureDesktop=0, ConsentPromptBehaviorAdmin=0",
            "scanner_id": "windows.uac",
            "rule_id": "uac.configuration",
            "metadata": {"scanner_id": "windows.uac", "rule_id": "uac.configuration"},
            "evidence": [{"source": "Registry", "observed_value": "PromptOnSecureDesktop=0"}],
        },
        {
            "finding_id": "demo-smb-1",
            "occurrence_id": "demo:smb-1",
            "severity": "critical",
            "title": "SMBv1 Protocol Enabled",
            "description": "Legacy SMBv1 server protocol enabled.",
            "scanner_id": "windows.smb",
            "rule_id": "smb.smb1_enabled",
            "metadata": {"scanner_id": "windows.smb", "rule_id": "smb.smb1_enabled"},
            "evidence": [{"source": "Get-SmbServerConfiguration", "observed_value": "EnableSMB1Protocol=True"}],
        },
        {
            "finding_id": "demo-autorun-1",
            "occurrence_id": "demo:autorun-1",
            "severity": "medium",
            "title": "Machine AutoRun Restriction Not Enforced",
            "description": "The machine policy does not disable AutoRun for every drive type.",
            "scanner_id": "windows.autorun",
            "rule_id": "autorun.not_enforced",
            "metadata": {"scanner_id": "windows.autorun", "rule_id": "autorun.not_enforced"},
            "evidence": [{"source": "Registry", "observed_value": "NoDriveTypeAutoRun=145"}],
        },
    ]

    scanner_results = []
    for sid in all_scanners:
        if sid == "windows.firewall":
            scanner_results.append({
                "scanner_id": sid, "status": "success", "findings": ["demo-fw-1"],
                "execution_evidence": {"completeness": "complete"},
            })
        elif sid == "windows.bitlocker":
            scanner_results.append({
                "scanner_id": sid, "status": "success", "findings": ["demo-bl-1"],
                "execution_evidence": {"completeness": "complete"},
            })
        elif sid == "windows.uac":
            scanner_results.append({
                "scanner_id": sid, "status": "success", "findings": ["demo-uac-1"],
                "execution_evidence": {"completeness": "complete"},
            })
        elif sid == "windows.smb":
            scanner_results.append({
                "scanner_id": sid, "status": "success", "findings": ["demo-smb-1"],
                "execution_evidence": {"completeness": "complete"},
            })
        elif sid == "windows.autorun":
            scanner_results.append({
                "scanner_id": sid, "status": "success", "findings": ["demo-autorun-1"],
                "execution_evidence": {"completeness": "complete"},
            })
        elif sid == "windows.wifi":
            scanner_results.append({
                "scanner_id": sid, "status": "failed", "error_category": "READ_FAILED",
                "has_error": True, "findings": [],
            })
        else:
            scanner_results.append({
                "scanner_id": sid, "status": "success", "findings": [],
                "execution_evidence": {"completeness": "complete"},
            })

    endpoint = {
        "endpoint_id": "demo-win11-pc",
        "hostname": "DEMO-WIN11-PC",
        "scan_status": "scanned",
        "findings_omitted": 0,
        "latest_assessment": {
            "assessment_id": "demo-windows-assessment",
            "scanner_ids": tuple(all_scanners),
            "status": "completed",
            "completed_at": datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
        },
        "scanner_results": scanner_results,
        "findings": findings,
    }

    return {
        "organization_id": "bundled-demo-organization",
        "generated_at": datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
        "summary": {
            "total_enrolled": 1,
            "approved": 1,
            "scanned": 1,
            "partial": 0,
            "not_scanned": 0,
            "failed": 0,
            "pending_approval": 0,
        },
        "endpoints": [endpoint],
    }


def get_demo_source_descriptor(demo_id: str) -> dict[str, Any]:
    """Build source descriptor for bundled synthetic demo without fabricated assessment links."""
    return {
        "kind": "bundled_demo",
        "demo_id": demo_id,
        "organization_id": "bundled-demo-organization",
        "assessment_ids": [],
        "endpoint_ids": [],
        "report_generated_at": datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
    }
