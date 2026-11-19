"""Server-owned deterministic fix plan and 24-check rule ground truth.

All 24 checks from windows_read_only_scanners() are accounted for.
Plain-language fix actions are rendered by the server. If inference is
disabled, fails, times out, or hallucinates, this deterministic engine
generates the complete plan labeled 'Offline rules'.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from ...agent.windows_scanners import windows_read_only_scanners


_SEVERITY_RANKS: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

# Rule-level remediation mappings for known checks
_RULE_ACTIONS: dict[str, tuple[str, str]] = {
    "firewall.profile": (
        "Enable Windows Defender Firewall for all network profiles (Domain, Private, Public).",
        "Inbound connections are uninspected when firewall profiles are disabled.",
    ),
    "uac.configuration": (
        "Configure User Account Control (UAC) to maximum elevation security (EnableLUA=1, ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1).",
        "Permissive UAC policies allow administrative tasks to elevate without interactive secure prompts.",
    ),
    "smb.smb1_enabled": (
        "Disable legacy SMBv1 server protocol using Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force.",
        "SMBv1 contains critical vulnerabilities and lacks modern encryption and message signing.",
    ),
    "updates.disabled": (
        "Enable and start the Windows Update service (wuauserv) to allow security patching.",
        "A disabled update service prevents the installation of essential security updates.",
    ),
    "defender.antivirus_off": (
        "Enable the Microsoft Defender Antivirus engine.",
        "The endpoint lacks an active antivirus engine to detect and quarantine malware.",
    ),
    "defender.realtime_off": (
        "Enable Microsoft Defender Real-Time Protection.",
        "Files and processes are not scanned as they are accessed or launched.",
    ),
    "defender.path_exclusions": (
        "Review configured Microsoft Defender path exclusions and remove unapproved directory paths.",
        "Overly permissive path exclusions allow malware in excluded locations to run undetected.",
    ),
    "defender.extension_exclusions": (
        "Review configured Microsoft Defender file extension exclusions and remove unapproved extensions.",
        "Excluded file extensions bypass inspection by the antivirus engine.",
    ),
    "defender.process_exclusions": (
        "Review configured Microsoft Defender process exclusions and remove unapproved processes.",
        "Excluded processes can execute arbitrary payload code without real-time analysis.",
    ),
    "autologon.enabled": (
        "Disable automatic interactive Windows logon (AutoAdminLogon = 0).",
        "Automatic logon exposes the interactive session upon reboot without user authentication.",
    ),
    "rdp.enabled": (
        "Confirm Remote Desktop is required; if required, restrict network exposure via firewall policy.",
        "Exposed Remote Desktop connections increase the attack surface for credential stuffing.",
    ),
    "rdp.nla_off": (
        "Enable Network Level Authentication (NLA) for Remote Desktop connections.",
        "RDP without NLA allows unauthorized users to reach the Windows logon screen without prior network authentication.",
    ),
    "guest.enabled": (
        "Disable the built-in Windows Guest account.",
        "An active Guest account provides unauthenticated interactive access to the local workstation.",
    ),
    "password.not_required": (
        "Require passwords for all active local Windows user accounts.",
        "Accounts configured without password requirements can be logged into without credentials.",
    ),
    "port.21": (
        "Disable FTP service on TCP port 21 and use secure file transfer protocols (SFTP/HTTPS).",
        "FTP transmits credentials and file contents across the network in cleartext.",
    ),
    "port.23": (
        "Disable Telnet listener on TCP port 23 and replace with SSH or PowerShell Remoting.",
        "Telnet sends all session traffic and administrative credentials in unencrypted cleartext.",
    ),
    "port.110": (
        "Disable unencrypted POP3 listener on TCP port 110 and migrate to encrypted mail protocols.",
        "Cleartext POP3 exposes email communications and credentials to network sniffing.",
    ),
    "port.3389": (
        "Restrict listening RDP port 3389 to authorized administrative subnets or disable Remote Desktop.",
        "Unrestricted port 3389 exposure allows brute-force attacks from unauthorized hosts.",
    ),
    "port.5900": (
        "Stop and disable VNC service on TCP port 5900 or restrict it to authenticated encrypted tunnels.",
        "VNC listeners often lack strong multi-factor authentication and encryption.",
    ),
    "sharing.nondefault": (
        "Review non-default SMB network shares and remove unneeded shares or tighten share permissions.",
        "Non-default network shares expose local filesystem folders to network peers.",
    ),
    "powershell.permissive": (
        "Set machine-wide PowerShell execution policy to RemoteSigned or Restricted.",
        "Permissive execution policies (Bypass/Unrestricted) allow untrusted scripts to run without prompt.",
    ),
    "autorun.not_enforced": (
        "Enforce machine policy disabling AutoRun on all drive types (NoDriveTypeAutoRun = 255).",
        "Unrestricted AutoRun allows removable media and network shares to execute commands automatically.",
    ),
    "services.remote_registry": (
        "Stop and disable the Windows Remote Registry service.",
        "Remote Registry service allows network users to modify registry keys if permissions allow.",
    ),
    "time.disabled": (
        "Enable and start the Windows Time service (W32Time).",
        "Clock synchronization is required for Kerberos authentication and reliable security audit logs.",
    ),
    "telnet.enabled": (
        "Uninstall the optional legacy Telnet Client Windows feature.",
        "The legacy Telnet Client feature is obsolete and insecure.",
    ),
    "dns.none": (
        "Configure valid DNS server addresses on all active network interfaces.",
        "Absence of configured DNS servers disrupts domain name resolution and endpoint updates.",
    ),
    "integrity.signature_invalid": (
        "Investigate invalid Authenticode signature on core system binaries using SFC /scannow or DISM.",
        "Invalid Authenticode signatures indicate damaged, unverified, or altered operating system binaries.",
    ),
    "integrity.signer_unexpected": (
        "Investigate unexpected signer on core Windows system binaries.",
        "Core System32 operating system files must be digitally signed by Microsoft.",
    ),
    "admin.builtin_enabled": (
        "Disable the built-in Administrator account and use named administrative credentials.",
        "The well-known SID -500 Administrator account is a standard target for automated credential attacks.",
    ),
    "startup.script_entry": (
        "Review script-based Run startup entries in the registry and remove unauthorized entries.",
        "Script-based startup entries are a common persistence technique for unapproved software.",
    ),
    "wifi.weak_cipher": (
        "Reconfigure Wi-Fi connection to modern WPA2-AES (CCMP) or WPA3 encryption.",
        "WEP and TKIP encryption ciphers are cryptographically obsolete and vulnerable to packet decryption.",
    ),
    "wifi.open_network": (
        "Disconnect from unencrypted open Wi-Fi network and connect to an authenticated corporate network.",
        "Open Wi-Fi networks transmit all wireless traffic without layer-2 encryption.",
    ),
    "audit.logon_incomplete": (
        "Configure Logon auditing to record both Success and Failure events (auditpol /set /subcategory:Logon /success:enable /failure:enable).",
        "Incomplete logon auditing blinds administrators to failed brute-force attacks and unauthorized sessions.",
    ),
}


def _scanner_registry_catalogue() -> dict[str, dict[str, str]]:
    """Query the source-of-truth scanner registry once."""
    catalogue = {}
    for scanner in windows_read_only_scanners():
        m = scanner.manifest
        catalogue[m.scanner_id] = {
            "scanner_id": m.scanner_id,
            "name": m.name,
            "category": m.category,
            "description": m.description,
        }
    return catalogue


def _bitlocker_remediation(
    resource_key: str | None,
    title: str,
    details: str,
    evidence: Sequence[Mapping[str, Any]],
) -> tuple[str, str]:
    # Determine drive letter
    drive = None
    if resource_key and isinstance(resource_key, str):
        cleaned = resource_key.strip().rstrip("\\").upper()
        if re.match(r"^[A-Z]:$", cleaned):
            drive = cleaned
    if not drive:
        match = re.search(r"\b([A-Za-z]:)", details)
        if match:
            drive = match.group(1).upper()
        else:
            for ev in evidence:
                obs = str(ev.get("observed_value") or "")
                m = re.search(r"\b([A-Za-z]:)", obs)
                if m:
                    drive = m.group(1).upper()
                    break

    if drive == "C:":
        drive_label = "The OS volume (C:)"
    elif drive:
        drive_label = f"The {drive} volume"
    else:
        drive_label = "The OS volume"

    # Gather evidence text
    evidence_text = " ".join(
        f"{ev.get('source', '')} {ev.get('description', '')} {ev.get('observed_value', '')}"
        for ev in evidence if isinstance(ev, Mapping)
    )
    combined = f"{title} {details} {evidence_text}"

    # 1. FullyDecrypted / Not Enabled / DecryptionInProgress / unencrypted
    # Check explicitly for decrypted/unencrypted state FIRST so ProtectionStatus=Off does not misclassify it as encrypted
    is_decrypted = bool(
        re.search(r"\bVolumeStatus\s*=\s*FullyDecrypted\b", combined, re.I)
        or re.search(r"\bFullyDecrypted\b", combined, re.I)
        or re.search(r"\bBitLocker Not Enabled\b", combined, re.I)
        or re.search(r"\bunencrypted\b", combined, re.I)
        or re.search(r"\b0% encrypted\b", combined, re.I)
    )
    if is_decrypted:
        return (
            f"Enable BitLocker drive encryption on {drive_label}.",
            f"Data at rest on {drive_label} is unencrypted and unprotected against physical disk extraction.",
        )

    # 2. FullyEncrypted but Protection is Off / Suspended
    is_fully_encrypted = bool(
        re.search(r"\bVolumeStatus\s*=\s*FullyEncrypted\b", combined, re.I)
        or re.search(r"\bFullyEncrypted\b", combined, re.I)
        or re.search(r"\b100% encrypted\b", combined, re.I)
        or re.search(r"\bProtection Suspended or Off\b", combined, re.I)
    )
    is_protection_off = bool(
        re.search(r"\bProtectionStatus\s*=\s*Off\b", combined, re.I)
        or re.search(r"\bprotection\s+is\s+off\b", combined, re.I)
        or re.search(r"\bprotection\s+suspended\b", combined, re.I)
    )
    if is_fully_encrypted and is_protection_off:
        return (
            f"{drive_label} is encrypted but protection is off. Investigate why protection is suspended or disabled before reviewing whether to resume BitLocker protection.",
            "Volume data is at risk when protection is suspended because decryption keys are stored unsealed in volume metadata.",
        )

    # 3. Encryption or decryption in progress / paused
    if re.search(r"\b(EncryptionInProgress|DecryptionInProgress|EncryptionPaused|DecryptionPaused)\b", combined, re.I):
        return (
            f"Monitor {drive_label} until BitLocker operation completes and verify active protection is enabled.",
            f"{drive_label} is in an intermediate encryption transition state.",
        )

    # 4. Fallback for other BitLocker states
    return (
        f"Investigate {drive_label} BitLocker protection state and review resuming full protection.",
        f"{drive_label} is not in an actively protected, fully encrypted state.",
    )


def _resolve_action_and_rationale(
    scanner_id: str | None,
    rule_id: str | None,
    resource_key: str | None,
    title: str,
    details: str,
    evidence: Sequence[Mapping[str, Any]],
) -> tuple[str, str]:
    if scanner_id == "windows.bitlocker" or rule_id == "bitlocker.os_volume":
        return _bitlocker_remediation(resource_key, title, details, evidence)

    # Use exact rule IDs, removing substring/prefix inference.
    if rule_id and rule_id in _RULE_ACTIONS:
        return _RULE_ACTIONS[rule_id]

    # Unknown legacy rules should only receive generic review.
    return (
        f"Review and remediate {title} on the endpoint in accordance with baseline security policy.",
        f"Observed finding: {details}",
    )


def build_offline_fix_plan(report: Mapping[str, Any]) -> dict[str, Any]:
    """Build complete ground-truth facts, fix plan, and blind spots from stored evidence."""
    registry = _scanner_registry_catalogue()
    endpoints = [row for row in report["endpoints"] if row["scan_status"] in {"scanned", "partial"}]
    plan_items: list[dict[str, Any]] = []
    blind_spots: list[dict[str, Any]] = []
    out_of_scope_checks: list[dict[str, Any]] = []
    completed_coverage_no_findings: list[dict[str, Any]] = []
    total_omitted_findings = 0

    for endpoint in endpoints:
        endpoint_id = str(endpoint.get("endpoint_id", ""))
        hostname = str(endpoint.get("hostname", endpoint_id))
        latest = endpoint.get("latest_assessment") or {}
        assessment_id = str(latest.get("assessment_id", ""))
        requested_ids = set(latest.get("scanner_ids", ()))
        scanner_results_list = endpoint.get("scanner_results", ())
        scanner_results = {str(item.get("scanner_id")): item for item in scanner_results_list if isinstance(item, Mapping)}

        # 1. Account for all 24 checks
        for sid, meta in registry.items():
            if sid not in requested_ids:
                out_of_scope_checks.append({
                    "endpoint_id": endpoint_id,
                    "hostname": hostname,
                    "assessment_id": assessment_id,
                    "scanner_id": sid,
                    "name": meta["name"],
                    "reason": "Not requested in assessment scope",
                })
            else:
                res = scanner_results.get(sid)
                if res is None:
                    # Requested check has no result returned
                    blind_spots.append({
                        "endpoint_id": endpoint_id,
                        "hostname": hostname,
                        "assessment_id": assessment_id,
                        "scanner_id": sid,
                        "name": meta["name"],
                        "status": "unverified",
                        "reason": "No execution result returned for requested check",
                        "error_category": None,
                    })
                else:
                    status = str(res.get("status", "unknown"))
                    has_error = bool(res.get("has_error", False))
                    error_category = res.get("error_category")
                    finding_count = int(res.get("finding_count", 0))

                    if status == "success" and not has_error and finding_count == 0:
                        completed_coverage_no_findings.append({
                            "endpoint_id": endpoint_id,
                            "hostname": hostname,
                            "assessment_id": assessment_id,
                            "scanner_id": sid,
                            "name": meta["name"],
                            "status": "no finding observed in completed coverage",
                        })
                    elif status != "success" or has_error:
                        if sid == "windows.wifi":
                            if error_category == "READ_FAILED":
                                reason = "Wi-Fi collection failed; the active Wi-Fi cipher remains unverified."
                            elif status == "incompatible":
                                reason = "The Wi-Fi cipher could not be verified on this interface."
                            else:
                                reason = f"Wi-Fi collection unverified ({error_category or status})."
                        else:
                            if error_category == "READ_FAILED":
                                reason = "Collection failed on host (READ_FAILED); check outcome unverified."
                            elif error_category == "UNSUPPORTED" or status == "incompatible":
                                reason = "Collection unsupported on host (UNSUPPORTED); check outcome unverified."
                            elif status == "skipped":
                                reason = "Check execution was skipped; check outcome unverified."
                            else:
                                reason = f"Check unverified (status: {status})."

                        blind_spots.append({
                            "endpoint_id": endpoint_id,
                            "hostname": hostname,
                            "assessment_id": assessment_id,
                            "scanner_id": sid,
                            "name": meta["name"],
                            "status": status,
                            "reason": reason,
                            "error_category": error_category,
                        })

        # 2. Extract and ground confirmed findings
        findings = endpoint.get("findings", ())
        omitted = int(endpoint.get("findings_omitted", 0))
        total_omitted_findings += omitted

        for index, finding in enumerate(findings):
            finding_id = str(finding.get("finding_id") or f"finding-{index}")
            occurrence_id = str(finding.get("occurrence_id") or f"{assessment_id}:{finding_id}")
            finding_key = f"{endpoint_id}:{assessment_id}:{index}:{occurrence_id}"
            raw_meta = finding.get("metadata")
            meta = raw_meta if isinstance(raw_meta, Mapping) else {}
            scanner_id = str(
                finding.get("scanner_id")
                or meta.get("scanner_id")
                or finding.get("component")
                or "windows.unknown"
            )
            rule_id = str(finding.get("rule_id") or meta.get("rule_id") or "") or None
            resource_key = str(finding.get("resource_key") or meta.get("resource_key") or "") or None
            severity = str(finding.get("severity") or "unknown").lower()
            title = str(finding.get("title") or "Security Finding")
            description = str(finding.get("description") or "")
            evidence = finding.get("evidence", ())
            action, rationale = _resolve_action_and_rationale(
                scanner_id, rule_id, resource_key, title, description, evidence
            )

            plan_items.append({
                "finding_key": finding_key,
                "severity": severity,
                "severity_rank": _SEVERITY_RANKS.get(severity, 0),
                "scanner_id": scanner_id,
                "rule_id": rule_id,
                "resource_key": resource_key,
                "occurrence_id": occurrence_id,
                "finding_id": finding_id,
                "endpoint_id": endpoint_id,
                "hostname": hostname,
                "assessment_id": assessment_id,
                "title": title,
                "details": description,
                "action": action,
                "rationale": rationale,
            })

    # Sort plan items deterministically: severity descending, then hostname, then finding_key
    plan_items.sort(key=lambda x: (-x["severity_rank"], x["hostname"].casefold(), x["finding_key"]))
    for i, item in enumerate(plan_items, start=1):
        item["priority"] = i

    markdown = render_plan_markdown(
        plan_items,
        blind_spots,
        out_of_scope_checks,
        completed_coverage_no_findings,
        total_omitted_findings,
        len(endpoints),
    )

    return {
        "analysis": markdown,
        "plan": plan_items,
        "blind_spots": blind_spots,
        "out_of_scope_checks": out_of_scope_checks,
        "completed_coverage_no_findings": completed_coverage_no_findings,
        "findings_omitted": total_omitted_findings,
    }


def _markdown_text(value: str) -> str:
    # Endpoint-supplied evidence is literal text inside the server's Markdown.
    return re.sub(r"([\\{}\[\]()*_~<>|#&!\x60])", r"\\\1", " ".join(value.split()))


def render_plan_markdown(
    plan: Sequence[Mapping[str, Any]],
    blind_spots: Sequence[Mapping[str, Any]],
    out_of_scope: Sequence[Mapping[str, Any]],
    clean_checks: Sequence[Mapping[str, Any]],
    omitted_findings: int,
    endpoint_count: int,
) -> str:
    """Render plain-language fix plan and coverage report in Markdown."""
    lines: list[str] = ["### Summary", ""]
    lines.append(
        f"Evaluated {endpoint_count} endpoint(s). Identified {len(plan)} confirmed finding action(s), "
        f"{len(clean_checks)} check(s) with no finding observed in completed coverage, "
        f"{len(blind_spots)} unverified check observation(s), and {len(out_of_scope)} check(s) out of assessment scope."
    )
    if omitted_findings > 0:
        lines.append(
            f"**Note:** {omitted_findings} finding record(s) exceeded report bounds and were omitted. "
            "Consult individual assessment detail views for complete evidence records."
        )
    lines.append("")

    lines.append("### Prioritized Fix Plan")
    lines.append("")
    if not plan:
        lines.append("No confirmed findings were observed in completed coverage requiring remediation actions.")
    else:
        for item in plan:
            sev = str(item.get("severity", "unknown")).upper()
            prio = item.get("priority", 1)
            title = _markdown_text(item["title"])
            host = _markdown_text(item["hostname"])
            action = _markdown_text(item["action"])
            rationale = _markdown_text(item["rationale"])
            assessment_id = _markdown_text(item["assessment_id"])
            occ_id = _markdown_text(item["occurrence_id"])

            lines.append(f"**Priority {prio}: {title}** ({sev}) — {host}")
            lines.append(f"- **Recommended Action:** {action}")
            lines.append(f"- **Rationale:** {rationale}")
            lines.append(f"- **Source Reference:** Assessment {assessment_id}, Occurrence {occ_id}")
            lines.append("")

    lines.append("### Coverage and Follow-Up Checks")
    lines.append("")
    if not blind_spots:
        lines.append("All requested checks completed collection successfully without unverified observations.")
    else:
        lines.append("The following requested checks did not achieve completed observation and require follow-up verification:")
        for spot in blind_spots:
            host = _markdown_text(spot["hostname"])
            sid = _markdown_text(spot["scanner_id"])
            reason = _markdown_text(spot["reason"])
            aid = _markdown_text(spot["assessment_id"])
            lines.append(f"- **{host} · {sid}**: {reason} (Assessment {aid})")
    lines.append("")

    if out_of_scope:
        lines.append("### Out-of-Scope Checks")
        lines.append("")
        lines.append("The following checks from the 24-check catalogue were not requested in the selected assessment scope:")
        # Group by scanner_id for compact reading
        sids = sorted({str(x.get("scanner_id")) for x in out_of_scope})
        for sid in sids:
            lines.append(f"- `{sid}`: Not requested in assessment scope")
        lines.append("")

    if clean_checks:
        lines.append("### Completed Coverage (No Findings Observed)")
        lines.append("")
        lines.append("The following checks completed with full coverage and observed no policy violations:")
        sids = sorted({str(x.get("scanner_id")) for x in clean_checks})
        for sid in sids:
            lines.append(f"- `{sid}`: no finding observed in completed coverage")
        lines.append("")

    return "\n".join(lines).strip()


def reorder_plan_with_model_refs(
    base_offline: dict[str, Any],
    model_refs: Sequence[str],
    endpoint_count: int,
) -> dict[str, Any]:
    """Apply validated model priority ordering to prompt findings, preserving all findings deterministically."""
    items = base_offline["plan"]
    by_key = {item["finding_key"]: item for item in items}
    reordered = [by_key.pop(key) for key in model_refs] + list(by_key.values())
    reordered = [dict(item, priority=index) for index, item in enumerate(reordered, start=1)]

    markdown = render_plan_markdown(
        reordered,
        base_offline.get("blind_spots", ()),
        base_offline.get("out_of_scope_checks", ()),
        base_offline.get("completed_coverage_no_findings", ()),
        base_offline.get("findings_omitted", 0),
        endpoint_count,
    )

    return {
        "analysis": markdown,
        "plan": reordered,
        "blind_spots": base_offline.get("blind_spots", ()),
        "out_of_scope_checks": base_offline.get("out_of_scope_checks", ()),
        "completed_coverage_no_findings": base_offline.get("completed_coverage_no_findings", ()),
        "findings_omitted": base_offline.get("findings_omitted", 0),
    }
