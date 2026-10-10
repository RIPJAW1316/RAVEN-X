"""
RAVEN-X Enterprise — Defense Compliance Engine
Maps detected vulnerabilities to CIS, NIST, ISO 27001, PCI-DSS,
SMLDI 2025 (Indian MoD), and CERT-In Baseline frameworks.
"""

from typing import Dict, List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# CVSS base scores for known vulnerability types
# ─────────────────────────────────────────────────────────────────────────────
CVSS_MAP: Dict[str, float] = {
    "SMBv1": 9.8,
    "Real-time Protection Disabled": 9.1,
    "Antivirus Engine Disabled": 9.0,
    "Firewall Disabled": 8.8,
    "No Password Required": 9.3,
    "Defender Path Exclusion": 8.5,
    "Defender Process Exclusion": 8.5,
    "AlwaysInstallElevated": 8.2,
    "Guest Account Enabled": 7.5,
    "RDP NLA": 7.5,
    "Tamper Protection": 7.3,
    "UAC Not": 7.0,
    "Weak Wi-Fi": 6.5,
    "Automatic Login": 6.5,
    "Remote Desktop Enabled": 5.9,
    "PowerShell Execution": 5.5,
    "Outdated Windows Updates": 7.8,
    "BitLocker": 7.2,
    "Suspicious Registry": 7.0,
    "Potential Malware": 9.5,
    "Attack Chain": 9.8,
    "Privilege Escalation": 8.8,
}

_SEVERITY_DEFAULTS = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0}


def cvss_for(vuln: dict) -> float:
    title = vuln.get("title", "")
    for k, v in CVSS_MAP.items():
        if k.lower() in title.lower():
            return v
    return _SEVERITY_DEFAULTS.get(vuln.get("severity", "low"), 5.0)


# ─────────────────────────────────────────────────────────────────────────────
# Framework control mappings  {category → [control_ids]}
# ─────────────────────────────────────────────────────────────────────────────
FRAMEWORKS: Dict[str, Dict[str, List[str]]] = {

    "CIS": {
        "Windows Update":      ["CIS 1.1", "CIS 1.2"],
        "Firewall":            ["CIS 9.1", "CIS 9.2", "CIS 9.3"],
        "Antivirus":           ["CIS 8.1", "CIS 8.2"],
        "User Account Control":["CIS 2.3.17"],
        "Authentication":      ["CIS 1.1.1", "CIS 5.1"],
        "Remote Access":       ["CIS 18.8", "CIS 18.9"],
        "Network":             ["CIS 9.1", "CIS 9.2"],
        "Services":            ["CIS 5.1", "CIS 5.2"],
        "Auditing":            ["CIS 17.1", "CIS 17.2"],
        "Disk Encryption":     ["CIS 18.10.14"],
        "Scripting":           ["CIS 18.9.99"],
        "Privilege Management":["CIS 2.3.11"],
        "Persistence":         ["CIS 9.1"],
        "Network Sharing":     ["CIS 9.3"],
        "Memory":              ["CIS 8.1"],
        "Malware":             ["CIS 8.1", "CIS 8.2"],
    },

    "NIST": {
        "Windows Update":      ["SI-2"],
        "Firewall":            ["SC-7", "AC-4"],
        "Antivirus":           ["SI-3"],
        "User Account Control":["AC-6"],
        "Authentication":      ["IA-2", "IA-5"],
        "Remote Access":       ["AC-17"],
        "Network":             ["SC-7", "CM-7"],
        "Services":            ["CM-7"],
        "Auditing":            ["AU-2", "AU-12"],
        "Disk Encryption":     ["SC-28"],
        "Scripting":           ["CM-7", "SI-7"],
        "Privilege Management":["AC-6", "AC-2"],
        "Persistence":         ["SI-7", "CM-3"],
        "Memory":              ["SI-3", "SC-3"],
        "Malware":             ["SI-3"],
        "Attack Chain":        ["RA-5", "SI-2"],
    },

    "ISO 27001": {
        "Windows Update":      ["A.12.6.1"],
        "Firewall":            ["A.13.1.3"],
        "Antivirus":           ["A.12.2.1"],
        "User Account Control":["A.9.2.3"],
        "Authentication":      ["A.9.2.1", "A.9.4.3"],
        "Remote Access":       ["A.6.2.1"],
        "Network":             ["A.13.1.1"],
        "Services":            ["A.12.5.1"],
        "Auditing":            ["A.12.4.1"],
        "Disk Encryption":     ["A.10.1.1"],
        "Scripting":           ["A.12.6.2"],
        "Privilege Management":["A.9.2.3"],
        "Malware":             ["A.12.2.1"],
    },

    "PCI-DSS": {
        "Windows Update":      ["6.2"],
        "Firewall":            ["1.1", "1.2"],
        "Antivirus":           ["5.1", "5.2"],
        "User Account Control":["7.1", "8.1"],
        "Authentication":      ["8.2", "8.3"],
        "Remote Access":       ["8.3"],
        "Network":             ["1.3", "2.2"],
        "Services":            ["2.2"],
        "Auditing":            ["10.2", "10.3"],
        "Disk Encryption":     ["3.4"],
        "Malware":             ["5.1", "5.2"],
    },

    # ── Indian Defence Standards ───────────────────────────────────────────
    "SMLDI 2025": {
        # Security Manual for Licensed Defence Industries (MoD, 2025)
        "Windows Update":      ["SMLDI-4.2", "SMLDI-4.3"],
        "Firewall":            ["SMLDI-5.1", "SMLDI-5.2"],
        "Antivirus":           ["SMLDI-5.3"],
        "User Account Control":["SMLDI-6.1"],
        "Authentication":      ["SMLDI-6.2", "SMLDI-6.3"],
        "Remote Access":       ["SMLDI-7.1"],
        "Network":             ["SMLDI-5.4", "SMLDI-5.5"],
        "Services":            ["SMLDI-4.4"],
        "Auditing":            ["SMLDI-8.1", "SMLDI-8.2"],
        "Disk Encryption":     ["SMLDI-9.1"],
        "Scripting":           ["SMLDI-4.5"],
        "Malware":             ["SMLDI-5.3"],
        "Persistence":         ["SMLDI-5.6"],
        "USB / Removable Media":["SMLDI-7.3"],
        "Privilege Management":["SMLDI-6.4"],
        "Memory":              ["SMLDI-5.7"],
    },

    "CERT-In": {
        # CERT-In Cyber Security Audit Baseline Requirements
        "Windows Update":      ["CERT-IN-PM-01"],
        "Firewall":            ["CERT-IN-NW-01", "CERT-IN-NW-02"],
        "Antivirus":           ["CERT-IN-EP-01"],
        "Authentication":      ["CERT-IN-IAM-01", "CERT-IN-IAM-02"],
        "Auditing":            ["CERT-IN-LOG-01", "CERT-IN-LOG-02"],
        "Disk Encryption":     ["CERT-IN-DA-01"],
        "Remote Access":       ["CERT-IN-RA-01"],
        "Malware":             ["CERT-IN-EP-02"],
        "Network":             ["CERT-IN-NW-03"],
        "Services":            ["CERT-IN-CM-01"],
        "Scripting":           ["CERT-IN-CM-02"],
    },
}


def get_controls(framework: str, category: str) -> List[str]:
    """Return the list of control IDs for a given framework + category."""
    return FRAMEWORKS.get(framework, {}).get(category, [])


def get_all_controls(framework: str) -> List[str]:
    """Return every control ID defined in a framework."""
    controls: List[str] = []
    for ctrl_list in FRAMEWORKS.get(framework, {}).values():
        controls.extend(ctrl_list)
    return list(set(controls))


def enrich_vulnerability(vuln: dict) -> dict:
    """Add CVSS score and compliance tags to a vulnerability dict."""
    vuln = dict(vuln)
    vuln["cvss_score"] = cvss_for(vuln)
    tags: Dict[str, List[str]] = {}
    category = vuln.get("category", "")
    for fw in FRAMEWORKS:
        controls = get_controls(fw, category)
        if controls:
            tags[fw] = controls
    vuln["compliance_tags"] = tags
    return vuln


def calculate_compliance_score(
    framework: str,
    vulnerabilities: List[dict],
) -> dict:
    """
    Calculate compliance score for a framework given a list of vulnerabilities.

    Returns:
        {
            "framework": str,
            "score": float,          # 0.0 – 100.0
            "total_controls": int,
            "passed": int,
            "failed": int,
            "failed_controls": list[str],
            "passed_controls": list[str],
        }
    """
    all_controls = set(get_all_controls(framework))
    failed: set = set()

    for vuln in vulnerabilities:
        category = vuln.get("category", "")
        controls = get_controls(framework, category)
        failed.update(controls)

    passed = all_controls - failed
    total = len(all_controls)
    score = round((len(passed) / total * 100) if total else 100.0, 1)

    return {
        "framework": framework,
        "score": score,
        "total_controls": total,
        "passed": len(passed),
        "failed": len(failed),
        "failed_controls": sorted(failed),
        "passed_controls": sorted(passed),
    }


def calculate_all_scores(vulnerabilities: List[dict]) -> Dict[str, dict]:
    """Calculate compliance scores for all frameworks at once."""
    return {fw: calculate_compliance_score(fw, vulnerabilities) for fw in FRAMEWORKS}


def list_frameworks() -> List[str]:
    return list(FRAMEWORKS.keys())
