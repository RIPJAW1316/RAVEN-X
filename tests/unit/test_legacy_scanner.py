"""Characterization tests for the personal-mode scanner finding shape."""

import json
from pathlib import Path
from types import SimpleNamespace

import scanner as legacy_scanner_module
from scanner import VulnerabilityScanner


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_legacy_firewall_finding_matches_compatibility_fixture(monkeypatch):
    scanner = VulnerabilityScanner()

    monkeypatch.setattr(
        legacy_scanner_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="State OFF", stderr=""),
    )

    scanner.check_firewall()

    expected = json.loads((FIXTURES / "legacy_firewall_finding.json").read_text(encoding="utf-8"))
    assert scanner.vulnerabilities[0] == expected
    assert set(scanner.vulnerabilities[0]) == {
        "severity",
        "category",
        "title",
        "details",
        "component",
        "remediation",
        "powershell_command",
    }


def test_legacy_finding_has_stable_compliance_inputs():
    finding = json.loads((FIXTURES / "legacy_firewall_finding.json").read_text(encoding="utf-8"))

    assert legacy_scanner_module.cvss_for(finding) == 8.8
    assert legacy_scanner_module.COMPLIANCE["CIS"][finding["category"]] == ["CIS 9.1", "CIS 9.2", "CIS 9.3"]
