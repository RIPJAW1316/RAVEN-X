"""Regression tests for the executable EnhancedScanner registry."""

import asyncio
from types import SimpleNamespace

from backend.core.scanner.enhanced_scanner import EnhancedScanner
import backend.core.scanner.enhanced_scanner as enhanced_scanner_module


def test_scanner_initializes_with_only_implemented_modules():
    scanner = EnhancedScanner()

    advertised = set(scanner.modules)
    implemented = {
        name
        for name, (status, _) in scanner.MODULE_STATUS.items()
        if status == "implemented"
    }

    assert advertised == implemented
    assert "uac" not in advertised
    assert "firewall" not in advertised
    assert "rootkit_detection" not in advertised


def test_registry_methods_exist_and_are_callable():
    scanner = EnhancedScanner()

    assert scanner.modules
    assert all(callable(check) for check in scanner.modules.values())


def test_targeted_windows_update_scan_is_safe_with_mocked_platform(monkeypatch):
    scanner = EnhancedScanner()
    today = "2026-08-18T00:00:00"

    monkeypatch.setattr(
        enhanced_scanner_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=f'{{"InstalledOn": "{today}"}}',
            stderr="",
        ),
    )

    findings = asyncio.run(
        scanner.scan_all_async(
            scan_type="targeted",
            target_categories=["windows_updates"],
            deep_scan=False,
        )
    )

    assert findings == []
