"""Smoke tests for import-time wiring defects."""

import importlib

import pytest


@pytest.mark.parametrize(
    "module_name",
    [
        "backend.api.main",
        "backend.core.database.database",
        "backend.core.scanner.enhanced_scanner",
        "backend.core.reporting.report_generator",
        "backend.core.remediation.auto_fixer",
        "backend.core.ai.llm_client",
    ],
)
def test_core_modules_import(module_name):
    assert importlib.import_module(module_name) is not None
