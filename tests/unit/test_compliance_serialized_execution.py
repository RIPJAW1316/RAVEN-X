from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from backend.application.compliance.service import ComplianceControlEvaluator
from backend.domain.compliance import ComplianceStatus, ravenx_windows_baseline_registry


@pytest.mark.parametrize("change,result", [
    ({}, ComplianceStatus.COMPLIANT),
    ({"rules_completed": []}, ComplianceStatus.UNKNOWN),
    ({"completeness": "partial"}, ComplianceStatus.UNKNOWN),
    ({"scanner_id": "windows.uac"}, ComplianceStatus.UNKNOWN),
    ({"rules_completed": ["unknown.rule"]}, ComplianceStatus.UNKNOWN),
])
def test_compliance_requires_completed_rule_in_serialized_evidence(change, result):
    registry = ravenx_windows_baseline_registry()
    control = registry.controls_for(registry.frameworks()[0].framework_id)[0]
    now = datetime.now(timezone.utc)
    assessment = SimpleNamespace(
        completed_at=now, state="completed", assessment_id="fixture-run",
        result={"scanner_results": [{
            "scanner_id": "windows.firewall",
            "status": "success",
            "execution_evidence": {
                "scanner_id": "windows.firewall", "completeness": "complete",
                "rules_attempted": ["firewall.profile"], "rules_completed": ["firewall.profile"],
                **change,
            },
        }]},
    )
    endpoint = SimpleNamespace(endpoint_id="fixture-machine", platform=SimpleNamespace(name="Windows"))
    evaluation = ComplianceControlEvaluator(clock=lambda: now).evaluate(control, endpoint, [assessment])
    assert evaluation.status is result
