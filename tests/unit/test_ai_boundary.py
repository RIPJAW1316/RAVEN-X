"""AI boundary tests with a fake provider; no local model is required."""

import asyncio
from types import SimpleNamespace

from backend.core.ai.llm_client import LLMClient


class FakeCompletions:
    def create(self, **kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="RECOMMENDATIONS\n- Enable firewall"))],
            usage=SimpleNamespace(prompt_tokens=12, completion_tokens=5),
        )


def test_ai_analysis_transforms_structured_findings_without_live_llm():
    client = LLMClient()
    client.client = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))

    result = asyncio.run(
        client.analyze_vulnerabilities(
            vulnerabilities=[
                {
                    "severity": "high",
                    "category": "Firewall",
                    "title": "Firewall Disabled",
                    "details": "Public profile is off.",
                    "component": "Windows Defender Firewall",
                    "remediation": "Enable it.",
                }
            ],
            system_info={"hostname": "test-host"},
        )
    )

    assert result["prompt_tokens"] == 12
    assert result["completion_tokens"] == 5
    assert result["recommendations"] == ["- Enable firewall"]
