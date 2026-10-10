"""Safe, isolated checks for the existing in-process API workflows."""

import asyncio
from datetime import datetime

from sqlalchemy import select

from backend.api.v1 import analysis as analysis_api
from backend.api.v1 import remediation as remediation_api
from backend.api.v1 import scan as scan_api
from backend.core.database.database import DatabaseManager
from backend.core.database.models import AIAnalysis, Fix, Scan, Vulnerability


def _isolated_manager(tmp_path, name):
    database_path = tmp_path / f"{name}.db"
    config_path = tmp_path / f"{name}.yaml"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  sqlite_path: '{database_path.as_posix()}'\n",
        encoding="utf-8",
    )
    return DatabaseManager(str(config_path))


def test_scan_execution_persists_mocked_findings(tmp_path, monkeypatch):
    manager = _isolated_manager(tmp_path, "scan")
    monkeypatch.setattr(scan_api, "db_manager", manager)

    async def mocked_scan(**kwargs):
        return [
            {
                "severity": "high",
                "category": "Firewall",
                "title": "Windows Firewall Disabled",
                "details": "Test fixture finding.",
                "component": "Windows Defender Firewall",
                "remediation": "Enable the firewall.",
            }
        ]

    monkeypatch.setattr(scan_api.scanner, "scan_all_async", mocked_scan)

    async def scenario():
        await manager.create_tables_async()
        async with manager.get_async_db() as session:
            session.add(Scan(id="scan-1", scan_type="quick", start_time=datetime.utcnow(), status="running"))

        await scan_api.execute_scan("scan-1", "quick", None, False, False)

        async with manager.get_async_db() as session:
            scan = (await session.execute(select(Scan).where(Scan.id == "scan-1"))).scalar_one()
            findings = (await session.execute(select(Vulnerability).where(Vulnerability.scan_id == "scan-1"))).scalars().all()
            assert scan.status == "completed"
            assert scan.total_vulnerabilities == 1
            assert findings[0].title == "Windows Firewall Disabled"

        await manager.close_async()

    asyncio.run(scenario())


def test_analysis_execution_persists_mocked_ai_response(tmp_path, monkeypatch):
    manager = _isolated_manager(tmp_path, "analysis")
    monkeypatch.setattr(analysis_api, "db_manager", manager)

    async def mocked_analysis(**kwargs):
        return {
            "full_analysis": "Structured test analysis",
            "prompt_tokens": 5,
            "completion_tokens": 3,
            "recommendations": ["Enable the firewall"],
            "priority_fixes": [],
            "compliance_mapping": {"CIS": ["CIS 9.1"]},
        }

    monkeypatch.setattr(analysis_api.llm_client, "analyze_vulnerabilities", mocked_analysis)

    async def scenario():
        await manager.create_tables_async()
        async with manager.get_async_db() as session:
            session.add(Scan(id="scan-2", scan_type="quick", start_time=datetime.utcnow(), status="completed", system_info={}))
            session.add(
                Vulnerability(
                    id="vuln-2",
                    scan_id="scan-2",
                    severity="high",
                    category="Firewall",
                    title="Windows Firewall Disabled",
                    details="Test fixture finding.",
                    component="Windows Defender Firewall",
                )
            )

        await analysis_api.perform_ai_analysis("analysis-2", "scan-2", "comprehensive", None)

        async with manager.get_async_db() as session:
            analysis = (await session.execute(select(AIAnalysis).where(AIAnalysis.id == "analysis-2"))).scalar_one()
            assert analysis.analysis_text == "Structured test analysis"
            assert analysis.recommendations == ["Enable the firewall"]

        await manager.close_async()

    asyncio.run(scenario())


def test_dry_run_remediation_persists_without_host_mutation(tmp_path, monkeypatch):
    manager = _isolated_manager(tmp_path, "remediation")
    monkeypatch.setattr(remediation_api, "db_manager", manager)

    async def scenario():
        await manager.create_tables_async()
        async with manager.get_async_db() as session:
            session.add(Scan(id="scan-3", scan_type="quick", start_time=datetime.utcnow(), status="completed"))
            session.add(
                Vulnerability(
                    id="vuln-3",
                    scan_id="scan-3",
                    severity="high",
                    category="Firewall",
                    title="Windows Firewall Disabled",
                    details="Test fixture finding.",
                    component="Windows Defender Firewall",
                    remediation="Enable the firewall.",
                )
            )

        await remediation_api.execute_remediation(
            remediation_id="remediation-3",
            vulnerabilities=[
                {
                    "id": "vuln-3",
                    "scan_id": "scan-3",
                    "severity": "high",
                    "category": "Firewall",
                    "title": "Windows Firewall Disabled",
                    "details": "Test fixture finding.",
                    "component": "Windows Defender Firewall",
                    "remediation": "Enable the firewall.",
                }
            ],
            auto_fix=False,
            create_restore_point=False,
            dry_run=True,
        )

        async with manager.get_async_db() as session:
            fix = (await session.execute(select(Fix).where(Fix.vulnerability_id == "vuln-3"))).scalar_one()
            assert fix.status == "simulated"
            assert fix.output == "Dry run - no changes applied"

        await manager.close_async()

    asyncio.run(scenario())
