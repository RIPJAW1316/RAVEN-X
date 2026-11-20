"""Stage a public prototype from the built portal and first-party sample evidence."""
import argparse
from collections import Counter
from copy import deepcopy
import csv
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.application.ai.local_analysis import TenantLocalAnalysisService
from backend.application.ai.synthetic_demo import build_synthetic_windows_demo_report


def extra_finding(scanner, rule, title, severity, source, observed):
    return {
        "finding_id": f"sample-{scanner}",
        "scanner_id": scanner,
        "rule_id": rule,
        "metadata": {"scanner_id": scanner, "rule_id": rule},
        "severity": severity,
        "title": title,
        "description": observed,
        "evidence": [{"source": source, "observed_value": observed}],
    }


def build_fixture(now):
    report = build_synthetic_windows_demo_report()
    template = report["endpoints"][0]
    baseline = {finding["scanner_id"]: finding for finding in template["findings"]}
    rdp = extra_finding("windows.rdp", "rdp.nla_off", "RDP Network Level Authentication Disabled",
                        "high", "RDP listener configuration", "Network Level Authentication is disabled.")
    realtime = extra_finding("windows.defender", "defender.realtime_off", "Defender Real-Time Protection Off",
                             "high", "Get-MpComputerStatus", "RealTimeProtectionEnabled=False")
    signatures = extra_finding("windows.defender-signature-age", "defender.signatures_stale",
                               "Defender Signatures Are Stale", "high", "Get-MpComputerStatus",
                               "AntivirusSignatureAge=12 days")
    hotfix = extra_finding("windows.hotfix-recency", "updates.hotfix_inventory_old",
                           "No Recent Windows Hotfix Recorded", "high", "Get-HotFix",
                           "Most recent installed hotfix was recorded 104 days before assessment.")
    updates = extra_finding("windows.updates", "updates.disabled", "Windows Update Service Disabled",
                            "high", "Windows Update service", "wuauserv startup type is Disabled.")
    samples = [
        ("demo-win11-pc", "demo-windows-assessment", "FINANCE-LT-01", "Windows", "11 Pro",
         [baseline["windows.bitlocker"], baseline["windows.firewall"]], "failed"),
        ("demo-branch-server", "sample-branch-assessment", "BRANCH-SRV-01", "Windows Server", "2022",
         [baseline["windows.smb"], rdp], "incompatible"),
        ("demo-ops-desktop", "sample-ops-assessment", "OPS-WS-04", "Windows", "11 Enterprise",
         [realtime, signatures], "success"),
        ("demo-frontdesk", "sample-frontdesk-assessment", "FRONTDESK-PC-02", "Windows", "11 Pro",
         [baseline["windows.uac"], baseline["windows.autorun"]], "success"),
        ("demo-warehouse", "sample-warehouse-assessment", "WAREHOUSE-PC-03", "Windows", "11 Enterprise",
         [hotfix, updates], "success"),
    ]
    endpoints, fleet_rows, assessments, recent_results, findings, routes = [], [], [], [], [], {}
    for index, sample in enumerate(samples):
        machine, fleet_row, assessment, result, machine_routes = build_machine(
            report["organization_id"], template["latest_assessment"]["scanner_ids"],
            sample, (now - timedelta(minutes=7 + index * 5)).isoformat(),
        )
        endpoints.append(machine)
        fleet_rows.append(fleet_row)
        assessments.append(assessment)
        recent_results.append(result)
        findings.extend(result["findings"])
        routes.update(machine_routes)

    partial = sum(row["partial_evidence"] for row in endpoints)
    report.update(
        generated_at=now.isoformat(), advisory_note="Buildathon prototype using synthetic Windows evidence.",
        endpoints=endpoints, scope={"kind": "fleet", "endpoint_id": None,
                                    "assessment_ids": [row["assessment_id"] for row in assessments],
                                    "selection_mode": "synthetic"},
    )
    report["summary"].update(total_enrolled=len(endpoints), approved=len(endpoints), scanned=len(endpoints) - partial,
                             partial=partial, pending=0, running=0, revoked=0, unavailable=0,
                             findings_from_completed_scans=len(findings), presence={"online": len(endpoints)})
    org = report["organization_id"]
    severity = Counter(finding["severity"] for finding in findings)
    routes.update({
        "/security/overview": {
            "organization_id": org, "generated_at": now.isoformat(),
            "endpoints": {"total_endpoints": len(endpoints), "active_endpoints": len(endpoints), "revoked_endpoints": 0},
            "presence": {"online": len(endpoints), "stale": 0, "offline": 0, "unknown": 0, "revoked": 0},
            "assessments": {"completed": len(assessments)}, "recent_assessments": recent_results,
            "findings": {**dict.fromkeys(("critical", "high", "medium", "low", "info", "unknown"), 0), **severity,
                         "total_occurrences": len(findings)},
            "recent_high_severity_findings": [item for item in findings if item["severity"] in ("critical", "high")],
            "malformed_finding_count": 0,
        },
        "/security/metrics": {
            "organization_id": org, "generated_at": now.isoformat(), "window_minutes": 60, "signals": [], "operations": {},
            "authorization": {"attempts": 0, "allowed": 0, "denied": 0, "denial_rate": 0,
                              "denied_by_reason": {}, "denied_by_action": {}},
            "authentication": {"success": 0, "failure": 0, "failure_rate": 0},
        },
        "/audit-events": {"items": [], "pagination": {"limit": 20, "offset": 0, "returned": 0, "total": 0,
                                                      "has_next": False}, "excluded_event_types": []},
        "/compliance/frameworks": [],
        "/assessments": assessments,
        "/reports/fleet": report,
    })
    return report, fleet_rows, routes


def build_machine(org, scanner_ids, sample, stamp):
    machine_id, run_id, hostname, platform, version, input_findings, wifi = sample
    findings = deepcopy(input_findings)
    for finding in findings:
        finding.update(assessment_id=run_id, endpoint_id=machine_id, observed_at=stamp,
                       fingerprint=None, occurrence_id=finding["finding_id"])
    counts = Counter(finding["scanner_id"] for finding in findings)
    if set(counts) - set(scanner_ids):
        raise ValueError("Sample evidence refers to an unavailable scanner.")
    scans = []
    for scanner in scanner_ids:
        status = wifi if scanner == "windows.wifi" else "success"
        error = {"failed": "READ_FAILED", "incompatible": "UNSUPPORTED"}.get(status)
        scans.append({"scanner_id": scanner, "status": status, "has_error": error is not None,
                      "error_category": error, "finding_count": counts[scanner]})
    partial = any(scan["status"] != "success" for scan in scans)
    latest = {"assessment_id": run_id, "scanner_ids": scanner_ids, "status": "completed",
              "completed_at": stamp, "started_at": stamp, "requested_at": stamp}
    machine = {
        "endpoint_id": machine_id, "hostname": hostname, "latest_assessment": latest,
        "scanner_results": scans, "findings": findings, "findings_omitted": 0,
        "scan_status": "partial" if partial else "scanned", "lifecycle_status": "approved", "presence_state": "online",
        "last_seen_at": stamp, "findings_count": len(findings), "partial_evidence": partial,
        "malformed_findings": 0, "selected_for_report": True,
    }
    assessment = {
        "assessment_id": run_id, "endpoint_id": machine_id, "organization_id": org,
        "state": "completed", "requested_at": stamp, "scanner_ids": latest["scanner_ids"],
        "correlation_id": f"{run_id}-correlation", "progress": None, "result": None,
        "error": None, "schedule_id": None,
    }
    result = {
        **assessment, "status": "completed", "created_at": stamp, "started_at": stamp, "completed_at": stamp,
        "scanner_results": [{**scan, "error": scan.get("error_category")} for scan in scans],
        "findings": findings, "total_findings": len(findings), "malformed_finding_count": 0,
    }
    fleet_row = {
        "endpoint_id": machine_id, "hostname": hostname, "platform": platform,
        "platform_version": version, "architecture": "x64", "lifecycle_status": "active",
        "presence_state": "online", "last_seen_at": stamp, "created_at": stamp, "updated_at": stamp,
        "agent_version": "1.0.0 (sample)",
    }
    endpoint = {
        **fleet_row, "organization_id": org, "status": "active",
        "platform": {"name": platform, "version": version, "architecture": "x64"},
        "capabilities": ["windows.powershell"], "capability_observations": [], "last_seen": stamp, "agent": None,
    }
    presence = {
        "endpoint_id": machine_id, "organization_id": org, "state": "online",
        "last_seen_at": stamp, "last_heartbeat_at": stamp, "connected_since": stamp,
        "stale_since": None, "offline_since": None, "updated_at": stamp,
    }
    routes = {
        f"/assessments/{run_id}": assessment,
        f"/assessments/{run_id}/details": result,
        f"/endpoints/{machine_id}": endpoint,
        f"/endpoints/{machine_id}/presence": presence,
    }
    for finding in findings:
        routes[f"/assessments/{run_id}/findings/{finding['occurrence_id']}/recurrence"] = {}
    return machine, fleet_row, assessment, result, routes


def stage(args):
    report, fleet_rows, routes = build_fixture(datetime.now(timezone.utc))
    analyses = {}
    reports = {"fleet": report}
    for endpoint in report["endpoints"]:
        endpoint_id = endpoint["endpoint_id"]
        scope = {
            "kind": "endpoint", "endpoint_id": endpoint_id,
            "assessment_ids": [endpoint["latest_assessment"]["assessment_id"]], "selection_mode": "synthetic",
        }
        summary = {**report["summary"], "total_enrolled": 1, "approved": 1,
                   "scanned": int(not endpoint["partial_evidence"]), "partial": int(endpoint["partial_evidence"]),
                   "findings_from_completed_scans": endpoint["findings_count"], "presence": {"online": 1}}
        machine_report = {**report, "scope": scope, "summary": summary, "endpoints": [endpoint]}
        reports[endpoint_id] = machine_report
        routes[f"/endpoints/{endpoint_id}/report"] = machine_report

    service = TenantLocalAnalysisService(None, None, None)
    for scope, item in reports.items():
        source = {
            "organization_id": item["organization_id"], "assessment_ids": item["scope"]["assessment_ids"],
            "endpoint_ids": [endpoint["endpoint_id"] for endpoint in item["endpoints"]],
            "report_generated_at": item["generated_at"],
        }
        analyses[scope] = service._analyze_report(item, source, model="offline")
    data = {"org": report["organization_id"], "machines": fleet_rows, "routes": routes,
            "analyses": analyses}

    args.output.mkdir()
    shutil.copytree(args.frontend, args.output / "portal")
    templates = ROOT / "scripts/buildathon"
    for filename in ("server.mjs", "gemini.mjs", "reviews.mjs", "render_pdf.py", "Dockerfile"):
        shutil.copyfile(templates / filename, args.output / filename)
    shutil.copyfile(ROOT / "backend/application/reporting/fleet_pdf.py", args.output / "fleet_pdf.py")
    (args.output / "demo.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    with (args.output / "fleet.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Scope", "Device", "Platform", "Evidence coverage", "Findings"])
        for fleet_row, endpoint in zip(fleet_rows, report["endpoints"], strict=True):
            writer.writerow(["Synthetic buildathon sample", fleet_row["hostname"],
                             f"{fleet_row['platform']} {fleet_row['platform_version']}",
                             endpoint["scan_status"], endpoint["findings_count"]])
    if "Buildathon prototype" not in " ".join(file.read_text(encoding="utf-8")
                                             for file in (args.output / "portal/assets").glob("*.js")):
        raise ValueError("Frontend must be built with VITE_RAVENX_HOSTED_DEMO=true")
    archive = shutil.make_archive(str(args.output), "zip", args.output)
    print(f"{archive} SHA-256 {hashlib.sha256(Path(archive).read_bytes()).hexdigest()}")
    print(f"Built {len(fleet_rows)} distinct machines and {len(reports)} report scopes.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    stage(parser.parse_args())
