"""Stage a public prototype from the built portal and first-party sample evidence."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.application.ai.local_analysis import TenantLocalAnalysisService
from backend.application.ai.synthetic_demo import (
    CANONICAL_DEMO_REFS,
    WINDOWS_HARDENING_DEMO_ID,
    build_synthetic_windows_demo_report,
    get_demo_source_descriptor,
)
from backend.application.reporting.fleet_pdf import render_fleet_pdf


class RecordedGemini:
    def __init__(self, sample):
        self.enabled = bool(sample)
        self.model = sample.get("model", "")
        self.order = sample.get("order", [])

    def prioritize_synthetic_demo(self, *, fixture_id):
        if fixture_id != WINDOWS_HARDENING_DEMO_ID:
            raise ValueError("Unknown demo fixture")
        return self.order


def build_fixture(now):
    report = build_synthetic_windows_demo_report()
    org = report["organization_id"]
    machine = report["endpoints"][0]
    latest = machine["latest_assessment"]
    machine_id = machine["endpoint_id"]
    run_id = latest["assessment_id"]
    stamp = latest["completed_at"]
    scans = machine["scanner_results"]
    findings = machine["findings"]
    partial = any(scan["status"] != "success" for scan in scans)
    for scan in scans:
        scan["has_error"] = bool(scan.get("has_error", False))
        scan["finding_count"] = len(scan["findings"])
    for finding in findings:
        finding.update(assessment_id=run_id, endpoint_id=machine_id, observed_at=stamp,
                       fingerprint=None, occurrence_id=finding["finding_id"])

    latest.update(requested_at=stamp, started_at=stamp)
    machine.update(scan_status="partial" if partial else "scanned", lifecycle_status="approved",
                   presence_state="online", last_seen_at=stamp, findings_count=len(findings),
                   partial_evidence=partial, malformed_findings=0, selected_for_report=True)
    report.update(generated_at=now, advisory_note="Buildathon prototype using synthetic Windows evidence.",
                  scope={"kind": "fleet", "endpoint_id": None, "assessment_ids": [run_id],
                         "selection_mode": "synthetic"})
    report["summary"].update(scanned=int(not partial), partial=int(partial), pending=0, running=0, revoked=0,
                             unavailable=0, findings_from_completed_scans=len(findings), presence={"online": 1})
    assessment = {
        "assessment_id": run_id, "endpoint_id": machine_id, "organization_id": org,
        "state": "completed", "requested_at": stamp, "scanner_ids": latest["scanner_ids"],
        "correlation_id": "buildathon-sample-correlation", "progress": None, "result": None,
        "error": None, "schedule_id": None,
    }
    result = {
        **assessment, "status": "completed", "created_at": stamp, "started_at": stamp, "completed_at": stamp,
        "scanner_results": [{**scan, "error": scan.get("error_category")} for scan in scans],
        "findings": findings, "total_findings": len(findings), "malformed_finding_count": 0,
    }
    fleet_row = {
        "endpoint_id": machine_id, "hostname": machine["hostname"], "platform": "Windows",
        "platform_version": "11", "architecture": "x64", "lifecycle_status": "active",
        "presence_state": "online", "last_seen_at": stamp, "created_at": stamp, "updated_at": stamp,
        "agent_version": "1.0.0 (sample)",
    }
    endpoint = {
        **fleet_row, "organization_id": org, "status": "active",
        "platform": {"name": "Windows", "version": "11", "architecture": "x64"},
        "capabilities": ["windows.powershell"], "capability_observations": [], "last_seen": stamp, "agent": None,
    }
    presence = {
        "endpoint_id": machine_id, "organization_id": org, "state": "online",
        "last_seen_at": stamp, "last_heartbeat_at": stamp, "connected_since": stamp,
        "stale_since": None, "offline_since": None, "updated_at": stamp,
    }
    severity = Counter(finding["severity"] for finding in findings)
    overview = {
        "organization_id": org, "generated_at": now,
        "endpoints": {"total_endpoints": 1, "active_endpoints": 1, "revoked_endpoints": 0},
        "presence": {"online": 1, "stale": 0, "offline": 0, "unknown": 0, "revoked": 0},
        "assessments": {"completed": 1}, "recent_assessments": [result],
        "findings": {**dict.fromkeys(("critical", "high", "medium", "low", "info", "unknown"), 0), **severity,
                     "total_occurrences": len(findings)},
        "recent_high_severity_findings": [item for item in findings if item["severity"] in ("critical", "high")],
        "malformed_finding_count": 0,
    }
    routes = {
        "/security/overview": overview,
        "/security/metrics": {
            "organization_id": org, "generated_at": now, "window_minutes": 60, "signals": [], "operations": {},
            "authorization": {"attempts": 0, "allowed": 0, "denied": 0, "denial_rate": 0,
                              "denied_by_reason": {}, "denied_by_action": {}},
            "authentication": {"success": 0, "failure": 0, "failure_rate": 0},
        },
        "/audit-events": {"items": [], "pagination": {"limit": 20, "offset": 0, "returned": 0, "total": 0,
                                                      "has_next": False}, "excluded_event_types": []},
        "/compliance/frameworks": [],
        "/assessments": [assessment],
        f"/assessments/{run_id}": assessment,
        f"/assessments/{run_id}/details": result,
        f"/endpoints/{machine_id}": endpoint,
        f"/endpoints/{machine_id}/presence": presence,
    }
    for finding in findings:
        routes[f"/assessments/{run_id}/findings/{finding['occurrence_id']}/recurrence"] = {}
    return report, fleet_row, routes


def stage(args):
    now = datetime.now(timezone.utc).isoformat()
    recorded = json.loads(args.gemini_result.read_text(encoding="utf-8")) if args.gemini_result else {}
    if recorded and (recorded.get("model") != "gemini-3.5-flash-lite" or
                     sorted(recorded.get("order", [])) != sorted(CANONICAL_DEMO_REFS)):
        raise ValueError("Invalid recorded Gemini sample")
    report, fleet_row, routes = build_fixture(now)
    service = TenantLocalAnalysisService(None, None, None, cloud_provider=RecordedGemini(recorded))
    source = get_demo_source_descriptor(WINDOWS_HARDENING_DEMO_ID)
    analyses = {model: service._analyze_report(report, source, demo_id=WINDOWS_HARDENING_DEMO_ID, model=model)
                for model in ("offline", "gemini")}
    if recorded:
        if analyses["gemini"]["provider"] != "google_cloud":
            raise ValueError("Recorded result could not be mapped to the synthetic findings")
        analyses["gemini"].update(
            generated_at=recorded["generated_at"],
            notice="Recorded Gemini inference on this synthetic assessment. Review priorities against the evidence.",
        )
    else:
        analyses["gemini"]["fallback_reason"] = "No recorded Gemini result is available. Showing offline rules."
    machine_id = fleet_row["endpoint_id"]
    machine_report = {**report, "scope": {**report["scope"], "kind": "endpoint", "endpoint_id": machine_id}}
    review_data = {}
    for model, analysis in analyses.items():
        review_data[model] = {
            "status": analysis["status"], "model": analysis["model"], "provider": analysis["provider"],
            "note": analysis.get("fallback_reason") or analysis["notice"], "finding_count": len(analysis["plan"]),
            "priorities": analysis["plan"], "unverified": analysis["blind_spots"],
            "unverified_count": len(analysis["blind_spots"]),
        }
    routes["/reports/fleet"] = report
    routes[f"/endpoints/{machine_id}/report"] = machine_report
    data = {"org": report["organization_id"], "machine": fleet_row, "routes": routes,
            "analyses": analyses, "review": review_data}

    args.output.mkdir()
    shutil.copytree(args.frontend, args.output / "portal")
    templates = ROOT / "scripts/buildathon"
    for filename in ("server.mjs", "Dockerfile"):
        shutil.copyfile(templates / filename, args.output / filename)
    (args.output / "demo.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    for scope, item in (("fleet", report), ("machine", machine_report)):
        for model, review in review_data.items():
            (args.output / f"{scope}-{model}.pdf").write_bytes(render_fleet_pdf(item, review=review))
    with (args.output / "fleet.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Scope", "Device", "Platform", "Evidence coverage", "Findings"])
        writer.writerow(["Synthetic buildathon sample", fleet_row["hostname"], "Windows 11",
                         report["endpoints"][0]["scan_status"], report["summary"]["findings_from_completed_scans"]])
    if "Buildathon prototype" not in " ".join(file.read_text(encoding="utf-8")
                                             for file in (args.output / "portal/assets").glob("*.js")):
        raise ValueError("Frontend must be built with VITE_RAVENX_HOSTED_DEMO=true")
    archive = shutil.make_archive(str(args.output), "zip", args.output)
    print(f"{archive} SHA-256 {hashlib.sha256(Path(archive).read_bytes()).hexdigest()}")
    print(f"Gemini sample provider: {analyses['gemini']['provider']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gemini-result", type=Path)
    stage(parser.parse_args())
