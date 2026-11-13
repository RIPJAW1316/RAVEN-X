"""Build an immutable WS-03C recovery source ZIP; the digest needs independent delivery."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0-ws03c-rc6e"
BASELINE = "409f95573b1832a8d1a458dd4f91e13b8ca0d7d8"
SERVER_RC7_SHA256 = "dc45a85f40fac3a267574af6f983d8b1379fb26e731cf0c514f8b621c16ccbfa"
ACCEPTED_DIFF = "038e1ff76c664017a3c1e886362360c958fe9cdddfcd7f0469b7b7e58782c3a6"
ACCEPTED_PATHS = (
    "backend/agent/windows_scanners.py", "backend/application/assessment/local_orchestrator.py",
    "backend/application/reporting/detail.py", "backend/application/reporting/fleet_report.py",
    "frontend/e2e/assessment-outcomes.spec.ts", "frontend/playwright.config.ts",
    "frontend/src/features/Assessments.tsx", "scripts/e2e-server.py",
    "tests/integration/test_https_windows_golden_path.py", "tests/integration/test_tenant_fleet_report_sql.py",
    "tests/unit/test_finding_identity_and_detail.py", "tests/unit/test_local_assessment_orchestrator.py",
    "tests/unit/test_local_capabilities.py", "tests/unit/test_tenant_insights.py",
    "tests/unit/test_windows_agent_host.py", "tests/unit/test_windows_agent_store.py",
    "tests/unit/test_windows_read_only_scanners.py",
)
SCRIPTS = ("archive-agent-ws03c.ps1", "build-agent-recovery-release.py",
           "ws03c-synthetic-fixture.py", "ws03c-privileged-rehearsal.ps1",
           "ws03c-launch-disposable.ps1")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source(path: Path) -> bytes:
    current = path
    while current != ROOT:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("release source contains a reparse point")
        current = current.parent
    return path.read_bytes()


def build(wheels: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("release candidate already exists")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != BASELINE:
        raise ValueError("source baseline differs")
    diff = subprocess.check_output(["git", "diff", "--binary", "--", *ACCEPTED_PATHS], cwd=ROOT)
    if sha(diff) != ACCEPTED_DIFF:
        raise ValueError("accepted Phase 1A-B diff differs")
    if sys.platform != "win32" or sys.version_info[:2] != (3, 13):
        raise ValueError("release targets Windows Python 3.13")
    paths = (set((ROOT / "backend").rglob("*.py")) |
             {ROOT / "scripts" / name for name in SCRIPTS} |
             {ROOT / "WS03C_AGENT_RECOVERY_RUNBOOK.md"})
    payload = {p.relative_to(ROOT).as_posix(): source(p) for p in paths if p.is_file()}
    server_release = ROOT / "dist" / "RAVEN-X-Server-0.5.0-ws03b-rc7.zip"
    if sha(server_release.read_bytes()) != SERVER_RC7_SHA256:
        raise ValueError("trusted WS-03B RC7 dependency baseline differs")
    with zipfile.ZipFile(server_release) as archive:
        reference = json.loads(archive.read("release-manifest.json"))
    pinned = {Path(item["path"]).name: item["sha256"] for item in reference["files"]
              if item["path"].startswith("wheels/")}
    if len(pinned) != 23 or {p.name for p in wheels.iterdir()} != set(pinned):
        raise ValueError("recovery wheel inventory differs from RC7")
    lock = []
    for wheel in sorted(wheels.iterdir()):
        if wheel.suffix != ".whl" or wheel.is_symlink() or not wheel.is_file():
            raise ValueError("wheelhouse contains an unsafe member")
        data = wheel.read_bytes()
        if sha(data) != pinned[wheel.name]:
            raise ValueError("recovery wheel differs from RC7")
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or not any(n.endswith(".dist-info/WHEEL") for n in names):
                raise ValueError("wheel metadata or inventory is unsafe")
            for item in archive.infolist():
                entry = PurePosixPath(item.filename)
                if (entry.is_absolute() or ".." in entry.parts or "\\" in item.filename or
                        ":" in item.filename or item.file_size > 64 * 1024 * 1024 or
                        (item.external_attr >> 16) & 0o170000 == 0o120000):
                    raise ValueError("wheel contains an unsafe member")
            if archive.testzip() is not None:
                raise ValueError("corrupt wheel")
        payload["wheels/" + wheel.name] = data
        distribution, version = wheel.name.split("-")[:2]
        lock.append(f"{distribution.replace('_','-')}=={version} --hash=sha256:{sha(data)}")
    if len(lock) != 23:
        raise ValueError("reviewed 23-wheel dependency set is required")
    payload["requirements-recovery-lock.txt"] = ("\n".join(sorted(lock)) + "\n").encode()
    payload["VERSION"] = (VERSION + "\n").encode()
    entries = [{"path": name, "sha256": sha(data), "size": len(data)} for name, data in sorted(payload.items())]
    manifest = {"format": 1, "product": "RAVEN-X Windows Agent Recovery", "version": VERSION,
                "source_baseline": BASELINE, "accepted_phase1ab_diff_sha256": ACCEPTED_DIFF,
                "target": "Windows AMD64 / CPython 3.13", "files": entries}
    payload["release-manifest.json"] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, (2026, 11, 12, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)
    digest = sha(output.read_bytes())
    output.with_suffix(output.suffix + ".sha256").write_text(digest + "  " + output.name + "\n", encoding="ascii")
    verify(output, digest)
    return {"zip_sha256": digest, "manifest_sha256": sha(payload["release-manifest.json"]),
            "files": len(entries)}


def verify(path: Path, expected: str) -> dict:
    if len(expected) != 64 or sha(path.read_bytes()) != expected.lower():
        raise ValueError("release digest differs")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("release ZIP is corrupt or ambiguous")
        manifest = json.loads(archive.read("release-manifest.json"))
        if manifest.get("version") != VERSION or manifest.get("source_baseline") != BASELINE:
            raise ValueError("release identity differs")
        entries = {item["path"]: item for item in manifest["files"]}
        if set(names) != set(entries) | {"release-manifest.json"}:
            raise ValueError("release inventory differs")
        for name, entry in entries.items():
            p = PurePosixPath(name)
            if p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name:
                raise ValueError("unsafe release path")
            data = archive.read(name)
            if sha(data) != entry["sha256"] or len(data) != entry["size"]:
                raise ValueError("release member changed")
    return {"verified": True, "files": len(entries), "sha256": expected.lower()}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--wheels", type=Path, required=True)
    b.add_argument("--output", type=Path, required=True)
    v = sub.add_parser("verify")
    v.add_argument("package", type=Path)
    v.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    result = build(args.wheels, args.output) if args.command == "build" else verify(args.package, args.expected_sha256)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
