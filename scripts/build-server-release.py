"""Freeze exact WS-03 server bytes into a deterministic, verifiable ZIP.

The adjacent SHA-256 must be conveyed to the operator independently; it is
not a signature and the bundled manifest alone does not authenticate itself.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.5.0-ws03b-rc7"
BASELINE = "409f95573b1832a8d1a458dd4f91e13b8ca0d7d8"
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
SCRIPTS = ("start-server-ws03.ps1", "backup-server-ws03.ps1", "upgrade-server-ws03.ps1",
           "recover-server-ws03.ps1", "ws03-verify-san.py", "ws03b-synthetic-fixture.py",
           "ws03b-privileged-rehearsal.ps1",
           "upgrade-server.ps1", "install-server.ps1",
           "runtime-selection.ps1", "release-integrity.ps1", "build-server-release.py")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_source(path: Path) -> bytes:
    relative = path.relative_to(ROOT)
    current = path
    while current != ROOT:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f"release source traverses a reparse point: {relative}")
        current = current.parent
    if not path.is_file():
        raise ValueError(f"release source is not a file: {relative}")
    return path.read_bytes()


def _verify_source() -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != BASELINE:
        raise ValueError("source baseline changed")
    diff = subprocess.check_output(["git", "diff", "--binary", "--", *ACCEPTED_PATHS], cwd=ROOT)
    if sha(diff) != ACCEPTED_DIFF:
        raise ValueError("accepted Phase 1A-B diff changed")
    if sys.version_info[:2] != (3, 13) or sys.platform != "win32":
        raise ValueError("server release targets Windows CPython 3.13")


def _wheel_identity(path: Path) -> tuple[str, str]:
    if path.suffix != ".whl" or path.is_symlink():
        raise ValueError("wheelhouse contains an unexpected member")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("wheel has duplicate or corrupt members")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError("wheel metadata is missing or ambiguous")
        for name in names:
            member = PurePosixPath(name)
            if member.is_absolute() or ".." in member.parts or "\\" in name or ":" in name:
                raise ValueError("wheel contains an unsafe path")
        record = BytesParser().parsebytes(archive.read(metadata[0]))
    name, version = record.get("Name"), record.get("Version")
    if not name or not version or not re.fullmatch(r"[A-Za-z0-9_.-]+", name + version):
        raise ValueError("wheel name or version is invalid")
    return name.lower().replace("_", "-"), version


def _payloads(wheel_dir: Path) -> tuple[dict[str, bytes], list[dict]]:
    paths = set((ROOT / "backend").rglob("*.py"))
    paths |= set((ROOT / "frontend" / "dist").rglob("*"))
    paths |= {ROOT / "config" / "config.yaml", ROOT / "requirements-server.txt"}
    paths |= {ROOT / "scripts" / name for name in SCRIPTS}
    paths = {path for path in paths if path.is_file()}
    if not (ROOT / "frontend" / "dist" / "index.html") in paths:
        raise ValueError("built React portal is missing")
    payload = {path.relative_to(ROOT).as_posix(): _safe_source(path) for path in paths}
    wheels = sorted(wheel_dir.iterdir())
    if not wheels or any(not path.is_file() for path in wheels):
        raise ValueError("offline wheelhouse is missing or unsafe")
    identities = {}
    lock_lines = []
    for wheel in wheels:
        name, version = _wheel_identity(wheel)
        if name in identities:
            raise ValueError("wheelhouse contains duplicate distributions")
        identities[name] = version
        data = wheel.read_bytes()
        payload["wheels/" + wheel.name] = data
        lock_lines.append(f"{name}=={version} --hash=sha256:{sha(data)}")
    direct = {"fastapi": "0.118.0", "uvicorn": "0.38.0", "sqlalchemy": "2.0.45",
              "aiosqlite": "0.21.0", "pyyaml": "6.0.3", "httpx": "0.28.1",
              "pydantic": "2.12.5", "cryptography": "50.0.2", "pywin32": "312"}
    if not all(identities.get(name) == version for name, version in direct.items()):
        raise ValueError("wheelhouse does not match pinned direct dependencies")
    payload["requirements-server-lock.txt"] = ("\n".join(sorted(lock_lines)) + "\n").encode()
    payload["VERSION"] = (VERSION + "\n").encode()
    entries = [{"path": name, "sha256": sha(data), "size": len(data)}
               for name, data in sorted(payload.items())]
    return payload, entries


def build(wheel_dir: Path, output: Path) -> dict:
    _verify_source()
    if output.exists():
        raise FileExistsError("release ZIP already exists; refusing to replace it")
    payload, entries = _payloads(wheel_dir)
    manifest = {"format": 1, "product": "RAVEN-X Enterprise Server", "version": VERSION,
                "target": "Windows AMD64 / CPython 3.13", "source_baseline": BASELINE,
                "accepted_phase1ab_diff_sha256": ACCEPTED_DIFF, "files": entries}
    payload["release-manifest.json"] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 12, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = sha(output.read_bytes())
    (output.with_suffix(output.suffix + ".sha256")).write_text(digest + "  " + output.name + "\n", encoding="ascii")
    verify(output, expected_sha256=digest)
    return {"package": str(output), "sha256": digest, "files": len(entries),
            "manifest_sha256": sha(payload["release-manifest.json"])}


def verify(path: Path, *, expected_sha256: str) -> dict:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
        raise ValueError("an independently supplied 64-digit SHA-256 is required")
    if sha(path.read_bytes()) != expected_sha256.lower():
        raise ValueError("release package SHA-256 mismatch")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("release archive has duplicate or corrupt members")
        manifest = json.loads(archive.read("release-manifest.json"))
        if manifest.get("version") != VERSION or manifest.get("source_baseline") != BASELINE:
            raise ValueError("release manifest identity is wrong")
        listed = {item["path"]: item for item in manifest["files"]}
        if set(names) != set(listed) | {"release-manifest.json"}:
            raise ValueError("release manifest inventory differs from archive")
        for name, item in listed.items():
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
                raise ValueError("release contains an unsafe path")
            data = archive.read(name)
            if sha(data) != item["sha256"] or len(data) != item["size"]:
                raise ValueError("release member hash mismatch")
    return {"version": VERSION, "files": len(listed), "sha256": expected_sha256.lower()}


def verify_extracted(root: Path, package: Path, *, expected_sha256: str) -> dict:
    """Compare every extracted executable byte to the independently checked ZIP."""
    verified = verify(package, expected_sha256=expected_sha256)
    with zipfile.ZipFile(package) as archive:
        manifest = json.loads(archive.read("release-manifest.json"))
        listed = {item["path"]: item for item in manifest["files"]}
        listed["release-manifest.json"] = {
            "sha256": sha(archive.read("release-manifest.json")),
            "size": len(archive.read("release-manifest.json")),
        }
    root = root.absolute()
    if root.is_symlink() or root.is_junction():
        raise ValueError("extracted root is a reparse point")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_junction() or (
                getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError("extracted release contains a reparse point")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith("venv/"):
            continue
        actual.add(relative)
        if relative not in listed:
            raise ValueError("extracted release contains an unreviewed file")
        data = path.read_bytes()
        if sha(data) != listed[relative]["sha256"] or len(data) != listed[relative]["size"]:
            raise ValueError("extracted release member differs from ZIP")
    if actual != set(listed):
        raise ValueError("extracted release is incomplete")
    return verified


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("build")
    create.add_argument("--wheel-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, default=ROOT / "dist" / f"RAVEN-X-Server-{VERSION}.zip")
    check = sub.add_parser("verify")
    check.add_argument("package", type=Path)
    check.add_argument("--expected-sha256", required=True)
    extracted = sub.add_parser("verify-extracted")
    extracted.add_argument("package", type=Path)
    extracted.add_argument("--root", type=Path, required=True)
    extracted.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = build(args.wheel_dir, args.output)
    elif args.command == "verify-extracted":
        result = verify_extracted(args.root, args.package, expected_sha256=args.expected_sha256)
    else:
        result = verify(args.package, expected_sha256=args.expected_sha256)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
