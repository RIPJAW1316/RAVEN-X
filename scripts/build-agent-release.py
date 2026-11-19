"""Freeze the reviewed endpoint source and eight Windows wheels for Inno Setup.

This builder never copies the server, personal scanner, databases or TLS keys.
The resulting manifest checks integrity; authenticity comes from an independently
delivered SHA-256 of the final Setup.exe (or a future code signature).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "b53ac0fea11432badcc13e89d0d0f3966d1689bd"
ACCEPTED_DIFF = "97a03d490a87183a2d0f89f247250bd4349e1f3f68b1e2476f8788e55d422f0f"
VERSION = "1.0.0-rc10"
EXTENDED_CHECKS_SHA256 = "eaa8d9b386b13222dba73ff90d1726f01a5bedb5a1e751f48df6b5ec277bfb93"
ACCEPTED_PATHS = (
    "backend/agent/windows_scanners.py", "backend/application/assessment/local_orchestrator.py",
    "backend/application/reporting/detail.py", "backend/application/reporting/fleet_report.py",
    "scripts/e2e-server.py",
    "tests/integration/test_https_windows_golden_path.py", "tests/integration/test_tenant_fleet_report_sql.py",
    "tests/unit/test_finding_identity_and_detail.py", "tests/unit/test_local_assessment_orchestrator.py",
    "tests/unit/test_local_capabilities.py", "tests/unit/test_tenant_insights.py",
    "tests/unit/test_windows_agent_host.py", "tests/unit/test_windows_agent_store.py",
    "tests/unit/test_windows_read_only_scanners.py",
    "backend/domain/enrollment/models.py", "scripts/install-agent.ps1", "scripts/setup-agent.ps1",
    "scripts/RAVEN-X-Windows-Setup.iss", "scripts/setup-token-pipe.iss",
)
WHEEL_NAMES = frozenset({
    "anyio-4.16.0-py3-none-any.whl", "certifi-2026.10.23-py3-none-any.whl",
    "h11-0.16.0-py3-none-any.whl", "httpcore-1.0.9-py3-none-any.whl",
    "httpx-0.28.1-py3-none-any.whl", "idna-3.20-py3-none-any.whl",
    "pywin32-312-cp313-cp313-win_amd64.whl", "typing_extensions-4.16.0-py3-none-any.whl",
})
SCRIPT_NAMES = ("install-agent.ps1", "runtime-selection.ps1", "release-integrity.ps1", "setup-agent.ps1", "managed-python.ps1")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_accepted_source() -> None:
    if subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE, "HEAD"], cwd=ROOT).returncode:
        raise ValueError("source baseline changed")
    delta = subprocess.check_output(["git", "diff", "--binary", BASELINE, "--", *ACCEPTED_PATHS], cwd=ROOT)
    if digest(delta) != ACCEPTED_DIFF:
        raise ValueError("reviewed scanner source diff changed")
    extended = ROOT / "backend" / "agent" / "windows_extended_checks.py"
    if digest(extended.read_bytes().replace(b"\r\n", b"\n")) != EXTENDED_CHECKS_SHA256:
        raise ValueError("reviewed extended scanner source changed")


def agent_source_paths() -> set[Path]:
    # Import-time dependency closure is intentionally checked against explicit
    # forbidden trees. Any new dynamic import needs review before release.
    sys.path.insert(0, str(ROOT))
    import backend.agent.__main__  # noqa: F401
    import backend.agent.trust  # noqa: F401

    paths: set[Path] = set()
    for name, module in tuple(sys.modules.items()):
        if name != "backend" and not name.startswith("backend."):
            continue
        source = getattr(module, "__file__", None)
        if not source or not source.endswith(".py"):
            continue
        path = Path(source).resolve()
        if not path.is_relative_to(ROOT / "backend"):
            raise ValueError("agent import escaped backend source")
        relative = path.relative_to(ROOT)
        if relative.parts[1] in {"api", "core"} or relative.name == "legacy_adapters.py":
            raise ValueError(f"agent imported forbidden component: {relative}")
        paths.add(relative)
    paths.add(Path("backend/agent/__main__.py"))
    if not paths or not {Path("backend/agent/windows_scanners.py"),
                         Path("backend/agent/windows_extended_checks.py")}.issubset(paths):
        raise ValueError("agent dependency closure is incomplete")
    return paths


def verify_wheel(path: Path) -> None:
    if path.name not in WHEEL_NAMES or path.is_symlink() or not path.is_file():
        raise ValueError("unexpected agent wheel")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not any(n.endswith(".dist-info/METADATA") for n in names):
            raise ValueError("wheel metadata or entries are invalid")
        if not any(n.endswith(".dist-info/WHEEL") for n in names):
            raise ValueError("wheel tag metadata is missing")
        for item in archive.infolist():
            entry = PurePosixPath(item.filename)
            if (entry.is_absolute() or ".." in entry.parts or "\\" in item.filename
                    or ":" in item.filename or item.file_size > 64 * 1024 * 1024
                    or (item.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("wheel has an unsafe member")
        if archive.testzip() is not None:
            raise ValueError("wheel archive is corrupt")


def assert_normal_source_file(relative: Path) -> None:
    source = ROOT / relative
    if not source.is_file() or not source.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError(f"source file is unsafe or missing: {relative}")
    current = source
    while current != ROOT:
        info = current.lstat()
        if current.is_symlink() or current.is_junction() or (
                getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(f"source path contains a reparse point: {relative}")
        current = current.parent


def build(wheel_dir: Path, destination: Path) -> Path:
    verify_accepted_source()
    if destination.exists():
        raise FileExistsError("release staging path already exists; refusing to overwrite it")
    wheels = {path.name: path for path in wheel_dir.iterdir() if path.is_file()}
    if set(wheels) != WHEEL_NAMES or any(p.is_symlink() for p in wheel_dir.iterdir()):
        raise ValueError("offline wheel set differs from the eight reviewed wheels")
    for wheel in wheels.values():
        verify_wheel(wheel)
    lock = (ROOT / "requirements-agent-lock.txt").read_text(encoding="utf-8")
    for wheel in wheels.values():
        if f"sha256:{digest(wheel.read_bytes())}" not in lock:
            raise ValueError("wheel SHA-256 does not match the locked dependency set")

    runtime_archive = ROOT / "dist" / "python-3.13.17-amd64.zip"
    if digest(runtime_archive.read_bytes()) != "b26ca4b4ee51e157836049934d2b8eabd55939be296f3130254251b6df96ec2f":
        raise ValueError("official full Python runtime archive differs")
    sources = agent_source_paths()
    payloads = sorted(sources | {Path("scripts") / name for name in SCRIPT_NAMES}
                      | {Path("requirements-agent-lock.txt")})
    for path in payloads:
        assert_normal_source_file(path)

    destination.mkdir(parents=True)
    try:
        for relative in payloads:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        wheel_target = destination / "wheels"
        wheel_target.mkdir()
        for name, source in sorted(wheels.items()):
            shutil.copyfile(source, wheel_target / name)
        (destination / "runtime").mkdir()
        shutil.copyfile(runtime_archive, destination / "runtime" / runtime_archive.name)
        entries = []
        for path in sorted(destination.rglob("*")):
            if path.is_file():
                relative = path.relative_to(destination).as_posix()
                entries.append({"path": relative, "sha256": digest(path.read_bytes()), "size": path.stat().st_size})
        manifest = {
            "format": 1, "package": "RAVEN-X Enterprise Endpoint Agent", "version": VERSION,
            "source_baseline": BASELINE, "accepted_diff_sha256": ACCEPTED_DIFF,
            "target": "Windows AMD64 / CPython 3.13", "files": entries,
        }
        (destination / "release-manifest.json").write_bytes(
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    except BaseException:
        # Preserve a failed staging tree for inspection; never silently reuse it.
        raise
    return destination


def write_offline_manifest(stage: Path, target: Path) -> None:
    if target.exists():
        raise FileExistsError("offline dependency manifest already exists")
    release = json.loads((stage / "release-manifest.json").read_text(encoding="utf-8"))
    wheels = [entry for entry in release["files"] if entry["path"].startswith("wheels/")]
    if len(wheels) != len(WHEEL_NAMES):
        raise ValueError("release wheel inventory is incomplete")
    lock = next(entry for entry in release["files"] if entry["path"] == "requirements-agent-lock.txt")
    payload = {
        "format": 1, "version": VERSION, "target": "Windows AMD64 / CPython 3.13",
        "requirements_lock_sha256": lock["sha256"], "wheels": wheels,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "release" / f"RAVEN-X-Agent-{VERSION}")
    args = parser.parse_args()
    location = build(args.wheel_dir, args.output)
    write_offline_manifest(location, location.parent / f"{location.name}-offline-dependencies.json")
    print(f"Release stage: {location}")
    print(f"Manifest SHA-256: {digest((location / 'release-manifest.json').read_bytes())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
