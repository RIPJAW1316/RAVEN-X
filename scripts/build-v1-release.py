"""Build official v1.0.0 release artifacts for RAVEN-X.

Generates two standalone release packages:
1. dist/RAVEN-X-Admin-Portal-v1.0.0.zip (+ .sha256)
2. dist/RAVEN-X-Endpoint-v1.0.0.zip (+ .sha256)
"""

from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()
SIGNING_STATUS = "unsigned"
PYTHON_ARCHIVE = "python-3.13.17-amd64.zip"
PYTHON_SHA256 = "b26ca4b4ee51e157836049934d2b8eabd55939be296f3130254251b6df96ec2f"

SERVER_DIRECT_DEPENDENCIES = {
    "fastapi": "0.118.0",
    "uvicorn": "0.38.0",
    "sqlalchemy": "2.0.45",
    "aiosqlite": "0.21.0",
    "pyyaml": "6.0.3",
    "httpx": "0.28.1",
    "pydantic": "2.12.5",
    "cryptography": "50.0.2",
    "reportlab": "4.4.9",
    "pywin32": "312",
}

AGENT_WHEEL_NAMES = frozenset({
    "anyio-4.16.0-py3-none-any.whl",
    "certifi-2026.10.23-py3-none-any.whl",
    "h11-0.16.0-py3-none-any.whl",
    "httpcore-1.0.9-py3-none-any.whl",
    "httpx-0.28.1-py3-none-any.whl",
    "idna-3.20-py3-none-any.whl",
    "pywin32-312-cp313-cp313-win_amd64.whl",
    "typing_extensions-4.16.0-py3-none-any.whl",
})

SERVER_SCRIPTS = (
    "manage-gemini-credentials.ps1",
    "server-runtime.ps1",
    "backup-server-ws03.ps1",
    "managed-python.ps1",
    "release-integrity.ps1",
)

AGENT_SCRIPTS = (
    "install-agent.ps1",
    "setup-agent.ps1",
    "runtime-selection.ps1",
    "managed-python.ps1",
    "release-integrity.ps1",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def assert_safe_path(path: Path) -> None:
    if not path.is_relative_to(ROOT):
        raise ValueError("Build source escaped the checkout")
    current = path
    while current != ROOT:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f"Encountered reparse point in path: {path}")
        current = current.parent


def get_wheel_identity(path: Path) -> tuple[str, str]:
    if path.suffix != ".whl" or path.is_symlink():
        raise ValueError(f"Not a valid wheel: {path}")
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError(f"Corrupt wheel archive: {path}")
        names = archive.namelist()
        if len(names) != len(set(names)) or any(
            PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or
            "\\" in name or ":" in name for name in names
        ):
            raise ValueError(f"Wheel contains duplicate or unsafe paths: {path}")
        metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError(f"Ambiguous or missing METADATA in wheel: {path}")
        record = BytesParser().parsebytes(archive.read(metadata_names[0]))
    name, version = record.get("Name"), record.get("Version")
    if not name or not version:
        raise ValueError(f"Invalid METADATA in wheel: {path}")
    return name.lower().replace("_", "-"), version


def get_agent_source_paths() -> set[Path]:
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
            raise ValueError(f"Agent import escaped backend: {path}")
        relative = path.relative_to(ROOT)
        if relative.parts[1] in {"api", "core"} or relative.name == "legacy_adapters.py":
            raise ValueError(f"Agent imported forbidden component: {relative}")
        paths.add(relative)
    paths.add(Path("backend/agent/__main__.py"))
    return paths


def scan_for_secrets(data: bytes, filename: str) -> None:
    forbidden_patterns = [
        re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        re.compile(rb"AIza[0-9A-Za-z-_]{35}"),
        re.compile(rb"ya29\.[0-9A-Za-z-_]+"),
        re.compile(rb"AKIA[0-9A-Z]{16}"),
    ]
    for pattern in forbidden_patterns:
        if pattern.search(data):
            raise ValueError(f"Security scan detected credential pattern in release asset: {filename}")


def build_admin_portal_zip(wheel_dir: Path, python_zip: Path, csc_path: Path,
                           output_zip: Path, source_commit: str) -> dict:
    print(f"\n[1/4] Building Admin Portal Release Package v{VERSION}...")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, bytes] = {}

    # 1. Compile portable RAVEN-X-Server.exe launcher
    print("  -> Compiling portable RAVEN-X-Server.exe GUI launcher...")
    server_launcher_cs = ROOT / "scripts" / "pilot" / "OmenServerLauncher.cs"
    server_launcher_exe = output_zip.parent / "RAVEN-X-Server.exe"
    csc_cmd = [
        str(csc_path),
        "/nologo",
        "/target:winexe",
        "/platform:x64",
        "/define:RAVENX_RELEASE",
        "/optimize+",
        "/reference:System.Windows.Forms.dll",
        "/reference:System.Drawing.dll",
        f"/out:{server_launcher_exe}",
        f"/win32manifest:{server_launcher_cs.with_suffix('.manifest')}",
        str(server_launcher_cs),
    ]
    csc_res = subprocess.run(csc_cmd, capture_output=True, text=True)
    if csc_res.returncode != 0:
        raise RuntimeError(f"CSC failed compiling server launcher:\n{csc_res.stdout}\n{csc_res.stderr}")

    server_exe_bytes = server_launcher_exe.read_bytes()
    payload["RAVEN-X-Server.exe"] = server_exe_bytes
    print(f"  -> Built launcher: RAVEN-X-Server.exe ({len(server_exe_bytes):,} bytes)")

    # 2. Backend python files
    for name in git("ls-files", "-z", "--", "backend").decode("utf-8").split("\0"):
        if not name.endswith(".py"):
            continue
        path = ROOT / name
        assert_safe_path(path)
        rel = path.relative_to(ROOT).as_posix()
        data = path.read_bytes()
        scan_for_secrets(data, rel)
        payload[rel] = data

    # 3. Frontend dist assets
    frontend_dist = ROOT / "frontend" / "dist"
    if not (frontend_dist / "index.html").is_file():
        raise FileNotFoundError("Frontend dist is missing. Run npm run build first.")
    for path in frontend_dist.rglob("*"):
        if path.is_file():
            assert_safe_path(path)
            rel = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            scan_for_secrets(data, rel)
            payload[rel] = data

    # 4. Server configuration
    cfg = ROOT / "config" / "config.yaml"
    assert_safe_path(cfg)
    payload["config/config.yaml"] = cfg.read_bytes()

    # 5. Server wheels and the offline Python runtime.
    lock_path = ROOT / "requirements-server-lock.txt"
    lock = {line for line in lock_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")}
    server_wheels = sorted(wheel_dir.glob("*.whl"))
    if len(server_wheels) != len(lock):
        raise ValueError(f"Server wheelhouse must contain the {len(lock)} pinned wheels")

    identities = {}
    lock_lines = []
    for wheel in server_wheels:
        name, ver = get_wheel_identity(wheel)
        if name in identities:
            raise ValueError(f"Duplicate wheel in wheelhouse: {name}")
        identities[name] = ver
        data = wheel.read_bytes()
        payload[f"wheels/{wheel.name}"] = data
        lock_lines.append(f"{name}=={ver} --hash=sha256:{sha256_bytes(data)}")

    for req_name, req_ver in SERVER_DIRECT_DEPENDENCIES.items():
        if identities.get(req_name) != req_ver:
            raise ValueError(f"Server wheelhouse missing pinned dependency {req_name}=={req_ver}")
    if set(lock_lines) != lock:
        raise ValueError("Server wheelhouse does not match the committed dependency hashes")

    payload["requirements-server.txt"] = (ROOT / "requirements-server.txt").read_bytes()
    payload["requirements-server-lock.txt"] = lock_path.read_bytes()
    payload[f"runtime/{PYTHON_ARCHIVE}"] = python_zip.read_bytes()

    # 6. Server scripts
    for script_name in SERVER_SCRIPTS:
        script_path = ROOT / "scripts" / script_name
        if not script_path.is_file():
            raise FileNotFoundError(f"Missing required server script: {script_name}")
        assert_safe_path(script_path)
        data = script_path.read_bytes()
        scan_for_secrets(data, script_name)
        payload[f"scripts/{script_name}"] = data

    # 6b. Pilot lifecycle runner script
    pilot_script = ROOT / "scripts" / "pilot" / "Start-Omen-College-Pilot.ps1"
    assert_safe_path(pilot_script)
    payload["scripts/pilot/Start-Omen-College-Pilot.ps1"] = pilot_script.read_bytes()

    # 7. Walkthrough & Version
    walkthrough = ROOT / "ADMINISTRATOR_WALKTHROUGH.md"
    assert_safe_path(walkthrough)
    payload["ADMINISTRATOR_WALKTHROUGH.md"] = walkthrough.read_bytes()
    payload["VERSION"] = f"{VERSION}\n".encode("utf-8")

    # 8. Release manifest
    files_entry = [
        {"path": path, "sha256": sha256_bytes(data), "size": len(data)}
        for path, data in sorted(payload.items())
    ]
    manifest = {
        "format": 1,
        "product": "RAVEN-X Enterprise Server",
        "version": VERSION,
        "target": "Windows AMD64 / CPython 3.13",
        "source_commit": source_commit,
        "signing_status": SIGNING_STATUS,
        "files": files_entry,
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    payload["release-manifest.json"] = manifest_bytes

    # Create ZIP
    with zipfile.ZipFile(output_zip, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, data in sorted(payload.items()):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 20, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)

    pkg_hash = sha256_file(output_zip)
    sha_file = output_zip.with_suffix(output_zip.suffix + ".sha256")
    sha_file.write_text(f"{pkg_hash}  {output_zip.name}\n", encoding="ascii")

    print(f"  -> Built {output_zip.name}: {output_zip.stat().st_size:,} bytes")
    print(f"  -> SHA-256: {pkg_hash}")
    return {"path": str(output_zip), "sha256": pkg_hash, "size": output_zip.stat().st_size, "files": len(payload)}


def build_endpoint_zip(
    agent_wheels_dir: Path,
    python_zip: Path,
    iscc_path: Path,
    csc_path: Path,
    output_zip: Path,
    source_commit: str,
) -> dict:
    print(f"\n[2/4] Building Endpoint Release Package v{VERSION}...")
    dist_dir = output_zip.parent
    dist_dir.mkdir(parents=True, exist_ok=True)
    # 1. Stage agent payload for Inno Setup compiler
    stage_dir = dist_dir / "release" / f"RAVEN-X-Agent-{VERSION}"
    stage_dir.mkdir(parents=True)

    # 1a. Copy agent source files
    agent_sources = get_agent_source_paths()
    for rel_path in agent_sources:
        src = ROOT / rel_path
        assert_safe_path(src)
        dst = stage_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        scan_for_secrets(data, rel_path.as_posix())
        dst.write_bytes(data)

    # 1b. Copy agent scripts
    for script_name in AGENT_SCRIPTS:
        src = ROOT / "scripts" / script_name
        dst = stage_dir / "scripts" / script_name
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        scan_for_secrets(data, script_name)
        dst.write_bytes(data)

    # 1c. Copy agent wheels
    wheels_dst = stage_dir / "wheels"
    wheels_dst.mkdir(parents=True, exist_ok=True)
    agent_wheels = sorted(agent_wheels_dir.glob("*.whl"))
    if set(w.name for w in agent_wheels) != AGENT_WHEEL_NAMES:
        raise ValueError("Agent wheelhouse does not match expected 8 wheels")
    for wheel in agent_wheels:
        shutil.copy2(wheel, wheels_dst / wheel.name)

    # 1d. Copy python runtime
    runtime_dst = stage_dir / "runtime"
    runtime_dst.mkdir(parents=True, exist_ok=True)
    shutil.copy2(python_zip, runtime_dst / python_zip.name)

    # 1e. Copy requirements-agent-lock.txt
    shutil.copy2(ROOT / "requirements-agent-lock.txt", stage_dir / "requirements-agent-lock.txt")

    # 1f. Generate stage manifest
    stage_entries = []
    for path in sorted(stage_dir.rglob("*")):
        if path.is_file():
            rel = path.relative_to(stage_dir).as_posix()
            data = path.read_bytes()
            stage_entries.append({"path": rel, "sha256": sha256_bytes(data), "size": len(data)})

    stage_manifest = {
        "format": 1,
        "package": "RAVEN-X Enterprise Endpoint Agent",
        "version": VERSION,
        "source_commit": source_commit,
        "target": "Windows AMD64 / CPython 3.13",
        "signing_status": SIGNING_STATUS,
        "files": stage_entries,
    }
    (stage_dir / "release-manifest.json").write_bytes(
        (json.dumps(stage_manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    )
    print(f"  -> Staged agent payload: {len(stage_entries)} files")

    # 2. Compile Inno Setup Windows installer
    print("  -> Compiling Inno Setup Windows installer...")
    iss_script = ROOT / "scripts" / "RAVEN-X-Windows-Setup.iss"
    setup_basename = f"RAVEN-X-Windows-Setup-v{VERSION}"
    iscc_cmd = [
        str(iscc_path),
        f"/DReleaseVersion={VERSION}",
        f"/DStageRoot={stage_dir}",
        f"/F{setup_basename}",
        f"/O{dist_dir}",
        str(iss_script),
    ]
    result = subprocess.run(iscc_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ISCC failed with code {result.returncode}:\n{result.stdout}\n{result.stderr}")
    setup_exe = dist_dir / f"{setup_basename}.exe"
    if not setup_exe.is_file():
        raise FileNotFoundError(f"Expected setup executable not found: {setup_exe}")
    print(f"  -> Built installer: {setup_exe.name} ({setup_exe.stat().st_size:,} bytes)")

    # 3. Compile ClientRemoval.exe
    print("  -> Compiling ClientRemoval.exe C# GUI wrapper...")
    client_removal_exe = dist_dir / "ClientRemoval.exe"
    removal_cs = ROOT / "scripts" / "ClientRemoval.cs"
    removal_ps1 = ROOT / "scripts" / "Remove-RavenXClient.ps1"
    csc_cmd = [
        str(csc_path),
        "/nologo",
        "/target:winexe",
        f"/out:{client_removal_exe}",
        f"/resource:{removal_ps1},cleanup",
        f"/win32manifest:{removal_cs.with_suffix('.manifest')}",
        "/platform:x64",
        str(removal_cs),
    ]
    csc_result = subprocess.run(csc_cmd, capture_output=True, text=True)
    if csc_result.returncode != 0:
        raise RuntimeError(f"CSC failed with code {csc_result.returncode}:\n{csc_result.stdout}\n{csc_result.stderr}")
    print(f"  -> Built removal executable: {client_removal_exe.name} ({client_removal_exe.stat().st_size:,} bytes)")

    # 4. Assemble Endpoint Release ZIP
    payload: dict[str, bytes] = {}
    payload[setup_exe.name] = setup_exe.read_bytes()
    payload["Remove-RavenXClient.ps1"] = removal_ps1.read_bytes()
    payload["ClientRemoval.exe"] = client_removal_exe.read_bytes()
    payload["ClientRemoval.cs"] = removal_cs.read_bytes()
    payload["ENDPOINT_USER_WALKTHROUGH.md"] = (ROOT / "ENDPOINT_USER_WALKTHROUGH.md").read_bytes()
    payload["VERSION"] = f"{VERSION}\n".encode("utf-8")

    # Add offline wheels & python runtime into package
    for wheel in agent_wheels:
        payload[f"wheels/{wheel.name}"] = wheel.read_bytes()
    payload[f"runtime/{python_zip.name}"] = python_zip.read_bytes()
    payload["requirements-agent-lock.txt"] = (ROOT / "requirements-agent-lock.txt").read_bytes()

    # Manifest
    files_entry = [
        {"path": path, "sha256": sha256_bytes(data), "size": len(data)}
        for path, data in sorted(payload.items())
    ]
    manifest = {
        "format": 1,
        "product": "RAVEN-X Enterprise Endpoint Agent",
        "version": VERSION,
        "target": "Windows AMD64 / CPython 3.13",
        "source_commit": source_commit,
        "signing_status": SIGNING_STATUS,
        "files": files_entry,
    }
    payload["release-manifest.json"] = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    with zipfile.ZipFile(output_zip, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, data in sorted(payload.items()):
            info = zipfile.ZipInfo(path, date_time=(2026, 11, 20, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)

    pkg_hash = sha256_file(output_zip)
    sha_file = output_zip.with_suffix(output_zip.suffix + ".sha256")
    sha_file.write_text(f"{pkg_hash}  {output_zip.name}\n", encoding="ascii")

    print(f"  -> Built {output_zip.name}: {output_zip.stat().st_size:,} bytes")
    print(f"  -> SHA-256: {pkg_hash}")
    return {"path": str(output_zip), "sha256": pkg_hash, "size": output_zip.stat().st_size, "files": len(payload)}


def verify_package(zip_path: Path, source_commit: str) -> dict:
    print(f"  -> Verifying integrity of {zip_path.name}...")
    sha_file = zip_path.with_suffix(zip_path.suffix + ".sha256")
    expected_hash = sha_file.read_text(encoding="ascii").split()[0]
    actual_hash = sha256_file(zip_path)
    if actual_hash != expected_hash:
        raise ValueError(f"Hash mismatch on {zip_path.name}: {actual_hash} != {expected_hash}")

    with zipfile.ZipFile(zip_path, "r") as archive:
        if archive.testzip() is not None:
            raise ValueError(f"Corrupt member in {zip_path.name}")
        manifest = json.loads(archive.read("release-manifest.json").decode("utf-8"))
        if manifest["source_commit"] != source_commit or manifest["version"] != VERSION:
            raise ValueError(f"Source commit or version mismatch in {zip_path.name}")
        names = archive.namelist()
        if len(names) != len({name.casefold() for name in names}) or set(names) != (
            {entry["path"] for entry in manifest["files"]} | {"release-manifest.json"}
        ):
            raise ValueError(f"Unexpected package inventory in {zip_path.name}")
        for item in manifest["files"]:
            data = archive.read(item["path"])
            if sha256_bytes(data) != item["sha256"]:
                raise ValueError(f"Member hash mismatch in {zip_path.name}: {item['path']}")
            if len(data) != item["size"]:
                raise ValueError(f"Member size mismatch in {zip_path.name}: {item['path']}")
    return {"status": "verified", "manifest_entries": len(manifest["files"])}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build release packages from a clean Windows checkout.")
    parser.add_argument("--server-wheels", type=Path, required=True)
    parser.add_argument("--agent-wheels", type=Path, required=True)
    parser.add_argument("--python-zip", type=Path, required=True)
    parser.add_argument("--iscc", type=Path, required=True, help="Inno Setup compiler executable")
    parser.add_argument("--csc", type=Path, required=True, help=".NET Framework C# compiler executable")
    parser.add_argument("--npm", type=Path, required=True, help="npm.cmd for building the locked frontend")
    parser.add_argument("--output", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    if sys.platform != "win32" or sys.version_info[:2] != (3, 13):
        parser.error("use Windows CPython 3.13")
    if git("status", "--porcelain"):
        parser.error("commit the release source and build from a clean checkout")
    source_commit = git("rev-parse", "HEAD").decode("ascii").strip()
    if args.python_zip.name != PYTHON_ARCHIVE or sha256_file(args.python_zip) != PYTHON_SHA256:
        parser.error("bundled Python archive does not match its pinned name and digest")
    output = args.output.resolve()
    output.mkdir(parents=True)
    frontend = ROOT / "frontend"
    for command in (["ci", "--no-audit", "--no-fund"], ["run", "build"]):
        subprocess.run([str(args.npm.resolve(strict=True)), *command], cwd=frontend, check=True)
    if git("status", "--porcelain"):
        parser.error("frontend build changed the committed source")

    server_zip = output / f"RAVEN-X-Admin-Portal-v{VERSION}.zip"
    endpoint_zip = output / f"RAVEN-X-Endpoint-v{VERSION}.zip"
    admin_res = build_admin_portal_zip(args.server_wheels, args.python_zip, args.csc, server_zip, source_commit)
    endpoint_res = build_endpoint_zip(args.agent_wheels, args.python_zip, args.iscc, args.csc, endpoint_zip, source_commit)

    print("\n[3/4] Verifying generated release ZIPs...")
    v_admin = verify_package(server_zip, source_commit)
    v_endpoint = verify_package(endpoint_zip, source_commit)
    print(f"  -> Admin package: {v_admin['status']} ({v_admin['manifest_entries']} verified files)")
    print(f"  -> Endpoint package: {v_endpoint['status']} ({v_endpoint['manifest_entries']} verified files)")

    print("\n[4/4] Release Build Summary:")
    print(f"  Admin Portal: {admin_res['path']}")
    print(f"    Size:       {admin_res['size']:,} bytes")
    print(f"    SHA-256:    {admin_res['sha256']}")
    print(f"  Endpoint:     {endpoint_res['path']}")
    print(f"    Size:       {endpoint_res['size']:,} bytes")
    print(f"    SHA-256:    {endpoint_res['sha256']}")
    print("\nBuild complete successfully!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
