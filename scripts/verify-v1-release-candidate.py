"""Verify the exact Windows GitHub release packages in disposable directories."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from uuid import uuid4
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_builder", ROOT / "scripts" / "build-v1-release.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
POWERSHELL = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"


def extract_checked(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len({n.casefold() for n in names}) != len(names):
            raise ValueError("Release archive contains duplicate paths")
        for info in z.infolist():
            name = info.filename
            if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name or ":" in name:
                raise ValueError(f"Unsafe path in {archive.name}")
            if stat_is_link(info):
                raise ValueError(f"Symlink in {archive.name}")
            if archive.suffix == ".zip" and archive.name.startswith("RAVEN-X-"):
                BUILD.scan_for_secrets(z.read(info), name)
        z.extractall(destination)


def stat_is_link(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def run(*argv, cwd, env=None) -> str:
    result = subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env,
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=210)
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} exited {result.returncode}:\n{result.stderr or result.stdout}")
    return result.stdout


def verify_bindings(stage: Path, source_commit: str) -> None:
    manifest = (stage / "release-manifest.json").read_bytes()
    digest = hashlib.sha256(manifest).hexdigest()
    import json
    if json.loads(manifest)["source_commit"] != source_commit:
        raise ValueError("Endpoint installer stage has different source provenance")
    quoted = str(stage).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f". '{quoted}\\scripts\\release-integrity.ps1'; "
        f"Assert-ReleaseManifestFiles '{quoted}' -ExpectedManifestSha256 '{digest}' | Out-Null"
    )
    run(POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command, cwd=stage)
    print("Endpoint stage matches the pinned v1 manifest and verifier.")


def smoke_admin(root: Path, runtime: Path) -> None:
    python_zip = root / "runtime" / BUILD.PYTHON_ARCHIVE
    if BUILD.sha256_file(python_zip) != BUILD.PYTHON_SHA256:
        raise ValueError("Bundled CPython hash differs from the trusted archive")
    extract_checked(python_zip, runtime)
    base = runtime / "python.exe"
    sign_path = str(base).replace("'", "''")
    command = (
        f"$signature=Get-AuthenticodeSignature -LiteralPath '{sign_path}'; "
        "if ($signature.Status -ne 'Valid' -or "
        "$signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {exit 1}"
    )
    run(POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command, cwd=runtime)
    env = {name: value for name, value in os.environ.items() if not name.upper().startswith("RAVENX_")}
    env.update(PYTHONUTF8="1", RAVENX_ENVIRONMENT="development", RAVENX_DATABASE_PATH=":memory:",
               RAVENX_VERIFIER_KEY_MODE="ephemeral", RAVENX_ENABLE_LEGACY_ROUTES="false",
               RAVENX_SERVE_FRONTEND="true", RAVENX_CLOUD_GEMINI_ENABLED="false")

    venv = root / "venv"
    run(base, "-B", "-I", "-m", "venv", venv, cwd=root, env=env)
    python = venv / "Scripts" / "python.exe"
    pip = (python, "-B", "-I", "-m", "pip", "--isolated", "--disable-pip-version-check")
    run(*pip, "install", "--no-index", "--no-cache-dir", "--require-hashes", "--only-binary=:all:",
        "--find-links", root / "wheels", "-r", root / "requirements-server-lock.txt", cwd=root, env=env)
    run(*pip, "check", cwd=root, env=env)
    print("Fresh Windows runtime and locked admin wheels installed from the ZIP offline.")

    probe = """
import re
from fastapi.testclient import TestClient
from backend.api.main import app
from backend.application.reporting import fleet_pdf
with TestClient(app, base_url="https://testserver") as client:
    assert client.get("/health").json()["status"] == "healthy"
    assert client.get("/ready").json()["status"] == "ready"
    portal = client.get("/")
    assert portal.status_code == 200
    paths = re.findall(r'(?:src|href)="(/assets/[^"]+)"', portal.text)
    assert paths and all(client.get(path).status_code == 200 for path in paths)
"""
    run(python, "-B", "-E", "-s", "-c", probe, cwd=root, env=env)
    print("Extracted backend starts, reaches readiness, imports PDF reporting, and serves portal assets.")

    target = "RAVEN-X/ReleaseVerification/" + uuid4().hex
    store = """
import sys
from backend.infrastructure.security.windows_credentials import Win32CredStore
store = Win32CredStore(sys.argv[1])
"""
    command = (python, "-B", "-E", "-s", "-c")
    try:
        run(*command, store + 'assert not store.get_status()["configured"]; store.set_key("fixture-only-v1")',
            target, cwd=root, env=env)
        run(*command, store + 'assert store.get_key() == "fixture-only-v1"; store.set_key("fixture-only-v2")',
            target, cwd=root, env=env)
        run(*command, store + 'assert store.get_key() == "fixture-only-v2"', target, cwd=root, env=env)
    finally:
        run(*command, store + "store.delete_key(); assert store.get_key() is None", target, cwd=root, env=env)
    print("Windows Credential Manager passed process-restart and rotation checks with an isolated dummy key.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    artifacts = args.artifact_dir.resolve(strict=True)
    commit = BUILD.git("rev-parse", "HEAD").decode("ascii").strip()
    admin = artifacts / f"RAVEN-X-Admin-Portal-v{BUILD.VERSION}.zip"
    endpoint = artifacts / f"RAVEN-X-Endpoint-v{BUILD.VERSION}.zip"
    for archive in (admin, endpoint):
        result = BUILD.verify_package(archive, commit)
        print(f"{archive.name} contains {result['manifest_entries']} verified members.")
    with tempfile.TemporaryDirectory(prefix="ravenx-release-verification-") as temporary:
        test_root = Path(temporary)
        admin_root = test_root / "admin"
        extract_checked(admin, admin_root)
        extract_checked(endpoint, test_root / "endpoint")
        for name in (f"RAVEN-X-Windows-Setup-v{BUILD.VERSION}.exe", "ClientRemoval.exe"):
            if not (test_root / "endpoint" / name).read_bytes().startswith(b"MZ"):
                raise ValueError(f"{name} is not a Windows executable")
        verify_bindings(artifacts / "release" / f"RAVEN-X-Agent-{BUILD.VERSION}", commit)
        smoke_admin(admin_root, test_root / "runtime")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
