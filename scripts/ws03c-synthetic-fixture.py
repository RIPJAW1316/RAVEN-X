"""Build an inert Windows agent fixture inside a protected disposable root."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

# The launcher executes this verified release file by absolute path. Resolve
# imports from that release, independently of the caller's working directory.
_release_root = Path(__file__).resolve().parents[1]
if not (_release_root / "release-manifest.json").is_file():
    raise RuntimeError("synthetic fixture is outside a release tree")
sys.path.insert(0, str(_release_root))

from backend.agent.windows_store import AgentRecord, DpapiMachineProtector
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.infrastructure.security.windows_files import (
    atomic_create_protected, protect_directory, protect_secret_file, verify_directory,
)


def create(root: Path, base_python: Path) -> dict:
    root = root.absolute()
    expected_parent = Path(os.environ["PROGRAMDATA"]) / "RAVEN-X"
    if (os.name != "nt" or root.parent != expected_parent or
            not re.fullmatch(r"ws03c-disposable-[0-9a-f]{32}", root.name)):
        raise ValueError("fixture path is outside protected disposable storage")
    verify_directory(root)
    install_parent = protect_directory(root / "Program Files")
    install_parent = protect_directory(install_parent / "RavenX")
    install = protect_directory(install_parent / "Agent")
    data_parent = protect_directory(root / "ProgramData")
    data_parent = protect_directory(data_parent / "RavenX")
    data = protect_directory(data_parent / "agent")
    protect_directory(root / "backups")
    protect_directory(root / "restores")
    subprocess.run([str(base_python), "-I", "-m", "venv", str(install / "venv")], check=True)
    for child in sorted((install / "venv").rglob("*"), key=lambda p: len(p.parts)):
        if child.is_symlink() or child.is_junction():
            raise ValueError("synthetic runtime contains a reparse point")
        (protect_directory if child.is_dir() else protect_secret_file)(child)
    protect_directory(install / "venv")
    code = protect_directory(install / "backend")
    agent = protect_directory(code / "agent")
    atomic_create_protected(code / "__init__.py", b"")
    atomic_create_protected(agent / "__init__.py", b"")
    # Inert task action: records SYSTEM execution in disposable protected state.
    action = ("import argparse, pathlib, subprocess\n"
              "p=argparse.ArgumentParser(); p.add_argument('run'); p.add_argument('--server'); "
              "p.add_argument('--ca-cert'); p.add_argument('--data-dir'); a=p.parse_args()\n"
              "u=subprocess.check_output(['whoami'],text=True).strip()\n"
              "pathlib.Path(a.data_dir,'system-execution.txt').write_text(u,encoding='utf-8')\n")
    atomic_create_protected(agent / "__main__.py", action.encode())
    atomic_create_protected(install / "VERSION", b"synthetic-ws03c\n")
    ca = b"-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDLVdTMDND\n-----END CERTIFICATE-----\n"
    ca_hash = hashlib.sha256(ca).hexdigest()
    atomic_create_protected(data / "server-ca.pem", ca)
    endpoint = EndpointId(str(uuid4()))
    credential = CredentialId(str(uuid4()))
    origin = "https://127.0.0.1:28444"
    record = AgentRecord(endpoint, credential, "S" * 48, str(uuid4()), "1.0",
                         datetime.now(timezone.utc) - timedelta(days=1), origin, ca_hash)
    atomic_create_protected(data / "credential.bin", DpapiMachineProtector().protect(record.to_json_bytes()))
    outbox = protect_directory(data / "outbox")
    atomic_create_protected(outbox / "pending.json", b'{"synthetic":"pending-evidence"}\n')
    return {"endpoint_id": str(endpoint), "origin": origin, "ca_sha256": ca_hash,
            "task_name": "RAVEN-X WS03C Disposable " + root.name.rsplit("-", 1)[-1],
            "install": str(install), "data": str(data), "synthetic": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base-python", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create(args.root, args.base_python), sort_keys=True))
        return 0
    except Exception as error:
        parser.exit(2, "Synthetic fixture refused: " + type(error).__name__ + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
