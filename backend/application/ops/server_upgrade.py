"""Small fail-closed primitives for the WS-03 PowerShell upgrade driver."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import time


_PHASES = ("backup_verified", "migrated", "key_bound", "code_switched", "ready")
_JOURNAL = "ws03-upgrade-state.json"


def _journal_path(data_root: Path, *, production: bool) -> Path:
    path = Path(data_root).absolute()
    if os.name == "nt":
        from backend.infrastructure.security.windows_files import verify_directory, verify_private_directory
        (verify_directory if production else verify_private_directory)(path)
    return path / _JOURNAL


def mark_phase(data_root: Path, *, phase: str, package_sha256: str, backup_path: str,
               production: bool = True) -> dict:
    if phase not in _PHASES:
        raise ValueError("upgrade phase is invalid")
    if len(package_sha256) != 64 or any(c not in "0123456789abcdef" for c in package_sha256.lower()):
        raise ValueError("upgrade package digest is invalid")
    path = _journal_path(data_root, production=production)
    if path.exists():
        if os.name == "nt":
            from backend.infrastructure.security.windows_files import verify_protected_file, verify_verifier_key_custody
            if production:
                verify_protected_file(path)
            else:
                verify_verifier_key_custody(path, production=False)
        previous = json.loads(path.read_text(encoding="utf-8"))
        if (previous.get("package_sha256") != package_sha256.lower()
                or previous.get("backup_path") != backup_path):
            raise ValueError("upgrade journal identity differs")
        index = _PHASES.index(previous["phase"])
        if phase != _PHASES[min(index + 1, len(_PHASES) - 1)]:
            raise ValueError("upgrade phase transition is invalid")
    elif phase != _PHASES[0]:
        raise ValueError("upgrade journal must begin with verified backup")
    payload = {"format": 1, "phase": phase, "package_sha256": package_sha256.lower(),
               "backup_path": backup_path}
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if os.name == "nt":
        if production:
            from backend.infrastructure.security.windows_files import atomic_create_protected, atomic_write_protected
            (atomic_write_protected if path.exists() else atomic_create_protected)(path, data)
        else:
            path.write_bytes(data)
            from backend.infrastructure.security.windows_files import protect_private_secret_file
            protect_private_secret_file(path)
    else:
        if path.exists():
            path.write_bytes(data)
        else:
            with path.open("xb") as output:
                output.write(data)
    return {"phase": phase, "journal_sha256": hashlib.sha256(data).hexdigest()}


def key_check(database: Path) -> dict:
    from backend.infrastructure.security.verifier_key import prepare_persistent_verifier_key, verifier_key_id
    key = prepare_persistent_verifier_key(database, environment="production")
    return {"verifier_key_id": verifier_key_id(key), "bound": True}


def readiness(*, lan_address: str, port: int, ca_path: Path, timeout: float = 25.0) -> dict:
    from backend.application.ops.listeners import validated_hosts
    import httpx
    import ssl
    hosts = validated_hosts(["127.0.0.1", lan_address], ca_path.parent / "server.pem")
    context = ssl.create_default_context(cafile=str(ca_path))
    deadline = time.monotonic() + timeout
    last_error = "not_ready"
    while time.monotonic() < deadline:
        try:
            with httpx.Client(verify=context, trust_env=False, timeout=2.0) as client:
                for host in hosts:
                    response = client.get(f"https://{host}:{port}/ready")
                    if response.status_code != 200 or response.json().get("status") != "ready":
                        raise RuntimeError("server did not report ready")
            return {"ready": True, "listeners": list(hosts)}
        except (httpx.HTTPError, RuntimeError, ValueError) as error:
            last_error = type(error).__name__
            time.sleep(0.25)
    raise RuntimeError("TLS readiness failed: " + last_error)


def main() -> int:
    parser = argparse.ArgumentParser(description="RAVEN-X WS-03 upgrade gates")
    sub = parser.add_subparsers(dest="command", required=True)
    key = sub.add_parser("key-check")
    key.add_argument("--database", type=Path, required=True)
    mark = sub.add_parser("mark")
    mark.add_argument("--data-root", type=Path, required=True)
    mark.add_argument("--phase", choices=_PHASES, required=True)
    mark.add_argument("--package-sha256", required=True)
    mark.add_argument("--backup-path", required=True)
    ready = sub.add_parser("ready")
    ready.add_argument("--lan-address", required=True)
    ready.add_argument("--port", type=int, default=8443)
    ready.add_argument("--ca", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "key-check":
            result = key_check(args.database)
        elif args.command == "mark":
            result = mark_phase(args.data_root, phase=args.phase,
                                package_sha256=args.package_sha256, backup_path=args.backup_path)
        else:
            result = readiness(lan_address=args.lan_address, port=args.port, ca_path=args.ca)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        parser.exit(2, f"RAVEN-X upgrade gate refused: {type(error).__name__}\n")


if __name__ == "__main__":
    raise SystemExit(main())
