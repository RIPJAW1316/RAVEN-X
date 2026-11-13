"""Machine-bound encrypted backup for an installed Windows endpoint agent.

This module never starts, stops, registers, or deletes a Scheduled Task.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

from backend.application.ops.server_backup import (
    _check_path, _create_dir, _custody_metadata,
    _sha, _unwrap_key, _wrap_key, _write,
)


class AgentRecoveryError(RuntimeError):
    pass


class AgentOriginMismatch(AgentRecoveryError):
    pass


class AgentCaMismatch(AgentRecoveryError):
    pass


def _verify_child_custody(path: Path) -> None:
    from backend.infrastructure.security.windows_files import assert_ancestry_not_substitutable
    import win32security
    import ntsecuritycon
    assert_ancestry_not_substitutable(path)
    descriptor = win32security.GetFileSecurity(
        str(path), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    allowed = {"S-1-5-18", "S-1-5-32-544"}
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    dacl = descriptor.GetSecurityDescriptorDacl()
    if owner not in allowed or dacl is None or dacl.GetAceCount() != 2:
        raise AgentRecoveryError("agent child custody is unsafe")
    seen = set()
    for index in range(2):
        header, mask, sid = dacl.GetAce(index)
        identity = win32security.ConvertSidToStringSid(sid)
        if (header[0] != win32security.ACCESS_ALLOWED_ACE_TYPE or identity not in allowed or
                (mask & ntsecuritycon.FILE_ALL_ACCESS) != ntsecuritycon.FILE_ALL_ACCESS or
                (path.is_dir() and not (header[1] & win32security.OBJECT_INHERIT_ACE and
                                        header[1] & win32security.CONTAINER_INHERIT_ACE))):
            raise AgentRecoveryError("agent child grants unexpected access")
        seen.add(identity)
    if seen != allowed:
        raise AgentRecoveryError("agent child lacks protected principals")


def _members(root: Path, prefix: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_junction() or path.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise AgentRecoveryError("agent source contains a reparse point")
        _verify_child_custody(path)
        if path.is_file():
            result[prefix + "/" + path.relative_to(root).as_posix()] = path
    return result


def _task_xml(task_name: str) -> bytes:
    if task_name != "RAVEN-X Endpoint Agent" and not re.fullmatch(r"RAVEN-X WS03C Disposable [0-9a-f]{32}", task_name):
        raise AgentRecoveryError("task name is outside the reviewed set")
    result = subprocess.run(["schtasks.exe", "/Query", "/TN", task_name, "/XML"],
                            capture_output=True, check=False)
    if result.returncode or not result.stdout or len(result.stdout) > 1024 * 1024:
        raise AgentRecoveryError("scheduled task XML is unavailable")
    raw = result.stdout
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw
    # schtasks declares UTF-16 even when redirected stdout uses a single-byte
    # console encoding. Re-encode to the declared format so the archived XML
    # is parseable and remains suitable for a reviewed task restoration.
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("mbcs")
    declaration = re.match(r"\s*<\?xml\s+[^?]*\?>", text, re.IGNORECASE)
    if declaration and re.search(r"encoding\s*=\s*['\"]utf-16['\"]", declaration.group(), re.IGNORECASE):
        return text.encode("utf-16")
    return raw


def _validate_task(xml: bytes, *, install: Path, data: Path, server_url: str) -> None:
    try:
        document = ET.fromstring(xml)
    except ET.ParseError as error:
        raise AgentRecoveryError("scheduled task XML is invalid") from error
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    if document.tag != "{http://schemas.microsoft.com/windows/2004/02/mit/task}Task":
        raise AgentRecoveryError("scheduled task XML has an unexpected root")
    principals = document.findall("./t:Principals/t:Principal", ns)
    actions = document.findall("./t:Actions/t:Exec", ns)
    if len(principals) != 1 or len(actions) != 1 or len(document.findall("./t:Actions/*", ns)) != 1:
        raise AgentRecoveryError("scheduled task has an unexpected principal or action")
    def field(parent: ET.Element, name: str) -> str:
        node = parent.find("t:" + name, ns)
        return (node.text or "") if node is not None else ""
    expected_args = ('-E -s -m backend.agent run --server "' + server_url +
                     '" --ca-cert "' + str(data / "server-ca.pem") +
                     '" --data-dir "' + str(data) + '"')
    if (field(principals[0], "UserId").lower() not in {"system", "s-1-5-18"}
            # Task Scheduler omits the default LogonType when exporting a
            # registered SYSTEM service-account task.
            or field(principals[0], "LogonType") not in {"", "ServiceAccount"}
            or field(principals[0], "RunLevel") != "HighestAvailable"
            or field(actions[0], "Command").lower() != str(install / "venv" / "Scripts" / "python.exe").lower()
            or field(actions[0], "WorkingDirectory").lower() != str(install).lower()
            or field(actions[0], "Arguments") != expected_args):
        raise AgentRecoveryError("scheduled task identity differs")


def inspect(*, install: Path, data: Path, task_name: str,
            expected_server_url: str, expected_ca_sha256: str) -> dict:
    if os.name != "nt":
        raise AgentRecoveryError("agent inspection requires Windows")
    install, data = Path(install).absolute(), Path(data).absolute()
    _check_path(install, directory=True, production=True)
    _check_path(data, directory=True, production=True)
    from backend.agent.windows_store import WindowsAgentStateStore
    record = WindowsAgentStateStore(data).load_record()
    if record is None:
        raise AgentRecoveryError("agent state is unavailable")
    if record.server_url != expected_server_url.rstrip("/"):
        raise AgentOriginMismatch("stored agent origin differs")
    ca = data / "server-ca.pem"
    _check_path(ca, directory=False, production=True)
    ca_hash = _sha(ca.read_bytes())
    if record.ca_sha256 != ca_hash:
        raise AgentRecoveryError("stored CA binding differs")
    if ca_hash != expected_ca_sha256.lower():
        raise AgentCaMismatch("stored CA trust differs")
    _validate_task(_task_xml(task_name), install=install, data=data, server_url=record.server_url)
    files = {**_members(install, "code"), **_members(data, "state")}
    if not {"state/credential.bin", "state/server-ca.pem"} <= files.keys():
        raise AgentRecoveryError("installed agent state is incomplete")
    return {"endpoint_id": str(record.endpoint_id),
            "expires_at": record.credential_expires_at.isoformat(),
            "server_url": record.server_url, "files": len(files)}


def create(*, install: Path, data: Path, destination: Path, task_name: str,
           expected_server_url: str, expected_ca_sha256: str,
           task_xml: bytes | None = None) -> dict:
    if os.name != "nt":
        raise AgentRecoveryError("machine-bound recovery requires Windows")
    install, data, destination = (Path(p).absolute() for p in (install, data, destination))
    if destination.is_relative_to(install) or destination.is_relative_to(data):
        raise AgentRecoveryError("backup must be outside agent code and state")
    _check_path(install, directory=True, production=True)
    _check_path(data, directory=True, production=True)
    from backend.agent.windows_store import WindowsAgentStateStore
    record = WindowsAgentStateStore(data).load_record()
    if record is None or record.server_url != expected_server_url.rstrip("/"):
        raise AgentRecoveryError("stored agent origin differs")
    ca = data / "server-ca.pem"
    _check_path(ca, directory=False, production=True)
    ca_hash = _sha(ca.read_bytes())
    if ca_hash != expected_ca_sha256.lower() or record.ca_sha256 != ca_hash:
        raise AgentRecoveryError("stored CA trust differs")
    xml = task_xml if task_xml is not None else _task_xml(task_name)
    _validate_task(xml, install=install, data=data, server_url=record.server_url)
    files = {**_members(install, "code"), **_members(data, "state")}
    if "state/credential.bin" not in files or "state/server-ca.pem" not in files:
        raise AgentRecoveryError("installed agent state is incomplete")
    for path in files.values():
        _verify_child_custody(path)
    _create_dir(destination, production=True)
    key = secrets.token_bytes(32)
    _write(destination / "dpapi-key.bin", _wrap_key(key), production=True)
    entries = []
    for index, (name, source) in enumerate(sorted(files.items())):
        plain = source.read_bytes()
        nonce = secrets.token_bytes(12)
        encrypted = nonce + AESGCM(key).encrypt(nonce, plain, name.encode())
        member = f"member-{index:05d}.enc"
        _write(destination / member, encrypted, production=True)
        entries.append({"name": name, "member": member, "sha256": _sha(plain),
                        "encrypted_sha256": _sha(encrypted), "size": len(plain),
                        "custody": _custody_metadata(source)})
    nonce = secrets.token_bytes(12)
    encrypted_task = nonce + AESGCM(key).encrypt(nonce, xml, b"task.xml")
    _write(destination / "task.xml.enc", encrypted_task, production=True)
    manifest = {"format": 1, "kind": "ravenx-agent-recovery", "machine_bound": True,
                "task_name": task_name, "task_sha256": _sha(xml),
                "task_encrypted_sha256": _sha(encrypted_task),
                "source_install": str(install), "source_data": str(data),
                "identity": {"endpoint_id": str(record.endpoint_id),
                             "credential_id": str(record.credential_id),
                             "organization_id": record.organization_id,
                             "expires_at": record.credential_expires_at.isoformat(),
                             "server_url": record.server_url, "ca_sha256": ca_hash},
                "install_custody": _custody_metadata(install),
                "data_custody": _custody_metadata(data), "files": entries}
    payload = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _write(destination / "manifest.json", payload, production=True)
    verify(destination)
    return {"verified": True, "files": len(entries), "manifest_sha256": _sha(payload),
            "endpoint_id": str(record.endpoint_id), "expires_at": record.credential_expires_at.isoformat()}


def verify(root: Path) -> dict:
    root = Path(root).absolute()
    _check_path(root, directory=True, production=True)
    manifest_path = root / "manifest.json"
    _check_path(manifest_path, directory=False, production=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != 1 or manifest.get("kind") != "ravenx-agent-recovery":
        raise AgentRecoveryError("agent backup manifest is invalid")
    key_path = root / "dpapi-key.bin"
    _check_path(key_path, directory=False, production=True)
    key = _unwrap_key(key_path.read_bytes())
    expected = set()
    member_names = set()
    for entry in manifest["files"]:
        name, member = entry["name"], entry["member"]
        relative = PurePosixPath(name)
        if (name in expected or member in member_names or relative.is_absolute() or ".." in relative.parts or
                len(relative.parts) < 2 or relative.parts[0] not in {"code", "state"} or
                "\\" in name or ":" in name or
                not re.fullmatch(r"member-[0-9]{5}\.enc", member)):
            raise AgentRecoveryError("agent backup manifest has an unsafe member")
        expected.add(name)
        member_names.add(member)
        path = root / member
        _check_path(path, directory=False, production=True)
        encrypted = path.read_bytes()
        if _sha(encrypted) != entry["encrypted_sha256"]:
            raise AgentRecoveryError("agent backup member changed")
        plain = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], name.encode())
        if _sha(plain) != entry["sha256"] or len(plain) != entry["size"]:
            raise AgentRecoveryError("agent backup member differs")
    if not {"state/credential.bin", "state/server-ca.pem"} <= expected:
        raise AgentRecoveryError("agent backup is incomplete")
    task_path = root / "task.xml.enc"
    _check_path(task_path, directory=False, production=True)
    task = task_path.read_bytes()
    if _sha(task) != manifest["task_encrypted_sha256"]:
        raise AgentRecoveryError("task backup changed")
    xml = AESGCM(key).decrypt(task[:12], task[12:], b"task.xml")
    if _sha(xml) != manifest["task_sha256"]:
        raise AgentRecoveryError("task backup differs")
    _validate_task(xml, install=Path(manifest["source_install"]),
                   data=Path(manifest["source_data"]), server_url=manifest["identity"]["server_url"])
    actual = {p.name for p in root.iterdir()}
    if actual != member_names | {"dpapi-key.bin", "task.xml.enc", "manifest.json"}:
        raise AgentRecoveryError("agent backup inventory differs")
    return {"verified": True, "files": len(expected), "manifest_sha256": _sha(manifest_path.read_bytes())}


_PHASES = ("backup_verified", "task_disabled", "code_archived", "state_archived", "task_removed")


def mark_phase(root: Path, *, phase: str, backup: Path) -> dict:
    if phase not in _PHASES:
        raise AgentRecoveryError("agent transition phase is invalid")
    root = Path(root).absolute()
    backup = Path(backup).absolute()
    _check_path(root, directory=True, production=True)
    if backup.parent != root or not re.fullmatch(r"ws03c-agent-backup-[0-9a-f]{32}", backup.name):
        raise AgentRecoveryError("agent transition backup is outside its protected parent")
    path = root / "ws03c-transition.json"
    if path.exists():
        _check_path(path, directory=False, production=True)
        prior = json.loads(path.read_text(encoding="utf-8"))
        if prior.get("backup") != str(Path(backup).absolute()) or prior.get("phase") not in _PHASES:
            raise AgentRecoveryError("agent transition journal identity differs")
        if _PHASES.index(phase) != _PHASES.index(prior["phase"]) + 1:
            raise AgentRecoveryError("agent transition phase is out of order")
    elif phase != _PHASES[0]:
        raise AgentRecoveryError("agent transition lacks a verified backup")
    if phase == _PHASES[0]:
        verify(backup)
    payload = (json.dumps({"format": 1, "phase": phase, "backup": str(Path(backup).absolute())},
                          sort_keys=True, separators=(",", ":")) + "\n").encode()
    from backend.infrastructure.security.windows_files import atomic_create_protected, atomic_write_protected
    (atomic_write_protected if path.exists() else atomic_create_protected)(path, payload)
    return {"phase": phase, "journal_sha256": _sha(payload)}


def restore_isolated(*, backup: Path, destination: Path) -> dict:
    verified = verify(backup)
    backup, destination = Path(backup).absolute(), Path(destination).absolute()
    if destination.is_relative_to(backup):
        raise AgentRecoveryError("restore must be separate from backup")
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    key = _unwrap_key((backup / "dpapi-key.bin").read_bytes())
    _create_dir(destination, production=True)
    for entry in manifest["files"]:
        relative = PurePosixPath(entry["name"])
        parent = destination
        for part in relative.parts[:-1]:
            parent = parent / part
            if not parent.exists():
                _create_dir(parent, production=True)
        encrypted = (backup / entry["member"]).read_bytes()
        plain = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], entry["name"].encode())
        _write(destination / Path(*relative.parts), plain, production=True)
    task = (backup / "task.xml.enc").read_bytes()
    xml = AESGCM(key).decrypt(task[:12], task[12:], b"task.xml")
    _validate_task(xml, install=Path(manifest["source_install"]),
                   data=Path(manifest["source_data"]), server_url=manifest["identity"]["server_url"])
    _write(destination / "task.xml", xml, production=True)
    from backend.agent.windows_store import WindowsAgentStateStore
    record = WindowsAgentStateStore(destination / "state").load_record()
    identity = manifest["identity"]
    if (record is None or str(record.endpoint_id) != identity["endpoint_id"] or
            str(record.credential_id) != identity["credential_id"] or
            record.organization_id != identity["organization_id"] or
            record.server_url != identity["server_url"] or
            record.credential_expires_at.isoformat() != identity["expires_at"] or
            record.ca_sha256 != identity["ca_sha256"] or
            _sha((destination / "state" / "server-ca.pem").read_bytes()) != identity["ca_sha256"]):
        raise AgentRecoveryError("restored DPAPI agent identity differs")
    return {"restored": True, "files": verified["files"],
            "endpoint_id": identity["endpoint_id"], "server_url": identity["server_url"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Protected same-machine agent recovery backup")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--install", type=Path, required=True)
    create.add_argument("--data", type=Path, required=True)
    create.add_argument("--destination", type=Path, required=True)
    create.add_argument("--task-name", required=True)
    create.add_argument("--expected-server-url", required=True)
    create.add_argument("--expected-ca-sha256", required=True)
    examine = sub.add_parser("inspect")
    examine.add_argument("--install", type=Path, required=True)
    examine.add_argument("--data", type=Path, required=True)
    examine.add_argument("--task-name", required=True)
    examine.add_argument("--expected-server-url", required=True)
    examine.add_argument("--expected-ca-sha256", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--backup", type=Path, required=True)
    restore = sub.add_parser("restore-isolated")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    mark = sub.add_parser("mark")
    mark.add_argument("--root", type=Path, required=True)
    mark.add_argument("--phase", choices=_PHASES, required=True)
    mark.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = globals()["create"](install=args.install, data=args.data,
                destination=args.destination, task_name=args.task_name,
                expected_server_url=args.expected_server_url,
                expected_ca_sha256=args.expected_ca_sha256)
        elif args.command == "inspect":
            result = inspect(install=args.install, data=args.data, task_name=args.task_name,
                expected_server_url=args.expected_server_url,
                expected_ca_sha256=args.expected_ca_sha256)
        elif args.command == "verify":
            result = verify(args.backup)
        elif args.command == "restore-isolated":
            result = restore_isolated(backup=args.backup, destination=args.destination)
        else:
            result = mark_phase(args.root, phase=args.phase, backup=args.backup)
        print(json.dumps(result, sort_keys=True))
        return 0
    except AgentOriginMismatch:
        print("AGENT_ORIGIN_MISMATCH")
        return 20
    except AgentCaMismatch:
        print("AGENT_CA_MISMATCH")
        return 21
    except Exception as error:
        parser.exit(2, "Agent recovery refused: " + type(error).__name__ + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
