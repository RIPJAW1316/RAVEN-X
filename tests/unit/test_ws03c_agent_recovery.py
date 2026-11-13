from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import secrets
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.application.ops import agent_recovery
from backend.application.ops.agent_recovery import AgentRecoveryError, _validate_task


INSTALL = Path(r"C:\ProgramData\RAVEN-X\ws03c-disposable-" + "a" * 32 + r"\Program Files\RavenX\Agent")
DATA = Path(r"C:\ProgramData\RAVEN-X\ws03c-disposable-" + "a" * 32 + r"\ProgramData\RavenX\agent")
ORIGIN = "https://127.0.0.1:28444"


def task_xml(*, principal="SYSTEM", logon="ServiceAccount", run_level="HighestAvailable",
             command=None, args=None, extra_action="") -> bytes:
    command = command or str(INSTALL / "venv" / "Scripts" / "python.exe")
    args = args or (f'-E -s -m backend.agent run --server "{ORIGIN}" '
                    f'--ca-cert "{DATA / "server-ca.pem"}" --data-dir "{DATA}"')
    return (f'<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            f'<Principals><Principal><UserId>{principal}</UserId><LogonType>{logon}</LogonType>'
            f'<RunLevel>{run_level}</RunLevel></Principal></Principals>'
            f'<Actions><Exec><Command>{command}</Command><Arguments>{args}</Arguments>'
            f'<WorkingDirectory>{INSTALL}</WorkingDirectory></Exec>{extra_action}</Actions></Task>').encode()


def test_exact_system_task_accepted():
    _validate_task(task_xml(), install=INSTALL, data=DATA, server_url=ORIGIN)


def test_exported_system_task_may_omit_default_logon_type():
    _validate_task(task_xml(logon="").replace(b"<LogonType></LogonType>", b""),
                   install=INSTALL, data=DATA, server_url=ORIGIN)


@pytest.mark.parametrize("change", [
    {"principal": "Users"}, {"logon": "Password"}, {"run_level": "LeastPrivilege"},
    {"command": r"C:\Users\aryan\python.exe"}, {"args": "-m backend.agent run"},
    {"extra_action": "<Exec><Command>cmd.exe</Command></Exec>"},
    {"extra_action": "<ComHandler><ClassId>abc</ClassId></ComHandler>"},
])
def test_different_task_identity_or_extra_action_rejected(change):
    with pytest.raises(AgentRecoveryError):
        _validate_task(task_xml(**change), install=INSTALL, data=DATA, server_url=ORIGIN)


def test_malformed_task_xml_rejected():
    with pytest.raises(AgentRecoveryError):
        _validate_task(b"<Task>", install=INSTALL, data=DATA, server_url=ORIGIN)


def test_schtasks_single_byte_pipe_with_utf16_declaration_is_normalized(monkeypatch):
    task_name = "RAVEN-X WS03C Disposable " + "a" * 32
    raw = b'<?xml version="1.0" encoding="UTF-16"?>\r\r\n' + task_xml()
    monkeypatch.setattr(agent_recovery.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=raw))
    captured = agent_recovery._task_xml(task_name)
    assert captured.startswith(b"\xff\xfe")
    _validate_task(captured, install=INSTALL, data=DATA, server_url=ORIGIN)


@pytest.mark.skipif(os.name != "nt", reason="Windows inspection contract")
def test_inspect_distinguishes_origin_ca_and_corrupt_ca_binding(tmp_path, monkeypatch):
    from backend.agent import windows_store

    ca_bytes = b"synthetic public CA"
    data = tmp_path / "state"
    data.mkdir()
    (data / "server-ca.pem").write_bytes(ca_bytes)
    ca_hash = hashlib.sha256(ca_bytes).hexdigest()
    record = SimpleNamespace(server_url=ORIGIN, ca_sha256=ca_hash)
    monkeypatch.setattr(windows_store, "WindowsAgentStateStore",
                        lambda directory: SimpleNamespace(load_record=lambda: record))
    monkeypatch.setattr(agent_recovery, "_check_path", lambda *args, **kwargs: None)
    kwargs = dict(install=tmp_path / "code", data=data, task_name="unused",
                  expected_server_url=ORIGIN, expected_ca_sha256=ca_hash)
    with pytest.raises(agent_recovery.AgentOriginMismatch):
        agent_recovery.inspect(**(kwargs | {"expected_server_url": "https://127.0.0.1:29999"}))
    with pytest.raises(agent_recovery.AgentCaMismatch):
        agent_recovery.inspect(**(kwargs | {"expected_ca_sha256": "0" * 64}))
    record.ca_sha256 = "0" * 64
    with pytest.raises(AgentRecoveryError) as error:
        agent_recovery.inspect(**(kwargs | {"expected_ca_sha256": "0" * 64}))
    assert type(error.value) is AgentRecoveryError


@pytest.mark.parametrize(("failure", "code", "output"), [
    (agent_recovery.AgentOriginMismatch, 20, "AGENT_ORIGIN_MISMATCH\n"),
    (agent_recovery.AgentCaMismatch, 21, "AGENT_CA_MISMATCH\n"),
])
def test_inspection_cli_emits_only_stable_reason_code(monkeypatch, capsys, failure, code, output):
    def refuse(**kwargs):
        raise failure("sensitive path or secret must not be printed")

    monkeypatch.setattr(agent_recovery, "inspect", refuse)
    monkeypatch.setattr(sys, "argv", ["agent_recovery", "inspect", "--install", "C:\\secret",
                                   "--data", "C:\\state", "--task-name", "test",
                                   "--expected-server-url", ORIGIN,
                                   "--expected-ca-sha256", "0" * 64])
    assert agent_recovery.main() == code
    captured = capsys.readouterr()
    assert captured.out == output
    assert captured.err == ""


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def synthetic_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_recovery, "_check_path", lambda *args, **kwargs: None)
    key = secrets.token_bytes(32)
    monkeypatch.setattr(agent_recovery, "_unwrap_key", lambda _wrapped: key)
    (tmp_path / "dpapi-key.bin").write_bytes(b"synthetic-key-wrapper")
    entries = []
    for index, (name, plain) in enumerate((
        ("state/credential.bin", b"synthetic-credential-ciphertext"),
        ("state/server-ca.pem", b"synthetic-public-ca"),
    )):
        nonce = secrets.token_bytes(12)
        encrypted = nonce + AESGCM(key).encrypt(nonce, plain, name.encode())
        member = f"member-{index:05d}.enc"
        (tmp_path / member).write_bytes(encrypted)
        entries.append({"name": name, "member": member, "sha256": _sha(plain),
                        "encrypted_sha256": _sha(encrypted), "size": len(plain)})
    xml = task_xml()
    nonce = secrets.token_bytes(12)
    encrypted_task = nonce + AESGCM(key).encrypt(nonce, xml, b"task.xml")
    (tmp_path / "task.xml.enc").write_bytes(encrypted_task)
    manifest = {"format": 1, "kind": "ravenx-agent-recovery", "source_install": str(INSTALL),
                "source_data": str(DATA), "identity": {"server_url": ORIGIN}, "files": entries,
                "task_sha256": _sha(xml), "task_encrypted_sha256": _sha(encrypted_task)}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def test_backup_inventory_and_aead_verify(synthetic_backup):
    assert agent_recovery.verify(synthetic_backup)["files"] == 2


def test_backup_missing_member_fails(synthetic_backup):
    (synthetic_backup / "member-00000.enc").unlink()
    with pytest.raises(Exception):
        agent_recovery.verify(synthetic_backup)


def test_backup_extra_member_fails(synthetic_backup):
    (synthetic_backup / "rogue.bin").write_bytes(b"unexpected")
    with pytest.raises(AgentRecoveryError, match="inventory"):
        agent_recovery.verify(synthetic_backup)


def test_backup_manifest_tamper_fails(synthetic_backup):
    path = synthetic_backup / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AgentRecoveryError, match="differs"):
        agent_recovery.verify(synthetic_backup)
