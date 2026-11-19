"""Synthetic credentials ONLY; used by the protected installer rehearsal."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import httpcore
import httpx
import win32api
import win32con
import win32security

from backend.agent.windows_store import WindowsAgentStateStore
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.infrastructure.security.windows_files import atomic_create_protected, verify_protected_file

mode, directory = sys.argv[1], Path(sys.argv[2])
store = WindowsAgentStateStore(directory)
if mode == "create":
    grant = SimpleNamespace(endpoint_id=EndpointId.new(), credential_id=str(CredentialId.new()),
        credential_secret="synthetic-only-" + "x" * 48, organization_id=str(uuid4()),
        protocol_version="1.0", credential_expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    store.save_enrollment(grant, server_url="https://127.0.0.1:29999", ca_sha256="a" * 64)
    verify_protected_file(directory / "credential.bin")
    assert grant.credential_secret.encode() not in (directory / "credential.bin").read_bytes()
elif mode == "system":
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()
    assert sid == "S-1-5-18"
    assert store.credential_store.load().secret == "synthetic-only-" + "x" * 48
    atomic_create_protected(directory / "system-result.json", json.dumps({"sid": sid, "dpapi": "passed"}).encode())
else:
    raise ValueError("unknown synthetic fixture mode")
