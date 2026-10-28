"""Client-chosen successor secrets use a keyed verifier outside the credential DB."""

from pathlib import Path
import secrets

import pytest

from backend.agent.windows_store import WindowsAgentStateStore
from backend.domain.endpoint import EndpointId
from backend.domain.enrollment import CredentialId
from backend.infrastructure.security import (
    VerifierKeyError,
    generate_secret,
    hash_bearer_secret,
    hash_token,
    resolve_verifier_key,
    verify_secret,
)


def test_hmac_verifier_resists_database_only_disclosure():
    key = secrets.token_bytes(32)
    secret = "A" * 43
    binding = str(CredentialId.new())
    verifier = hash_bearer_secret(secret, key=key, binding=binding)
    assert verifier.startswith("token-hmac-v2$")
    assert verify_secret(secret, verifier, key=key, binding=binding)
    assert not verify_secret(secret, verifier)
    assert not verify_secret(secret, verifier, key=secrets.token_bytes(32), binding=binding)
    assert not verify_secret("B" * 43, verifier, key=key, binding=binding)
    assert not verify_secret(secret, verifier, key=key, binding=str(CredentialId.new()))


def test_enrollment_hash_token_verifiers_remain_usable_without_the_hmac_key():
    secret = generate_secret()
    verifier = hash_token(secret)
    assert verifier.startswith("token-sha256-v1$")
    assert verify_secret(secret, verifier)
    assert verify_secret(secret, verifier, key=secrets.token_bytes(32), binding="unused")


def test_malformed_hmac_verifiers_fail_closed():
    key = secrets.token_bytes(32)
    assert not verify_secret("A" * 43, "token-hmac-v2$not-valid", key=key, binding="id")
    assert not verify_secret("A" * 43, "token-hmac-v2$", key=key, binding="id")
    with pytest.raises(ValueError):
        hash_bearer_secret("A" * 43, key=b"short", binding="id")
    with pytest.raises(ValueError):
        hash_bearer_secret("", key=secrets.token_bytes(32), binding="id")


def test_verifier_key_is_not_created_from_a_bare_resolve(tmp_path, monkeypatch):
    # HIGH-01: a process with no configured key must not invent one, and must
    # not create a sidecar. Ephemeral keys require an explicit mode.
    monkeypatch.delenv("RAVENX_CREDENTIAL_VERIFIER_KEY", raising=False)
    monkeypatch.delenv("RAVENX_DATABASE_PATH", raising=False)
    monkeypatch.delenv("RAVENX_VERIFIER_KEY_MODE", raising=False)
    with pytest.raises(VerifierKeyError):
        resolve_verifier_key(environ={})
    # Ephemeral keys are only for an explicit in-memory database. A mode flag
    # alone must not mint a key that could be mistaken for file-backed custody.
    with pytest.raises(VerifierKeyError, match="in-memory"):
        resolve_verifier_key(environ={"RAVENX_VERIFIER_KEY_MODE": "ephemeral", "RAVENX_ENVIRONMENT": "test"})
    first = resolve_verifier_key(environ={
        "RAVENX_VERIFIER_KEY_MODE": "ephemeral", "RAVENX_ENVIRONMENT": "test",
        "RAVENX_DATABASE_PATH": ":memory:",
    })
    second = resolve_verifier_key(environ={
        "RAVENX_VERIFIER_KEY_MODE": "ephemeral", "RAVENX_ENVIRONMENT": "test",
        "RAVENX_DATABASE_PATH": ":memory:",
    })
    assert first != second
    assert not list(tmp_path.glob("**/*"))


def test_named_database_does_not_silently_create_a_sidecar(tmp_path, monkeypatch):
    # The previous resolve() created credential-hmac.key whenever the database
    # path was set. That recreated a lost key and invalidated ACTIVE HMAC
    # credentials. Creation now happens only in the empty-database bootstrap.
    database = tmp_path / "raven_x.db"
    database.write_bytes(b"")
    monkeypatch.delenv("RAVENX_CREDENTIAL_VERIFIER_KEY", raising=False)
    with pytest.raises(VerifierKeyError):
        resolve_verifier_key(environ={"RAVENX_DATABASE_PATH": str(database)})
    assert not (tmp_path / "credential-hmac.key").exists()


def test_hex_env_key_cannot_bypass_missing_database_identity(tmp_path):
    expected = secrets.token_bytes(32)
    sidecar = tmp_path / "credential-hmac.key"
    sidecar.write_bytes(secrets.token_bytes(32))
    with pytest.raises(VerifierKeyError, match="persistent verifier key is not available"):
        resolve_verifier_key(environ={
            "RAVENX_CREDENTIAL_VERIFIER_KEY": expected.hex(),
            "RAVENX_DATABASE_PATH": str(tmp_path / "raven_x.db"),
        })
    with pytest.raises(VerifierKeyError, match="database identity"):
        resolve_verifier_key(environ={"RAVENX_CREDENTIAL_VERIFIER_KEY": expected.hex()})


def test_legitimate_windows_agent_still_generates_urlsafe_secrets(tmp_path):
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    class FakeProtector:
        def protect(self, plaintext):
            return b"encrypted:" + plaintext

        def unprotect(self, ciphertext):
            return ciphertext[len(b"encrypted:"):]

    class FakeFiles:
        def verify_directory(self, path):
            assert Path(path).is_dir()

        def verify_protected_file(self, path):
            assert Path(path).is_file()

        def atomic_write_protected(self, path, data):
            Path(path).write_bytes(data)

        def atomic_create_protected(self, path, data):
            Path(path).write_bytes(data)

    now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    secrets_seen = set()
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        store = WindowsAgentStateStore(tmp_path / name, protector=FakeProtector(), files=FakeFiles())
        grant = type("Grant", (), {
            "endpoint_id": EndpointId.new(), "credential_id": str(CredentialId.new()),
            "credential_secret": generate_secret(), "organization_id": str(uuid4()),
            "protocol_version": "1.0", "credential_expires_at": now + timedelta(days=30),
        })()
        store.save_enrollment(grant, server_url="https://control.example", ca_sha256="a" * 64)
        pending = store.prepare_renewal(now=now)
        assert len(pending.successor_credential_secret) >= 43
        secrets_seen.add(pending.successor_credential_secret)
    assert len(secrets_seen) == 2
