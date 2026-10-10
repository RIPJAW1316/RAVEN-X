"""Agent preparation binds the CA to the verified digest and preserves state."""

import hashlib
import os

import pytest

from backend.agent import __main__ as agent_cli


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows agent installation only")


def _simulated_storage(monkeypatch, tmp_path):
    data_dir = tmp_path / "RavenX" / "agent"
    monkeypatch.setattr(agent_cli, "default_agent_data_directory", lambda: data_dir)
    protected = []

    def protect(path):
        protected.append(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create(path, contents):
        with path.open("xb") as output:
            output.write(contents)

    monkeypatch.setattr(agent_cli, "protect_directory", protect)
    monkeypatch.setattr(agent_cli, "atomic_create_protected", create)
    monkeypatch.setattr(agent_cli, "verify_protected_file", lambda path: path)
    return data_dir, protected


def test_prepare_refuses_repeated_setup_before_touching_existing_ca_or_credential(monkeypatch, tmp_path):
    data_dir, protected = _simulated_storage(monkeypatch, tmp_path)
    source = tmp_path / "source-ca.pem"
    first = b"-----BEGIN CERTIFICATE-----\nfirst\n-----END CERTIFICATE-----\n"
    source.write_bytes(first)
    verified_digest = hashlib.sha256(first).hexdigest().upper()
    assert agent_cli.prepare(data_dir, source, verified_digest).read_bytes() == first
    credential = data_dir / "credential.bin"
    credential.write_bytes(b"existing-encrypted-record")
    source.write_bytes(b"-----BEGIN CERTIFICATE-----\nreplacement\n-----END CERTIFICATE-----\n")
    before = tuple(protected)

    with pytest.raises(agent_cli.AgentStateError, match="already exists"):
        agent_cli.prepare(data_dir, source, verified_digest)

    assert tuple(protected) == before
    assert (data_dir / "server-ca.pem").read_bytes() == first
    assert credential.read_bytes() == b"existing-encrypted-record"


def test_prepare_exclusive_publication_preserves_competing_ca(monkeypatch, tmp_path):
    data_dir, _ = _simulated_storage(monkeypatch, tmp_path)
    source = tmp_path / "source-ca.pem"
    new_ca = b"-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n"
    source.write_bytes(new_ca)
    existing = b"-----BEGIN CERTIFICATE-----\nprevious\n-----END CERTIFICATE-----\n"

    def competing_create(path, contents):
        path.write_bytes(existing)
        with path.open("xb") as output:
            output.write(contents)

    monkeypatch.setattr(agent_cli, "atomic_create_protected", competing_create)
    with pytest.raises(agent_cli.AgentStateError, match="refusing to replace"):
        agent_cli.prepare(data_dir, source, hashlib.sha256(new_ca).hexdigest())
    assert (data_dir / "server-ca.pem").read_bytes() == existing


def test_prepare_rejects_swapped_ca_before_creating_storage(monkeypatch, tmp_path):
    data_dir, protected = _simulated_storage(monkeypatch, tmp_path)
    source = tmp_path / "source-ca.pem"
    verified_ca = b"-----BEGIN CERTIFICATE-----\nverified\n-----END CERTIFICATE-----\n"
    swapped_ca = b"-----BEGIN CERTIFICATE-----\nattacker\n-----END CERTIFICATE-----\n"
    verified_digest = hashlib.sha256(verified_ca).hexdigest()
    source.write_bytes(verified_ca)
    # The transfer file changes after an operator has compared its digest.
    source.write_bytes(swapped_ca)

    with pytest.raises(agent_cli.AgentStateError, match="does not match"):
        agent_cli.prepare(data_dir, source, verified_digest)

    assert not data_dir.exists()
    assert not protected


def test_prepare_rejects_invalid_fingerprint_without_publishing_ca(monkeypatch, tmp_path):
    data_dir, protected = _simulated_storage(monkeypatch, tmp_path)
    source = tmp_path / "source-ca.pem"
    source.write_bytes(b"-----BEGIN CERTIFICATE-----\nsource\n-----END CERTIFICATE-----\n")
    with pytest.raises(agent_cli.AgentStateError, match="64 hexadecimal"):
        agent_cli.prepare(data_dir, source, "not-a-digest")
    assert not data_dir.exists()
    assert not protected
