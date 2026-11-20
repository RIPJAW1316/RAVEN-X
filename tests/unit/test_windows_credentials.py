"""Unit tests for Windows Credential Manager Generic Credential storage."""

import json
import pytest

from backend.infrastructure.security.windows_credentials import (
    DEFAULT_GEMINI_TARGET,
    CredentialValidationError,
    InMemoryCredentialStore,
    Win32CredStore,
    get_default_store,
    get_gemini_api_key,
    get_gemini_key_status,
    delete_gemini_api_key,
    set_active_store,
    set_gemini_api_key,
    validate_credential_characters,
)
from backend.infrastructure.ai import CloudGeminiConfig, CloudGeminiProvider
from backend.application.ai.synthetic_demo import WINDOWS_HARDENING_DEMO_ID


@pytest.fixture(autouse=True)
def isolate_credentials():
    """Ensure all tests in this module run against an isolated in-memory store."""
    store = InMemoryCredentialStore("TEST/IsolatedGeminiKey")
    set_active_store(store)
    yield store
    set_active_store(None)


def test_validate_credential_characters():
    # Valid keys
    assert validate_credential_characters("AIzaSyD-123_456abc") == "AIzaSyD-123_456abc"
    assert validate_credential_characters("  test-key-with-padding  ") == "test-key-with-padding"

    # Missing / empty
    with pytest.raises(CredentialValidationError, match="empty or missing"):
        validate_credential_characters("")
    with pytest.raises(CredentialValidationError, match="empty or missing"):
        validate_credential_characters("   \t\n")

    # Unsafe characters
    with pytest.raises(CredentialValidationError, match="unsafe or non-printable"):
        validate_credential_characters("key\nwith-newline")
    with pytest.raises(CredentialValidationError, match="unsafe or non-printable"):
        validate_credential_characters("key\rwith-cr")
    with pytest.raises(CredentialValidationError, match="unsafe or non-printable"):
        validate_credential_characters("key\x00with-null")
    with pytest.raises(CredentialValidationError, match="unsafe or non-printable"):
        validate_credential_characters("key with spaces")


def test_in_memory_store_crud_and_status(isolate_credentials):
    store = isolate_credentials

    # Initially unconfigured
    status = store.get_status()
    assert status["configured"] is False
    assert status["target"] == "TEST/IsolatedGeminiKey"
    assert "key" not in status
    assert store.get_key() is None

    # Set key
    store.set_key("fake-secret-key-1", username="OperatorAlpha")
    assert store.get_key() == "fake-secret-key-1"

    status_set = store.get_status()
    assert status_set["configured"] is True
    assert status_set["username"] == "OperatorAlpha"
    assert status_set["target"] == "TEST/IsolatedGeminiKey"
    assert "fake-secret-key-1" not in str(status_set)

    # Rotate key
    store.set_key("fake-secret-key-2", username="OperatorBeta")
    assert store.get_key() == "fake-secret-key-2"
    status_rot = store.get_status()
    assert status_rot["configured"] is True
    assert status_rot["username"] == "OperatorBeta"
    assert "fake-secret-key-2" not in str(status_rot)

    # Delete key
    assert store.delete_key() is True
    assert store.get_key() is None
    assert store.get_status()["configured"] is False

    # Second delete returns False (already absent)
    assert store.delete_key() is False


def test_module_convenience_functions(isolate_credentials):
    # Status when unconfigured
    assert get_gemini_key_status()["configured"] is False
    assert get_gemini_api_key() is None

    # Set key
    set_gemini_api_key("fake-gemini-key-999", username="AdminUser")
    assert get_gemini_api_key() == "fake-gemini-key-999"

    status = get_gemini_key_status()
    assert status["configured"] is True
    assert status["username"] == "AdminUser"
    assert "fake-gemini-key-999" not in str(status)

    # Delete
    assert delete_gemini_api_key() is True
    assert get_gemini_api_key() is None
    assert get_gemini_key_status()["configured"] is False


def test_cloud_gemini_reads_from_credential_store(isolate_credentials):
    """CloudGeminiProvider dynamically resolves API key from the credential store."""
    recorded_calls = []

    def mock_transport(url, headers, body):
        recorded_calls.append({"url": url, "headers": headers})
        from tests.unit.test_ai_analyst_model_selector import _make_google_wire_response
        return _make_google_wire_response(["f1", "f2", "f3", "f4", "f5"])

    # 1. When unconfigured in store and config has no key, provider fails cleanly
    config = CloudGeminiConfig(enabled=True, auth_mode="api_key", api_key="")
    provider = CloudGeminiProvider(config, transport=mock_transport)

    with pytest.raises(ValueError, match="Gemini API key is unconfigured"):
        provider.prioritize_synthetic_demo(fixture_id=WINDOWS_HARDENING_DEMO_ID)
    assert len(recorded_calls) == 0

    # 2. Configure key in the store
    set_gemini_api_key("fake-studio-key-101", username="Operator1")
    refs = provider.prioritize_synthetic_demo(fixture_id=WINDOWS_HARDENING_DEMO_ID)
    assert refs == ["f1", "f2", "f3", "f4", "f5"]
    assert len(recorded_calls) == 1
    assert recorded_calls[0]["headers"]["x-goog-api-key"] == "fake-studio-key-101"

    # 3. Rotate key in the store - provider picks up rotated key without restarting
    set_gemini_api_key("rotated-fake-studio-key-202", username="Operator2")
    refs2 = provider.prioritize_synthetic_demo(fixture_id=WINDOWS_HARDENING_DEMO_ID)
    assert refs2 == ["f1", "f2", "f3", "f4", "f5"]
    assert len(recorded_calls) == 2
    assert recorded_calls[1]["headers"]["x-goog-api-key"] == "rotated-fake-studio-key-202"

    # 4. Delete key from store - provider fails closed without making requests
    delete_gemini_api_key()
    with pytest.raises(ValueError, match="Gemini API key is unconfigured"):
        provider.prioritize_synthetic_demo(fixture_id=WINDOWS_HARDENING_DEMO_ID)
    assert len(recorded_calls) == 2  # No new transport call


def test_cli_gemini_key_subcommand(monkeypatch, isolate_credentials):
    """Test CLI commands for gemini-key (status, set, rotate, delete)."""
    from backend import cli
    import io

    # Status initially unconfigured
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    cli.main(["gemini-key", "status"])
    status_out = json.loads(captured.getvalue())
    assert status_out["configured"] is False

    # Set key via --key-stdin
    monkeypatch.setattr("sys.stdin", io.StringIO("test-cli-api-key-555\n"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    captured_set = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured_set)
    cli.main(["gemini-key", "set", "--key-stdin"])
    set_out = json.loads(captured_set.getvalue())
    assert set_out["success"] is True
    assert set_out["status"]["configured"] is True
    assert "test-cli-api-key-555" not in captured_set.getvalue()
    assert isolate_credentials.get_key() == "test-cli-api-key-555"

    # Status now configured
    captured_stat2 = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured_stat2)
    cli.main(["gemini-key", "status"])
    status_out2 = json.loads(captured_stat2.getvalue())
    assert status_out2["configured"] is True

    # Delete
    captured_del = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured_del)
    cli.main(["gemini-key", "delete"])
    del_out = json.loads(captured_del.getvalue())
    assert del_out["success"] is True
    assert del_out["deleted"] is True
    assert isolate_credentials.get_key() is None
