"""Windows Credential Manager Generic Credential storage for RAVEN-X.

Persists secrets into the current user's local Windows Credential store using
Generic Credentials (CRED_TYPE_GENERIC = 1) with non-roaming machine persistence
(CRED_PERSIST_LOCAL_MACHINE = 2). Secrets are never printed in status, logs,
or error messages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
from typing import Any

DEFAULT_GEMINI_TARGET = "RAVEN-X/GeminiApiKey"
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2


class WindowsCredentialError(RuntimeError):
    """Base exception for Windows Credential Manager operations."""
    pass


class CredentialValidationError(WindowsCredentialError):
    """Raised when an API key format or characters are unsafe."""
    pass


def validate_credential_characters(key: str) -> str:
    """Validate that the credential contains only printable, non-space ASCII characters."""
    if not isinstance(key, str) or not key.strip():
        raise CredentialValidationError("Credential is empty or missing")
    k = key.strip()
    if any(ord(c) < 33 or ord(c) > 126 for c in k):
        raise CredentialValidationError("Credential contains unsafe or non-printable characters")
    return k


class BaseCredentialStore(ABC):
    """Abstract credential store interface for production and test isolation."""

    @abstractmethod
    def set_key(self, key: str, *, username: str | None = None) -> None:
        """Store a secret key."""
        pass

    @abstractmethod
    def get_key(self) -> str | None:
        """Retrieve the secret key, or None if unconfigured."""
        pass

    @abstractmethod
    def delete_key(self) -> bool:
        """Delete the secret key. Return True if deleted, False if absent."""
        pass

    @abstractmethod
    def get_status(self) -> dict[str, Any]:
        """Return safe status dictionary without exposing the secret key."""
        pass


class Win32CredStore(BaseCredentialStore):
    """Production Windows Credential Manager Generic Credential storage."""

    def __init__(self, target_name: str = DEFAULT_GEMINI_TARGET):
        self.target_name = target_name

    def _get_win32cred(self):
        if os.name != "nt":
            raise WindowsCredentialError("Windows Credential Manager requires Windows OS")
        try:
            import win32cred
            import pywintypes
            return win32cred, pywintypes
        except ImportError as err:
            raise WindowsCredentialError("pywin32 (win32cred) is required for Windows Credential Manager storage") from err

    def set_key(self, key: str, *, username: str | None = None) -> None:
        validated = validate_credential_characters(key)
        win32cred, _ = self._get_win32cred()
        user = username or os.environ.get("USERNAME", "RavenXOperator")

        cred_dict = {
            "Type": win32cred.CRED_TYPE_GENERIC,
            "TargetName": self.target_name,
            "CredentialBlob": validated,
            "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
            "UserName": user,
            "Comment": "RAVEN-X Gemini AI Studio API Key",
        }
        try:
            win32cred.CredWrite(cred_dict, 0)
        except Exception as err:
            raise WindowsCredentialError("Failed to write to Windows Credential Manager") from err

    def get_key(self) -> str | None:
        win32cred, pywintypes = self._get_win32cred()
        try:
            cred = win32cred.CredRead(self.target_name, win32cred.CRED_TYPE_GENERIC, 0)
            blob = cred.get("CredentialBlob")
            if blob is None:
                return None
            if isinstance(blob, bytes):
                try:
                    return blob.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    return blob.decode("utf-8", errors="replace").rstrip("\x00")
            elif isinstance(blob, str):
                return blob
            return None
        except pywintypes.error as err:
            # 1168 = ERROR_NOT_FOUND, 2 = ERROR_FILE_NOT_FOUND
            if err.winerror in (1168, 2):
                return None
            raise WindowsCredentialError("Failed to read from Windows Credential Manager") from err
        except Exception as err:
            raise WindowsCredentialError("Error accessing Windows Credential Manager") from err

    def delete_key(self) -> bool:
        win32cred, pywintypes = self._get_win32cred()
        try:
            win32cred.CredDelete(self.target_name, win32cred.CRED_TYPE_GENERIC, 0)
            return True
        except pywintypes.error as err:
            if err.winerror in (1168, 2):
                return False
            raise WindowsCredentialError("Failed to delete from Windows Credential Manager") from err
        except Exception as err:
            raise WindowsCredentialError("Error deleting from Windows Credential Manager") from err

    def get_status(self) -> dict[str, Any]:
        win32cred, pywintypes = self._get_win32cred()
        try:
            cred = win32cred.CredRead(self.target_name, win32cred.CRED_TYPE_GENERIC, 0)
            user = cred.get("UserName")
            last_written = None
            lw = cred.get("LastWritten")
            if lw is not None:
                try:
                    last_written = str(lw)
                except Exception:
                    pass
            return {
                "configured": True,
                "target": self.target_name,
                "type": "generic",
                "persistence": "local_machine",
                "username": user,
                "last_written": last_written,
            }
        except pywintypes.error as err:
            if err.winerror in (1168, 2):
                return {
                    "configured": False,
                    "target": self.target_name,
                    "type": "generic",
                    "persistence": "local_machine",
                }
            raise WindowsCredentialError("Failed to query Windows Credential Manager status") from err


class InMemoryCredentialStore(BaseCredentialStore):
    """Isolated in-memory credential store for tests and non-Windows environments."""

    def __init__(self, target_name: str = DEFAULT_GEMINI_TARGET):
        self.target_name = target_name
        self._key: str | None = None
        self._username: str | None = None
        self._last_written: datetime | None = None

    def set_key(self, key: str, *, username: str | None = None) -> None:
        validated = validate_credential_characters(key)
        self._key = validated
        self._username = username or os.environ.get("USERNAME", "TestOperator")
        self._last_written = datetime.now(timezone.utc)

    def get_key(self) -> str | None:
        return self._key

    def delete_key(self) -> bool:
        if self._key is not None:
            self._key = None
            self._username = None
            self._last_written = None
            return True
        return False

    def get_status(self) -> dict[str, Any]:
        if self._key is not None:
            return {
                "configured": True,
                "target": self.target_name,
                "type": "generic",
                "persistence": "local_machine",
                "username": self._username,
                "last_written": self._last_written.isoformat() if self._last_written else None,
            }
        return {
            "configured": False,
            "target": self.target_name,
            "type": "generic",
            "persistence": "local_machine",
        }


# Global active store hook for test isolation
_ACTIVE_STORE: BaseCredentialStore | None = None


def set_active_store(store: BaseCredentialStore | None) -> None:
    """Set explicit active credential store (used for test isolation)."""
    global _ACTIVE_STORE
    _ACTIVE_STORE = store


def get_default_store(target_name: str = DEFAULT_GEMINI_TARGET) -> BaseCredentialStore:
    """Return the active or platform-appropriate credential store."""
    if _ACTIVE_STORE is not None:
        return _ACTIVE_STORE
    if os.environ.get("RAVENX_TEST_ISOLATED_CREDENTIALS", "").lower() in {"1", "true", "yes"}:
        return InMemoryCredentialStore(target_name)
    if os.name == "nt":
        return Win32CredStore(target_name)
    raise WindowsCredentialError("Windows Credential Manager is only supported on Windows")


def set_gemini_api_key(key: str, *, target_name: str = DEFAULT_GEMINI_TARGET, username: str | None = None) -> None:
    """Store the Gemini API key in Windows Credential Manager."""
    store = get_default_store(target_name)
    store.set_key(key, username=username)


def get_gemini_api_key(*, target_name: str = DEFAULT_GEMINI_TARGET) -> str | None:
    """Retrieve the Gemini API key from Windows Credential Manager."""
    store = get_default_store(target_name)
    return store.get_key()


def delete_gemini_api_key(*, target_name: str = DEFAULT_GEMINI_TARGET) -> bool:
    """Delete the Gemini API key from Windows Credential Manager."""
    store = get_default_store(target_name)
    return store.delete_key()


def get_gemini_key_status(*, target_name: str = DEFAULT_GEMINI_TARGET) -> dict[str, Any]:
    """Retrieve safe status of the Gemini API key without exposing the key."""
    store = get_default_store(target_name)
    return store.get_status()
