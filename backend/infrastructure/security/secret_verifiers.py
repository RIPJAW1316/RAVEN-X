"""One-way secret handling for high-entropy bootstrap credentials.

The encoded value contains the algorithm parameters, a random salt, and only
the derived verifier.  It is never possible to recover the original secret
from this value.
"""

import base64
import hashlib
import hmac
import secrets

_PREFIX = "scrypt-v1"
_TOKEN_PREFIX = "token-sha256-v1"
_BEARER_HMAC_PREFIX = "token-hmac-v2"
_N, _R, _P = 2**14, 8, 1


def generate_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    return f"{_PREFIX}${_N}${_R}${_P}${encode(salt)}${encode(digest)}"


def hash_token(token: str) -> str:
    """Indexable verifier for generated, high-entropy opaque bearer tokens.

    This must not be used for passwords or user-chosen secrets.  Bounding the
    input also prevents an unauthenticated bearer header from asking the hash
    function to process an arbitrarily large value.
    """
    if not isinstance(token, str) or not token or len(token) > 128 or not token.isascii():
        raise ValueError("invalid opaque token")
    digest = hashlib.sha256(b"RAVEN-X opaque token v1\x00" + token.encode("ascii")).hexdigest()
    return f"{_TOKEN_PREFIX}${digest}"


def hash_bearer_secret(secret: str, *, key: bytes, binding: str) -> str:
    """Keyed verifier for client-prepared renewal secrets.

    Length and charset checks cannot prove entropy. This construction keeps a
    database-only disclosure from verifying guesses: the HMAC key is not stored
    with the credential rows. A lost HTTP response is still recoverable because
    the agent retains the secret and the server retains the salt and key.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
        raise ValueError("credential verifier key must be at least 32 bytes")
    if not isinstance(binding, str) or not binding:
        raise ValueError("credential binding is required")
    if not isinstance(secret, str) or not secret or len(secret) > 128 or not secret.isascii():
        raise ValueError("invalid opaque token")
    salt = secrets.token_bytes(16)
    digest = hmac.new(bytes(key), salt + b"\x00" + binding.encode("ascii") + b"\x00" + secret.encode("ascii"),
                      hashlib.sha256).digest()
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    return f"{_BEARER_HMAC_PREFIX}${encode(salt)}${encode(digest)}"


def verify_secret(secret: str, verifier: str, *, key: bytes | None = None, binding: str | None = None) -> bool:
    try:
        if isinstance(verifier, str) and verifier.startswith(_BEARER_HMAC_PREFIX + "$"):
            if not isinstance(key, (bytes, bytearray)) or len(key) < 32 or not binding:
                return False
            _, salt_text, digest_text = verifier.split("$", 2)
            salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
            expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
            if len(salt) != 16 or len(expected) != 32:
                return False
            if not isinstance(secret, str) or not secret or len(secret) > 128 or not secret.isascii():
                return False
            actual = hmac.new(bytes(key), salt + b"\x00" + binding.encode("ascii") + b"\x00" + secret.encode("ascii"),
                              hashlib.sha256).digest()
            return hmac.compare_digest(actual, expected)
        if isinstance(verifier, str) and verifier.startswith(_TOKEN_PREFIX + "$"):
            return hmac.compare_digest(hash_token(secret), verifier)
        prefix, n, r, p, salt_text, digest_text = verifier.split("$", 5)
        if prefix != _PREFIX:
            return False
        if (int(n), int(r), int(p)) != (_N, _R, _P):
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(
            secret.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError, UnicodeError):
        return False
