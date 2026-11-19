"""Pre-enrollment HTTPS trust check. No bootstrap secret is involved."""

from __future__ import annotations

import argparse
import hashlib
import hmac
from http.client import HTTPSConnection
from pathlib import Path
import re
import ssl
import sys
from urllib.parse import urlsplit


class AgentTrustError(ValueError):
    """A public trust input or the remote TLS endpoint failed validation."""


def validate_server_origin(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or len(value) > 2048 or re.search(r'[\s"\\\x00-\x1f\x7f]', value):
        raise AgentTrustError("server URL is invalid")
    try:
        parsed = urlsplit(value)
        port = 443 if parsed.port is None else parsed.port
    except ValueError as error:
        raise AgentTrustError("server URL is invalid") from error
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or not 1 <= port <= 65535 or not parsed.netloc):
        raise AgentTrustError("server URL must be an HTTPS origin")
    return parsed.hostname, port


def verify_public_ca(ca_path: Path, expected_sha256: str) -> bytes:
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None:
        raise AgentTrustError("expected CA SHA-256 is invalid")
    try:
        with Path(ca_path).open("rb") as handle:
            data = handle.read(256 * 1024 + 1)
    except OSError as error:
        raise AgentTrustError("public CA could not be read") from error
    if (not data or len(data) > 256 * 1024 or
            data.count(b"-----BEGIN CERTIFICATE-----") != 1 or
            data.count(b"-----END CERTIFICATE-----") != 1 or b"PRIVATE KEY" in data):
        raise AgentTrustError("public CA is invalid")
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256.lower()):
        raise AgentTrustError("public CA fingerprint does not match")
    return data


def check_server_trust(server_url: str, ca_path: Path, expected_sha256: str,
                       *, timeout: float = 10.0) -> None:
    """Verify CA bytes, peer chain, hostname/IP, validity dates and reachability."""
    host, port = validate_server_origin(server_url)
    data = verify_public_ca(ca_path, expected_sha256)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=data.decode("ascii"))
        connection = HTTPSConnection(host, port, timeout=timeout, context=context)
        try:
            connection.connect()
        finally:
            connection.close()
    except ssl.SSLCertVerificationError as error:
        messages = {
            9: "Omen certificate is not valid yet. Check the clocks on both computers.",
            10: "Omen certificate has expired. Check both clocks and the certificate validity dates.",
            62: "Omen certificate does not match the hostname entered in Setup.",
            64: "Omen certificate does not match the IP address entered in Setup.",
        }
        raise AgentTrustError(messages.get(
            error.verify_code, "Omen certificate chain could not be verified with the selected CA."
        )) from error
    except (TimeoutError, ConnectionRefusedError) as error:
        raise AgentTrustError(
            "Could not connect to Omen. Check the HTTPS address and port (normally 8443) and confirm the server is running."
        ) from error
    except (UnicodeError, ValueError, ssl.SSLError, OSError) as error:
        # Do not copy remote responses, addresses or certificate detail to logs.
        raise AgentTrustError("HTTPS server trust verification failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify server HTTPS trust before enrollment")
    parser.add_argument("--server", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--expected-ca-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        check_server_trust(args.server, Path(args.ca_cert), args.expected_ca_sha256)
    except AgentTrustError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("HTTPS server trust verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
