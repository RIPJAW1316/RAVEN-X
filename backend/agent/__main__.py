"""Install and operate the RAVEN-X Windows endpoint agent."""

from __future__ import annotations

import argparse
from getpass import GetPassWarning, getpass
import hashlib
import hmac
import os
from pathlib import Path
import re
import signal
import sys
import warnings
from uuid import UUID, uuid4

from ..infrastructure.security.windows_files import (
    WindowsFileSecurityError, atomic_create_protected, protect_directory,
    verify_directory, verify_protected_file,
)
from ..infrastructure.transport.http.client import (
    HttpAgentEnrollmentClient, HttpTransportConfig, HttpTransportError,
)
from ..protocol.agent import ProtocolVersion
from .host import AGENT_VERSION, WindowsAgentHost, ca_certificate_digest, local_agent_config
from .windows_store import AgentStateError, WindowsAgentStateStore, default_agent_data_directory


def _directory_argument(value):
    return Path(value) if value else default_agent_data_directory()


def prepare(directory: Path, ca_source: Path, expected_ca_sha256: str) -> Path:
    if os.name != "nt":
        raise AgentStateError("agent installation requires Windows")
    directory = Path(directory)
    if str(directory).casefold() != str(default_agent_data_directory()).casefold():
        raise AgentStateError("agent preparation is limited to ProgramData\\RavenX\\agent")
    if not directory.is_absolute() or str(directory).startswith("\\\\"):
        raise AgentStateError("agent data directory must be a local absolute path")
    if directory.parent == directory:
        raise AgentStateError("agent data directory is invalid")
    if directory.exists():
        raise AgentStateError("agent storage already exists; inspect it before preparing again")
    if not isinstance(expected_ca_sha256, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected_ca_sha256) is None:
        raise AgentStateError("expected CA SHA-256 fingerprint must be 64 hexadecimal characters")
    with Path(ca_source).open("rb") as source:
        cert = source.read(256 * 1024 + 1)
    if not cert or len(cert) > 256 * 1024 or b"-----BEGIN CERTIFICATE-----" not in cert:
        raise AgentStateError("CA certificate is not a valid PEM certificate file")
    if not hmac.compare_digest(hashlib.sha256(cert).hexdigest(), expected_ca_sha256.lower()):
        raise AgentStateError("CA certificate does not match the verified SHA-256 fingerprint")
    # Only the application-owned RavenX folder receives a changed ACL.
    # A newly created child never receives a credential before protection.
    protect_directory(directory.parent)
    protect_directory(directory)
    target = directory / "server-ca.pem"
    if (directory / "credential.bin").exists() or target.exists():
        raise AgentStateError("agent storage already contains enrollment or trust state")
    try:
        atomic_create_protected(target, cert)
    except FileExistsError as error:
        raise AgentStateError("agent CA already exists; refusing to replace it") from error
    verify_protected_file(target)
    return target


def _read_hidden(prompt: str) -> str:
    if not sys.stdin.isatty():
        raise AgentStateError("enrollment requires an interactive console")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        try:
            return getpass(prompt)
        except (GetPassWarning, EOFError, KeyboardInterrupt) as error:
            raise AgentStateError("hidden input was unavailable or cancelled") from error


def _enrollment_id(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as error:
        raise AgentStateError("enrollment ID must be a UUID") from error


def _request_enrollment(client, enrollment_id: str, *, token_stdin: bool, interactive_retry: bool):
    config = local_agent_config()
    attempts = 3 if interactive_retry else 1
    for attempt in range(attempts):
        token = sys.stdin.readline().rstrip("\r\n") if token_stdin else _read_hidden("Bootstrap token: ")
        try:
            if not token or not token.isascii() or any(char.isspace() for char in token) or len(token) > 128:
                if attempt + 1 == attempts:
                    raise AgentStateError("bootstrap token is missing or invalid")
                print("Enter the complete one-time token from the Omen Enrollment dialog.")
                continue
            return client.enroll(
                enrollment_id=enrollment_id, bootstrap_token=token,
                hostname=config.hostname, platform_name=config.platform,
                platform_version=config.platform_version, architecture=config.architecture,
                agent_version=AGENT_VERSION, protocol_version=str(ProtocolVersion.current()),
                request_id=str(uuid4()), nonce=uuid4().hex,
            )
        except HttpTransportError as error:
            if error.status_code != 401 or error.code != "enrollment_rejected" or attempt + 1 == attempts:
                raise
        finally:
            token = None
        print("Omen rejected enrollment. Check that the ID and one-time token came from the same dialog and are still valid.")
        replacement = _read_hidden("Enter a replacement Enrollment ID (hidden), or press Enter to keep the current ID: ")
        if replacement:
            try:
                enrollment_id = _enrollment_id(replacement)
            except AgentStateError:
                print("The replacement was not a UUID. The current Enrollment ID is still selected.")
            finally:
                replacement = None


def enroll(*, server: str, enrollment_id: str, ca_cert: Path, data_dir: Path,
           token_stdin: bool = False, interactive_retry: bool = False) -> str:
    verify_directory(data_dir)
    verify_protected_file(ca_cert)
    store = WindowsAgentStateStore(data_dir)
    with store.enrollment_lock():
        if store.load_record() is not None:
            raise AgentStateError("endpoint is already enrolled")
        enrollment_id = _enrollment_id(enrollment_id)
        client = HttpAgentEnrollmentClient(HttpTransportConfig(server, verify=str(ca_cert)))
        try:
            grant = _request_enrollment(
                client, enrollment_id, token_stdin=token_stdin, interactive_retry=interactive_retry,
            )
        finally:
            client.close()
        if grant.protocol_version != str(ProtocolVersion.current()):
            raise AgentStateError("server selected an unsupported protocol version")
        record = store.save_enrollment(grant, server_url=server, ca_sha256=ca_certificate_digest(ca_cert))
        return str(record.endpoint_id)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.agent")
    subcommands = parser.add_subparsers(dest="command", required=True)
    pre = subcommands.add_parser("prepare", help="protect machine storage and install a CA certificate")
    pre.add_argument("--data-dir")
    pre.add_argument("--ca-cert-source", required=True)
    pre.add_argument("--expected-ca-sha256", required=True)
    setup = subcommands.add_parser("enroll", help="redeem a one-use bootstrap token")
    setup.add_argument("--server", required=True)
    setup.add_argument("--enrollment-id", required=True)
    setup.add_argument("--ca-cert", required=True)
    setup.add_argument("--data-dir")
    token_input = setup.add_mutually_exclusive_group()
    token_input.add_argument("--token-stdin", action="store_true", help="read token from standard input instead of hidden prompt")
    token_input.add_argument("--interactive-retry", action="store_true", help="allow up to three interactive enrollment attempts")
    foreground = subcommands.add_parser("run", help="start the foreground agent")
    foreground.add_argument("--server", required=True)
    foreground.add_argument("--ca-cert", required=True)
    foreground.add_argument("--data-dir")
    foreground.add_argument("--once", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        directory = _directory_argument(arguments.data_dir)
        if arguments.command == "prepare":
            location = prepare(directory, Path(arguments.ca_cert_source), arguments.expected_ca_sha256)
            print(f"Agent storage prepared; CA installed at {location}")
        elif arguments.command == "enroll":
            endpoint = enroll(
                server=arguments.server, enrollment_id=arguments.enrollment_id,
                ca_cert=Path(arguments.ca_cert), data_dir=directory,
                token_stdin=arguments.token_stdin, interactive_retry=arguments.interactive_retry,
            )
            print(f"Endpoint enrolled: {endpoint}. Approval is required before assessments.")
        else:
            verify_protected_file(Path(arguments.ca_cert))
            host = WindowsAgentHost(store=WindowsAgentStateStore(directory), server_url=arguments.server,
                                    ca_cert=Path(arguments.ca_cert))
            signal.signal(signal.SIGINT, lambda *_: host.stop_event.set())
            signal.signal(signal.SIGTERM, lambda *_: host.stop_event.set())
            host.run(once=arguments.once)
        return 0
    except (AgentStateError, WindowsFileSecurityError, HttpTransportError, OSError, ValueError) as error:
        # Never echo exception text from remote responses or crypto libraries.
        code = error.code if isinstance(error, HttpTransportError) else type(error).__name__
        print(f"Agent operation failed: {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
