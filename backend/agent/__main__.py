"""Install and operate the RAVEN-X Windows endpoint agent."""

from __future__ import annotations

import argparse
from getpass import getpass
import hashlib
import hmac
import os
from pathlib import Path
import re
import signal
import sys
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


def enroll(*, server: str, enrollment_id: str, ca_cert: Path, data_dir: Path,
           token_stdin: bool = False) -> str:
    verify_directory(data_dir)
    verify_protected_file(ca_cert)
    store = WindowsAgentStateStore(data_dir)
    with store.enrollment_lock():
        if store.load_record() is not None:
            raise AgentStateError("endpoint is already enrolled")
        try:
            enrollment_id = str(UUID(enrollment_id))
        except ValueError as error:
            raise AgentStateError("enrollment ID must be a UUID") from error
        token = sys.stdin.readline().rstrip("\r\n") if token_stdin else getpass("Bootstrap token: ")
        if not token or not token.isascii() or any(char.isspace() for char in token) or len(token) > 128:
            raise AgentStateError("bootstrap token is missing or invalid")
        config = local_agent_config()
        client = HttpAgentEnrollmentClient(HttpTransportConfig(server, verify=str(ca_cert)))
        try:
            grant = client.enroll(
                enrollment_id=enrollment_id, bootstrap_token=token,
                hostname=config.hostname, platform_name=config.platform,
                platform_version=config.platform_version, architecture=config.architecture,
                agent_version=AGENT_VERSION, protocol_version=str(ProtocolVersion.current()),
                request_id=str(uuid4()), nonce=uuid4().hex,
            )
        finally:
            client.close()
            token = None
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
    setup.add_argument("--token-stdin", action="store_true", help="read token from standard input instead of hidden prompt")
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
                token_stdin=arguments.token_stdin,
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
