"""Explicit, single-process TLS listener selection for the Omen pilot."""
from __future__ import annotations

import ipaddress
import argparse
from datetime import datetime, timezone
from pathlib import Path
import socket

from cryptography import x509
from cryptography.exceptions import InvalidSignature


def validated_hosts(hosts: list[str], certificate: Path | None) -> tuple[str, ...]:
    """Accept one legacy explicit address or loopback plus one private LAN IP.

    The listener addresses must be literal IPs. DNS aliases and wildcard binds
    cannot silently broaden an installed server's exposure.
    """
    if len(hosts) not in (1, 2) or len(set(hosts)) != len(hosts):
        raise ValueError("one loopback or loopback plus one LAN address is required")
    parsed = []
    for host in hosts:
        try:
            address = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError as error:
            raise ValueError("listener hosts must be literal IPv4 addresses") from error
        if host != str(address):
            raise ValueError("listener address must use canonical IPv4 form")
        parsed.append(address)
    if len(parsed) == 2 and parsed[0] != ipaddress.IPv4Address("127.0.0.1"):
        raise ValueError("the first listener must preserve 127.0.0.1")
    if len(parsed) == 1 and parsed[0] != ipaddress.IPv4Address("127.0.0.1"):
        _require_lan(parsed[0])
    if len(parsed) == 2:
        _require_lan(parsed[1])
    if certificate is not None:
        cert = x509.load_pem_x509_certificate(Path(certificate).read_bytes())
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound as error:
            raise ValueError("server certificate has no subject alternative names") from error
        allowed = set(sans.get_values_for_type(x509.IPAddress))
        if not set(parsed) <= allowed:
            raise ValueError("server certificate SAN does not cover every listener")
    return tuple(hosts)


def _require_lan(lan: ipaddress.IPv4Address) -> None:
    if not lan.is_private or lan.is_loopback or lan.is_link_local or lan.is_multicast or lan.is_unspecified:
        raise ValueError("LAN listener must be a private address")
    octets = lan.packed
    if not (octets[0] == 10 or octets[0] == 172 and 16 <= octets[1] <= 31
            or octets[0] == 192 and octets[1] == 168):
        raise ValueError("LAN listener must be an RFC1918 address")


def bind_sockets(hosts: tuple[str, ...], port: int) -> list[socket.socket]:
    """Bind all explicit interfaces before starting one Uvicorn worker."""
    if not 1 <= port <= 65535:
        raise ValueError("listener port is invalid")
    sockets: list[socket.socket] = []
    try:
        for host in hosts:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(listener)
            listener.bind((host, port))
            listener.listen(socket.SOMAXCONN)
            listener.set_inheritable(True)
        return sockets
    except BaseException:
        for listener in sockets:
            listener.close()
        raise


def select_profile_certificate(directory: Path, hosts: list[str]) -> Path:
    """Select a current leaf issued by this profile's CA for every listener."""
    validated_hosts(hosts, None)
    ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
    now = datetime.now(timezone.utc)
    if not ca.not_valid_before_utc <= now <= ca.not_valid_after_utc:
        raise ValueError("profile CA is outside its validity period")
    for name in ("server.pem", "server-vm.pem"):
        candidate = directory / name
        try:
            validated_hosts(hosts, candidate)
            cert = x509.load_pem_x509_certificate(candidate.read_bytes())
            cert.verify_directly_issued_by(ca)
            if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
                return candidate
        except (FileNotFoundError, ValueError, InvalidSignature):
            continue
    raise ValueError("no current server certificate issued by the profile CA covers all listeners")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify explicit RAVEN-X TLS listener addresses")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--certificate", type=Path)
    mode.add_argument("--select-from", type=Path)
    parser.add_argument("--host", action="append", required=True)
    args = parser.parse_args()
    try:
        if args.select_from:
            print(select_profile_certificate(args.select_from, args.host).name)
        else:
            validated_hosts(args.host, args.certificate)
    except (ValueError, OSError) as error:
        parser.exit(2, f"{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
