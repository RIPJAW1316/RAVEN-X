"""Dependency-free certificate SAN preflight for the protected base Python.

Runtime validation in backend.application.ops.listeners repeats this check with
cryptography after the offline wheelhouse is installed.
"""
from __future__ import annotations

import argparse
import ipaddress
import ssl


def verify(certificate: str, hosts: list[str]) -> None:
    if len(hosts) != 2 or hosts[0] != "127.0.0.1":
        raise ValueError("loopback and one LAN address are required")
    addresses = [ipaddress.IPv4Address(host) for host in hosts]
    if any(str(address) != host for address, host in zip(addresses, hosts)):
        raise ValueError("listener address is not canonical")
    lan = addresses[1].packed
    if not (lan[0] == 10 or lan[0] == 172 and 16 <= lan[1] <= 31
            or lan[0] == 192 and lan[1] == 168):
        raise ValueError("LAN listener is not RFC1918")
    # CPython's certificate decoder is part of the tested Windows 3.13 runtime.
    decoded = ssl._ssl._test_decode_cert(certificate)
    sans = {name for kind, name in decoded.get("subjectAltName", ()) if kind == "IP Address"}
    if not set(hosts) <= sans:
        raise ValueError("certificate SAN does not cover both listeners")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--host", action="append", required=True)
    args = parser.parse_args()
    try:
        verify(args.certificate, args.host)
        return 0
    except Exception as error:
        parser.exit(2, "Listener SAN preflight refused: " + type(error).__name__ + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
