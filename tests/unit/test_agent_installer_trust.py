"""Real TLS preflight negatives; all keys stay in disposable test storage."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import socket
import ssl
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from backend.agent.trust import AgentTrustError, check_server_trust, validate_server_origin


def _certificates(directory, *, expired=False):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disposable test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=5)).not_valid_after(now + timedelta(days=10))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=5))
            .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=5))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    directory.mkdir()
    ca_path = directory / "ca.pem"
    cert_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_path, cert_path, key_path


@contextmanager
def _server(cert_path, key_path):
    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))
    listener.listen(8)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except (OSError, ssl.SSLError):
                    pass
        except OSError:
            pass

    thread = Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_valid_public_ca_and_matching_ip(tmp_path):
    ca, cert, key = _certificates(tmp_path / "valid")
    with _server(cert, key) as port:
        check_server_trust(f"https://127.0.0.1:{port}", ca, _hash(ca))


def test_wrong_fingerprint_is_rejected_before_network(tmp_path):
    ca, _, _ = _certificates(tmp_path / "wrong-hash")
    with pytest.raises(AgentTrustError, match="fingerprint"):
        check_server_trust("https://127.0.0.1:65500", ca, "0" * 64)


def test_ca_file_with_appended_private_key_is_rejected(tmp_path):
    ca, _, _ = _certificates(tmp_path / "mixed-pem")
    ca.write_bytes(ca.read_bytes() + b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
    with pytest.raises(AgentTrustError, match="public CA is invalid"):
        check_server_trust("https://127.0.0.1:65500", ca, _hash(ca))


@pytest.mark.parametrize("substituted_hash", [False, True])
def test_wrong_ca_or_substituted_bundle_pair_fails_tls(tmp_path, substituted_hash):
    _, cert, key = _certificates(tmp_path / "real")
    other_ca, _, _ = _certificates(tmp_path / "other")
    expected = _hash(other_ca) if substituted_hash else "1" * 64
    with _server(cert, key) as port:
        with pytest.raises(AgentTrustError):
            check_server_trust(f"https://127.0.0.1:{port}", other_ca, expected)


def test_wrong_host_ip_fails_hostname_verification(tmp_path):
    ca, cert, key = _certificates(tmp_path / "host")
    with _server(cert, key) as port:
        with pytest.raises(AgentTrustError, match="does not match the IP address"):
            check_server_trust(f"https://127.0.0.2:{port}", ca, _hash(ca))


def test_expired_server_certificate_is_rejected(tmp_path):
    ca, cert, key = _certificates(tmp_path / "expired", expired=True)
    with _server(cert, key) as port:
        with pytest.raises(AgentTrustError, match="certificate has expired"):
            check_server_trust(f"https://127.0.0.1:{port}", ca, _hash(ca))


def test_unreachable_server_is_rejected(tmp_path):
    ca, _, _ = _certificates(tmp_path / "unreachable")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    with pytest.raises(AgentTrustError, match="Check the HTTPS address and port"):
        check_server_trust(f"https://127.0.0.1:{port}", ca, _hash(ca), timeout=0.5)


@pytest.mark.parametrize("url", ["http://host:8443", "https://host:0", "https://host:70000",
    "https://user@host", "https://host/path", "https://host?x=1", "https://host#x",
    'https://host" -Command evil', "https://host:bad"])
def test_invalid_origins_rejected(url):
    with pytest.raises(AgentTrustError):
        validate_server_origin(url)
