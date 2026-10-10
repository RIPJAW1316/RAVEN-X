"""Local server administration. Secrets are read from a prompt, never argv."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import getpass
import ipaddress
import json
import os
from pathlib import Path
import socket

from .infrastructure.security.windows_files import WindowsFileSecurityError


ROOT = Path(__file__).resolve().parents[1]


def default_data_dir() -> Path:
    base = Path(os.environ.get("PROGRAMDATA", str(ROOT / "data")))
    return base / "RAVEN-X" / "server"


def prepare_data_dir(directory: Path) -> Path:
    if os.name == "nt":
        from .infrastructure.security.windows_files import protect_directory
        missing = []
        current = directory
        while not current.exists():
            missing.append(current)
            current = current.parent
        for path in reversed(missing):
            protect_directory(path)
        return protect_directory(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    return directory


class _TransactionDatabase:
    """Let existing repositories share one bootstrap transaction."""
    def __init__(self, session):
        self.session = session

    @contextmanager
    def get_db(self):
        yield self.session


def bootstrap(database, *, email: str, display_name: str, password: str, organization: str) -> dict:
    """Create the first operator, organization and owner role atomically.

    Refuse an occupied database. This local, operator-invoked boundary is never
    exposed through HTTP and cannot reset or elevate an existing account.
    """
    from sqlalchemy import text
    from .application.identity import HumanIdentityService
    from .application.organization import OrganizationMembershipService, OrganizationService
    from .application.rbac.service import RoleBindingService, RoleService
    from .domain.security import AuthorizationAction
    from .infrastructure.persistence.sqlalchemy_membership_repository import SQLAlchemyOrganizationMembershipRepository
    from .infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository
    from .infrastructure.persistence.sqlalchemy_rbac_repository import SQLAlchemyRoleBindingRepository, SQLAlchemyRoleRepository
    from .infrastructure.persistence.sqlalchemy_security_audit_repository import SQLAlchemySecurityAuditRepository
    from .infrastructure.persistence.sqlalchemy_user_repository import SQLAlchemyUserRepository

    if not 12 <= len(password) <= 128:
        raise ValueError("password must contain 12 to 128 characters")
    if not display_name.strip() or not organization.strip():
        raise ValueError("operator and organization names are required")
    database.create_tables()
    if database.engine.dialect.name != "sqlite":
        raise ValueError("this prototype bootstrap is validated for SQLite only")
    with database.get_db() as session:
        # Serialize the empty-database check with concurrent local bootstraps.
        session.execute(text("BEGIN IMMEDIATE"))
        tx = _TransactionDatabase(session)
        users = SQLAlchemyUserRepository(tx)
        if users.count_users():
            raise ValueError("bootstrap refused: this database already contains users")
        audit = SQLAlchemySecurityAuditRepository(tx)
        user = HumanIdentityService(users, audit_sink=audit).create_initial_user(email, display_name, password)
        orgs = SQLAlchemyOrganizationRepository(tx)
        org = OrganizationService(orgs, audit_sink=audit).create(organization)
        memberships = SQLAlchemyOrganizationMembershipRepository(tx)
        membership = OrganizationMembershipService(memberships, orgs, users, audit_sink=audit).create(user.user_id, org.organization_id)
        roles = SQLAlchemyRoleRepository(tx)
        permissions = {action.value for action in AuthorizationAction
                       if not action.value.startswith("agent.") and not action.value.endswith(".submit")}
        permissions.update({"ai.use", "reports.read"})
        role = RoleService(roles, audit_sink=audit).create(org.organization_id, "Owner", permissions,
                                                         description="Local prototype organization administrator")
        RoleBindingService(SQLAlchemyRoleBindingRepository(tx), roles, memberships, audit_sink=audit).create(
            org.organization_id, membership.membership_id, role.role_id)
        return {"user_id": str(user.user_id), "organization_id": str(org.organization_id),
                "email": user.email, "organization": org.name}


def generate_local_tls(directory: Path, hosts: list[str], *, protect=None) -> dict[str, str]:
    """Create a local CA and a server certificate; never replace existing keys."""
    # absolute() preserves the path components for Windows reparse-point
    # inspection. resolve() would follow a junction before the ACL helper saw
    # it and could place private keys outside the intended data directory.
    directory = directory.absolute()
    protected_windows_write = protect is None and os.name == "nt"
    if protect is None:
        if os.name == "nt":
            from .infrastructure.security.windows_files import protect_directory
            protect = protect_directory
        else:
            protect = lambda path: path.mkdir(parents=True, exist_ok=True, mode=0o700)
    protect(directory)
    with _exclusive_tls_initialization(directory, protected_windows_write):
        return _generate_local_tls_material(directory, hosts, protected_windows_write)


@contextmanager
def _exclusive_tls_initialization(directory: Path, protected_windows_write: bool):
    lock_path = directory / ".tls-init.lock"
    try:
        if protected_windows_write:
            from .infrastructure.security.windows_files import atomic_create_protected
            atomic_create_protected(lock_path, b"")
        else:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
    except FileExistsError as error:
        raise ValueError("TLS initialization is already in progress") from error
    try:
        yield
    finally:
        lock_path.unlink()


def _generate_local_tls_material(directory: Path, hosts: list[str],
                                 protected_windows_write: bool) -> dict[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    names = ("ca.pem", "ca-key.pem", "server.pem", "server-key.pem")
    if any((directory / name).exists() for name in names):
        raise ValueError("TLS material already exists; refusing to overwrite it")
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RAVEN-X local lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(days=1095))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    alternatives = []
    for host in dict.fromkeys(["localhost", "127.0.0.1", *hosts]):
        try:
            alternatives.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            if not host or "/" in host or ":" in host or len(host) > 253:
                raise ValueError("hosts must be DNS names or IP addresses")
            alternatives.append(x509.DNSName(host))
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0] if hosts else "localhost")])
    cert = (x509.CertificateBuilder().subject_name(server_name).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    payloads = {
        "ca.pem": ca.public_bytes(serialization.Encoding.PEM),
        "server.pem": cert.public_bytes(serialization.Encoding.PEM),
        "ca-key.pem": ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        "server-key.pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    }
    for name, payload in payloads.items():
        path = directory / name
        if protected_windows_write:
            from .infrastructure.security.windows_files import atomic_create_protected
            atomic_create_protected(path, payload)
        else:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
    return {name: str(directory / name) for name in names}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="RAVEN-X local server administration")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("bootstrap", "serve", "tls-init"):
        item = sub.add_parser(command)
        item.add_argument("--data-dir", type=Path, default=default_data_dir())
        if command == "bootstrap":
            item.add_argument("--email", required=True)
            item.add_argument("--name", default="RAVEN-X administrator")
            item.add_argument("--organization", required=True)
        elif command == "tls-init":
            item.add_argument("--host", action="append", default=[], help="LAN IP or DNS name; repeat for each name")
        else:
            item.add_argument("--host", default="127.0.0.1")
            item.add_argument("--port", type=int, default=8443)
            item.add_argument("--cert", type=Path)
            item.add_argument("--key", type=Path)
            item.add_argument("--local-http", action="store_true", help="Loopback development only")
    args = parser.parse_args(argv)
    data_dir = args.data_dir.absolute()
    os.environ["RAVENX_DATABASE_PATH"] = str(data_dir / "raven_x.db")
    os.environ["RAVENX_ENABLE_LEGACY_ROUTES"] = "false"
    try:
        if args.command == "tls-init":
            prepare_data_dir(data_dir)
            result = generate_local_tls(data_dir / "tls", args.host or [socket.gethostname()])
            print(json.dumps(result, indent=2))
        elif args.command == "bootstrap":
            prepare_data_dir(data_dir)
            password = getpass.getpass("New administrator password (12+ characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise ValueError("passwords did not match")
            from .core.database.database import DatabaseManager
            database = DatabaseManager()
            try:
                result = bootstrap(database, email=args.email, display_name=args.name,
                                   password=password, organization=args.organization)
                print(json.dumps(result, indent=2))
            finally:
                database.close()
        else:
            if args.local_http:
                if args.host not in {"127.0.0.1", "::1", "localhost"}:
                    raise ValueError("local HTTP is restricted to loopback")
                cert = key = None
                os.environ["RAVENX_ENVIRONMENT"] = "development"
            else:
                cert, key = args.cert or data_dir / "tls/server.pem", args.key or data_dir / "tls/server-key.pem"
                if not cert.is_file() or not key.is_file():
                    raise ValueError("HTTPS requires certificate and key; run tls-init first")
                if os.name == "nt":
                    from .infrastructure.security.windows_files import verify_directory, verify_protected_file
                    verify_directory(data_dir)
                    verify_protected_file(key.absolute())
                os.environ["RAVENX_ENVIRONMENT"] = "production"
            os.environ["RAVENX_SERVE_FRONTEND"] = "true"
            os.environ["RAVENX_SERVER_WORKERS"] = "1"
            os.environ.setdefault("RAVENX_PRESENCE_MAINTENANCE_ENABLED", "true")
            import uvicorn
            uvicorn.run("backend.api.main:app", host=args.host, port=args.port, workers=1,
                        ssl_certfile=str(cert) if cert else None, ssl_keyfile=str(key) if key else None,
                        proxy_headers=False, server_header=False)
        return 0
    except (ValueError, OSError, WindowsFileSecurityError) as error:
        parser.exit(2, f"RAVEN-X: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
