import pytest
from sqlalchemy import select, func

from backend.cli import bootstrap, generate_local_tls, main
from backend.core.database.database import DatabaseManager
from backend.core.database.models import UserRecord, OrganizationRecord
from backend.application.identity import HumanAuthenticationService
from backend.infrastructure.persistence.sqlalchemy_user_repository import SQLAlchemyUserRepository


def manager(tmp_path):
    db = DatabaseManager()
    db.config = {"type": "sqlite", "sqlite_path": str(tmp_path / "demo.db"), "echo": False}
    return db


def test_bootstrap_is_atomic_and_refuses_existing_users(tmp_path):
    db = manager(tmp_path)
    created = bootstrap(db, email="admin@example.test", display_name="Lab admin",
                        password="a long test-only password", organization="Test lab")
    assert HumanAuthenticationService(SQLAlchemyUserRepository(db)).authenticate(
        "admin@example.test", "a long test-only password").principal.principal_id == created["user_id"]
    with pytest.raises(ValueError, match="already contains users"):
        bootstrap(db, email="other@example.test", display_name="Other", password="another long test password", organization="Other")
    with db.get_db() as session:
        assert session.scalar(select(func.count()).select_from(UserRecord)) == 1
        assert session.scalar(select(func.count()).select_from(OrganizationRecord)) == 1
    db.close()


def test_invalid_bootstrap_does_not_leave_partial_user(tmp_path):
    db = manager(tmp_path)
    with pytest.raises(ValueError):
        bootstrap(db, email="invalid-email", display_name="Lab admin",
                  password="a long test-only password", organization="Test lab")
    assert SQLAlchemyUserRepository(db).count_users() == 0
    db.close()


def test_tls_certificate_contains_lan_sans_and_cannot_overwrite(tmp_path):
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
    import ipaddress
    protect = lambda path: path.mkdir(parents=True, exist_ok=True)
    paths = generate_local_tls(tmp_path / "tls", ["omen.test", "192.168.1.10"], protect=protect)
    cert = x509.load_pem_x509_certificate(__import__("pathlib").Path(paths["server.pem"]).read_bytes())
    names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert "omen.test" in names.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("192.168.1.10") in names.get_values_for_type(x509.IPAddress)
    with pytest.raises(ValueError, match="refusing to overwrite"):
        generate_local_tls(tmp_path / "tls", ["other.test"], protect=protect)


def test_lan_plaintext_launcher_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("RAVENX_DATABASE_PATH", "")
    monkeypatch.setenv("RAVENX_ENABLE_LEGACY_ROUTES", "false")
    with pytest.raises(SystemExit) as failure:
        main(["serve", "--data-dir", str(tmp_path), "--host", "0.0.0.0", "--local-http"])
    assert failure.value.code == 2
