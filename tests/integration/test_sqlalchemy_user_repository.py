from pathlib import Path
from unittest.mock import patch
import pytest
from sqlalchemy import text
from backend.core.database.database import DatabaseManager
from backend.infrastructure.persistence.sqlalchemy_user_repository import SQLAlchemyUserRepository
from backend.application.identity.service import HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.domain.security import PrincipalType
from backend.application.identity.service import AuthenticationFailure
from backend.infrastructure.security import hash_secret, hash_token

def test_users_credentials_sessions_survive_repository_reopen(tmp_path: Path):
    db = DatabaseManager(); db.config = {"type": "sqlite", "sqlite_path": str(tmp_path / "users.db"), "echo": False}; db.create_tables()
    repo = SQLAlchemyUserRepository(db); user = HumanIdentityService(repo).create_initial_user("Ops@Example.com", "Operator", "correct horse battery staple")
    token, session, principal = HumanAuthenticationService(repo).authenticate("ops@example.com", "correct horse battery staple")
    assert principal.principal_type is PrincipalType.HUMAN
    db.close(); db2 = DatabaseManager(); db2.config = db.config; db2.initialize_sync_engine()
    restored = HumanSessionAuthenticator(SQLAlchemyUserRepository(db2)).validate(token, session.session_id)
    assert restored.principal_id == str(user.user_id)
    db2.close()


def test_bearer_lookup_uses_indexed_verifier_without_scrypt_scan(tmp_path: Path):
    db = DatabaseManager()
    db.config = {"type": "sqlite", "sqlite_path": str(tmp_path / "bearer.db"), "echo": False}
    db.create_tables()
    repo = SQLAlchemyUserRepository(db)
    user = HumanIdentityService(repo).create_initial_user("a@example.com", "A", "correct horse battery staple")
    token, session, _ = HumanAuthenticationService(repo).authenticate(user.email, "correct horse battery staple")
    assert session.token_verifier == hash_token(token)

    # An existing salted session is not scanned for an arbitrary bearer.
    legacy = repo.get_session(session.session_id)
    legacy.token_verifier = hash_secret("legacy session token")
    repo.update_session(legacy)
    with db.get_db() as connection:
        connection.execute(text("UPDATE human_sessions SET token_verifier = :verifier WHERE session_id = :id"),
                           {"verifier": legacy.token_verifier, "id": str(legacy.session_id)})
    new_token, _, _ = HumanAuthenticationService(repo).authenticate(user.email, "correct horse battery staple")

    with patch("backend.infrastructure.security.secret_verifiers.hashlib.scrypt", side_effect=AssertionError("scrypt bearer scan")):
        assert HumanSessionAuthenticator(repo).authenticate_bearer(new_token).principal_type is PrincipalType.HUMAN
        with pytest.raises(AuthenticationFailure):
            HumanSessionAuthenticator(repo).authenticate_bearer("invalid-bearer")
        with pytest.raises(AuthenticationFailure):
            HumanSessionAuthenticator(repo).authenticate_bearer("A" * 129)

    with db.engine.connect() as connection:
        names = {row[1] for row in connection.exec_driver_sql("PRAGMA index_list(human_sessions)").all()}
    assert "ix_human_sessions_token_verifier" in names
    db.close()


def test_existing_session_table_gains_verifier_index(tmp_path: Path):
    db = DatabaseManager()
    db.config = {"type": "sqlite", "sqlite_path": str(tmp_path / "existing.db"), "echo": False}
    db.create_tables()
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ix_human_sessions_token_verifier")
    db.create_tables()
    with db.engine.connect() as connection:
        names = {row[1] for row in connection.exec_driver_sql("PRAGMA index_list(human_sessions)").all()}
    assert "ix_human_sessions_token_verifier" in names
    db.close()
