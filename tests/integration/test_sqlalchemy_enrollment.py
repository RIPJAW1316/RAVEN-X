from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from backend.application.enrollment import CredentialRejectedError, EnrollmentService
from backend.core.database.database import DatabaseManager
from backend.core.database.models import EndpointCredentialRecord, EndpointRecord, EnrollmentRecord
from backend.domain.endpoint import EndpointStatus, PlatformInfo
from backend.domain.enrollment import EnrollmentRequest, EnrollmentStatus
from backend.infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


def _manager(tmp_path):
    path = tmp_path / "enrollment.db"
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def test_enrollment_and_credential_survive_reload_and_endpoint_revoke(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyEnrollmentRepository(manager)
    service = EnrollmentService(repository)
    authorization, token = service.create_enrollment_authorization(now=NOW)
    endpoint, credential, credential_secret = service.accept_enrollment(
        authorization.enrollment_id,
        token.value,
        EnrollmentRequest("sql-host", PlatformInfo("Windows", "11", "x86_64")),
        now=NOW,
    )

    with manager.get_db() as session:
        stored = session.get(EnrollmentRecord, str(authorization.enrollment_id))
        assert stored.status == EnrollmentStatus.CONSUMED.value
        assert token.value not in stored.token_verifier
        stored_credential = session.get(EndpointCredentialRecord, str(credential.credential_id))
        assert credential_secret.value not in stored_credential.verifier

    reloaded = SQLAlchemyEnrollmentRepository(manager)
    service2 = EnrollmentService(reloaded)
    assert service2.verify_credential(endpoint.endpoint_id, credential_secret.value, now=NOW).credential_id == credential.credential_id

    with manager.get_db() as session:
        record = session.get(EndpointRecord, str(endpoint.endpoint_id))
        record.status = EndpointStatus.REVOKED.value
    with pytest.raises(CredentialRejectedError):
        service2.verify_credential(endpoint.endpoint_id, credential_secret.value, now=NOW)


def test_credential_rotation_and_revocation_are_durable(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyEnrollmentRepository(manager)
    service = EnrollmentService(repository)
    authorization, token = service.create_enrollment_authorization(now=NOW)
    endpoint, credential, secret = service.accept_enrollment(
        authorization.enrollment_id, token.value,
        EnrollmentRequest("rotate-host", PlatformInfo("Windows")), now=NOW,
    )
    replacement, replacement_secret = service.rotate_credential(credential.credential_id, now=NOW)
    assert service.verify_credential(endpoint.endpoint_id, replacement_secret.value, now=NOW).credential_id == replacement.credential_id
    with pytest.raises(CredentialRejectedError):
        service.verify_credential(endpoint.endpoint_id, secret.value, now=NOW)
    service.revoke_credential(replacement.credential_id, now=NOW, reason="test")
    reloaded = EnrollmentService(SQLAlchemyEnrollmentRepository(manager))
    with pytest.raises(CredentialRejectedError):
        reloaded.verify_credential(endpoint.endpoint_id, replacement_secret.value, now=NOW)
