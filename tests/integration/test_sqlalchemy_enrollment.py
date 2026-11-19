from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import secrets
from threading import Barrier

import pytest
from sqlalchemy import select

from backend.application.enrollment import (
    CredentialRejectedError,
    CredentialRenewalConflictError,
    EnrollmentService,
)
from backend.core.database.database import DatabaseManager
from backend.core.database.models import EndpointCredentialRecord, EndpointRecord, EnrollmentRecord
from backend.domain.endpoint import EndpointStatus, PlatformInfo
from backend.domain.enrollment import CredentialId, EnrollmentRequest, EnrollmentStatus
from backend.domain.organization import Organization, OrganizationId
from backend.infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository
from backend.infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


def _manager(tmp_path):
    path = tmp_path / "enrollment.db"
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '%s'\n" % path.as_posix(), encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def test_expired_authorization_renews_in_place_once_under_concurrency(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyEnrollmentRepository(manager)
    organization = Organization(OrganizationId.new(), "Renewal test", created_at=NOW, updated_at=NOW)
    SQLAlchemyOrganizationRepository(manager).add(organization)
    service = EnrollmentService(repository)
    invitation, secret = service.create_enrollment_authorization(
        now=NOW, ttl=timedelta(minutes=1), organization_id=organization.organization_id,
    )
    expired_at = NOW + timedelta(minutes=1)
    repository.expire_authorization(invitation.enrollment_id, expired_at)
    barrier = Barrier(2)

    def renew():
        barrier.wait(timeout=5)
        try:
            return repository.renew_expired_authorization(
                invitation.enrollment_id, organization.organization_id, expired_at,
            )
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(renew)
        second = pool.submit(renew)
        renewed, = [item for item in (first.result(), second.result()) if item is not None]

    assert renewed.enrollment_id == invitation.enrollment_id
    assert renewed.created_at == invitation.created_at
    assert renewed.token_verifier == invitation.token_verifier
    assert renewed.expires_at == expired_at + timedelta(minutes=30)
    repository.expire_authorization(invitation.enrollment_id, expired_at)
    assert repository.get_authorization(invitation.enrollment_id).status is EnrollmentStatus.PENDING
    service.accept_enrollment(invitation.enrollment_id, secret.value,
                              EnrollmentRequest("renewed-sql-host", PlatformInfo("Windows")), now=expired_at)
    with pytest.raises(ValueError, match="cannot be renewed"):
        repository.renew_expired_authorization(invitation.enrollment_id, organization.organization_id,
                                              expired_at + timedelta(hours=1))


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


def test_sql_credential_renewal_overlap_and_confirmation_survive_restart(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyEnrollmentRepository(manager)
    verifier_key = secrets.token_bytes(32)
    service = EnrollmentService(repository, verifier_key=verifier_key)
    organization = Organization(OrganizationId.new(), "SQL renew tenant", created_at=NOW, updated_at=NOW)
    SQLAlchemyOrganizationRepository(manager).add(organization)
    authorization, token = service.create_enrollment_authorization(
        now=NOW, organization_id=organization.organization_id)
    endpoint, credential, secret = service.accept_enrollment(
        authorization.enrollment_id,
        token.value,
        EnrollmentRequest("sql-renew-host", PlatformInfo("Windows")),
        now=NOW,
    )
    with manager.get_db() as session:
        ep_row = session.get(EndpointRecord, str(endpoint.endpoint_id))
        ep_row.status = EndpointStatus.ACTIVE.value

    successor_id, successor_secret = CredentialId.new(), secrets.token_urlsafe(32)
    first = service.renew_credential(
        endpoint.endpoint_id, secret.value,
        claimed_credential_id=credential.credential_id,
        successor_credential_id=successor_id, successor_secret=successor_secret,
        now=NOW + timedelta(days=25),
    )
    assert first.created is True
    deadline = first.renewal.predecessor_valid_until

    # Simulate server restart. The lost-response retry must be idempotent.
    reloaded = EnrollmentService(SQLAlchemyEnrollmentRepository(manager), verifier_key=verifier_key)
    assert reloaded.verify_credential(
        endpoint.endpoint_id, secret.value, now=NOW + timedelta(days=25, minutes=2)
    ).credential_id == credential.credential_id
    retry = reloaded.renew_credential(
        endpoint.endpoint_id, secret.value,
        claimed_credential_id=credential.credential_id,
        successor_credential_id=successor_id, successor_secret=successor_secret,
        now=NOW + timedelta(days=25, minutes=3),
    )
    assert retry.created is False
    assert retry.credential.credential_id == successor_id
    assert retry.renewal.predecessor_valid_until == deadline
    with pytest.raises(CredentialRenewalConflictError):
        reloaded.renew_credential(
            endpoint.endpoint_id, secret.value,
            claimed_credential_id=credential.credential_id,
            successor_credential_id=CredentialId.new(), successor_secret=secrets.token_urlsafe(32),
            now=NOW + timedelta(days=25, minutes=3),
        )

    reloaded.confirm_credential_renewal(
        endpoint.endpoint_id,
        successor_secret,
        now=NOW + timedelta(days=25, minutes=4),
        claimed_credential_id=successor_id,
        replaces_credential_id=credential.credential_id,
    )
    reloaded_again = EnrollmentService(SQLAlchemyEnrollmentRepository(manager), verifier_key=verifier_key)
    with pytest.raises(CredentialRejectedError):
        reloaded_again.verify_credential(
            endpoint.endpoint_id, secret.value, now=NOW + timedelta(days=25, minutes=4)
        )
    assert reloaded_again.verify_credential(
        endpoint.endpoint_id, successor_secret, now=NOW + timedelta(days=25, minutes=4)
    ).credential_id == successor_id

    reloaded_again.revoke_compromised_credential(
        credential.credential_id, now=NOW + timedelta(days=25, minutes=5), reason="sql lineage")
    with pytest.raises(CredentialRejectedError):
        reloaded_again.verify_credential(
            endpoint.endpoint_id, successor_secret, now=NOW + timedelta(days=25, minutes=5)
        )
    manager.close()
