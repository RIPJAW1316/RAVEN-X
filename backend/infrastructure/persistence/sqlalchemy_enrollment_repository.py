"""Transactional SQLAlchemy adapter for enrollment and credential state."""

from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import select, update

from ...application.enrollment.service import (
    EnrollmentAlreadyUsedError,
    EnrollmentExpiredError,
    EnrollmentRevokedError,
)
from ...core.database.database import DatabaseManager
from ...core.database.models import EndpointCredentialRecord, EndpointRecord, EnrollmentRecord
from ...domain.endpoint import Endpoint, EndpointId
from ...domain.enrollment import CredentialId, EndpointCredential, EnrollmentAuthorization, EnrollmentId, EnrollmentStatus
from ...domain.organization import OrganizationId
from ...infrastructure.security import verify_secret
from .endpoint_mappers import endpoint_to_record, record_to_endpoint
from .enrollment_mappers import (
    authorization_to_record,
    credential_to_record,
    record_to_authorization,
    record_to_credential,
)


def _store(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


class SQLAlchemyEnrollmentRepository:
    def __init__(self, database_manager: DatabaseManager):
        self._database_manager = database_manager

    def add_authorization(self, authorization: EnrollmentAuthorization) -> None:
        with self._database_manager.get_db() as session:
            session.add(authorization_to_record(authorization))

    def get_authorization(self, enrollment_id: EnrollmentId) -> Optional[EnrollmentAuthorization]:
        with self._database_manager.get_db() as session:
            record = session.get(EnrollmentRecord, str(enrollment_id))
            return record_to_authorization(record) if record else None

    def get_authorization_for_organization(self, enrollment_id, organization_id):
        with self._database_manager.get_db() as session:
            record = session.execute(select(EnrollmentRecord).where(
                EnrollmentRecord.enrollment_id == str(enrollment_id),
                EnrollmentRecord.organization_id == str(OrganizationId.parse(organization_id)),
            )).scalar_one_or_none()
            return record_to_authorization(record) if record else None

    def list_authorizations_for_organization(self, organization_id):
        with self._database_manager.get_db() as session:
            records = session.execute(select(EnrollmentRecord).where(
                EnrollmentRecord.organization_id == str(OrganizationId.parse(organization_id)),
            ).order_by(EnrollmentRecord.created_at.desc(), EnrollmentRecord.enrollment_id)).scalars()
            return tuple(record_to_authorization(record) for record in records)

    def revoke_authorization_for_organization(self, enrollment_id, organization_id, now):
        owner = str(OrganizationId.parse(organization_id))
        with self._database_manager.get_db() as session:
            changed = session.execute(update(EnrollmentRecord).where(
                EnrollmentRecord.enrollment_id == str(enrollment_id),
                EnrollmentRecord.organization_id == owner,
                EnrollmentRecord.status == EnrollmentStatus.PENDING.value,
            ).values(status=EnrollmentStatus.REVOKED.value, revoked_at=_store(now)))
            if changed.rowcount == 1:
                return True
            record = session.execute(select(EnrollmentRecord).where(
                EnrollmentRecord.enrollment_id == str(enrollment_id),
                EnrollmentRecord.organization_id == owner,
            )).scalar_one_or_none()
            if record is None:
                raise KeyError("enrollment authorization not found")
            if record.status != EnrollmentStatus.REVOKED.value:
                raise ValueError("enrollment authorization is no longer pending")
            return False

    def revoke_authorization(self, enrollment_id: EnrollmentId, now) -> None:
        with self._database_manager.get_db() as session:
            record = session.get(EnrollmentRecord, str(enrollment_id))
            if record is None:
                raise KeyError("enrollment authorization not found")
            if record.status == EnrollmentStatus.CONSUMED.value:
                raise ValueError("consumed enrollment authorization cannot be revoked")
            record.status = EnrollmentStatus.REVOKED.value
            record.revoked_at = _store(now)

    def expire_authorization(self, enrollment_id: EnrollmentId, now) -> None:
        with self._database_manager.get_db() as session:
            record = session.get(EnrollmentRecord, str(enrollment_id))
            if record is not None and record.status == EnrollmentStatus.PENDING.value:
                record.status = EnrollmentStatus.EXPIRED.value

    def complete_enrollment(self, enrollment_id, presented_token, endpoint, credential, now) -> None:
        with self._database_manager.get_db() as session:
            record = session.execute(
                select(EnrollmentRecord).where(EnrollmentRecord.enrollment_id == str(enrollment_id))
            ).scalar_one_or_none()
            if record is None:
                raise KeyError("enrollment authorization not found")
            if record.status == EnrollmentStatus.CONSUMED.value:
                raise EnrollmentAlreadyUsedError("enrollment authorization has already been consumed")
            if record.status == EnrollmentStatus.REVOKED.value:
                raise EnrollmentRevokedError("enrollment authorization has been revoked")
            if _store(now) >= record.expires_at:
                raise EnrollmentExpiredError("enrollment authorization has expired")
            if not verify_secret(presented_token, record.token_verifier):
                raise ValueError("invalid enrollment token")
            if endpoint.organization_id != (OrganizationId.parse(record.organization_id) if record.organization_id else None):
                raise ValueError("endpoint organization does not match enrollment authorization")
            if session.get(EndpointRecord, str(endpoint.endpoint_id)) is not None:
                raise ValueError("endpoint identity already exists")
            # SQLite ignores SELECT FOR UPDATE.  This conditional write is the
            # single-use claim; insertion below remains in the same transaction.
            claimed = session.execute(update(EnrollmentRecord).where(
                EnrollmentRecord.enrollment_id == str(enrollment_id),
                EnrollmentRecord.status == EnrollmentStatus.PENDING.value,
                EnrollmentRecord.expires_at > _store(now),
            ).values(status=EnrollmentStatus.CONSUMED.value, consumed_at=_store(now)))
            if claimed.rowcount != 1:
                raise EnrollmentAlreadyUsedError("enrollment authorization is no longer usable")
            session.add(endpoint_to_record(endpoint))
            session.add(credential_to_record(credential))

    def get_endpoint(self, endpoint_id: EndpointId) -> Optional[Endpoint]:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointRecord, str(endpoint_id))
            return record_to_endpoint(record) if record else None

    def get_credential(self, credential_id: CredentialId) -> Optional[EndpointCredential]:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointCredentialRecord, str(credential_id))
            return record_to_credential(record) if record else None

    def list_credentials(self, endpoint_id: EndpointId) -> Tuple[EndpointCredential, ...]:
        with self._database_manager.get_db() as session:
            statement = select(EndpointCredentialRecord).where(
                EndpointCredentialRecord.endpoint_id == str(endpoint_id)
            ).order_by(EndpointCredentialRecord.issued_at, EndpointCredentialRecord.credential_id)
            return tuple(record_to_credential(item) for item in session.execute(statement).scalars())

    def rotate_credential(self, old_credential_id, replacement, now) -> None:
        with self._database_manager.get_db() as session:
            old = session.execute(
                select(EndpointCredentialRecord).where(
                    EndpointCredentialRecord.credential_id == str(old_credential_id)
                ).with_for_update()
            ).scalar_one_or_none()
            if old is None or old.status != "active":
                raise ValueError("only an active credential can be rotated")
            old.status = "rotated"
            old.rotated_at = _store(now)
            session.add(credential_to_record(replacement))

    def revoke_credential(self, credential_id, now, reason=None) -> None:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointCredentialRecord, str(credential_id))
            if record is None:
                raise KeyError("credential not found")
            record.status = "revoked"
            record.revoked_at = _store(now)
            record.revocation_reason = reason
