"""Transactional SQLAlchemy adapter for enrollment and credential state."""

from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from ...application.enrollment.service import (
    EnrollmentAlreadyUsedError,
    EnrollmentExpiredError,
    EnrollmentRevokedError,
)
from ...application.ports.enrollment_repository import RenewalDecision, RenewalDecisionKind
from ...core.database.database import DatabaseManager
from ...core.database.models import (
    EndpointCredentialRecord,
    EndpointCredentialRenewalRecord,
    EndpointRecord,
    EnrollmentRecord,
    OrganizationRecord,
)
from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus
from ...domain.enrollment import (
    CredentialId,
    CredentialRenewal,
    CredentialStatus,
    EndpointCredential,
    EnrollmentAuthorization,
    EnrollmentId,
    EnrollmentStatus,
)
from ...domain.organization import OrganizationId
from ...domain.enrollment.models import ENROLLMENT_RENEWAL_MAX_AGE, ENROLLMENT_RENEWAL_TTL
from ...infrastructure.security import verify_secret
from .endpoint_mappers import endpoint_to_record, record_to_endpoint
from .enrollment_mappers import (
    authorization_to_record,
    credential_to_record,
    record_to_authorization,
    record_to_credential,
    record_to_renewal,
)
from .write_transaction import begin_serialized_write


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

    def renew_expired_authorization(self, enrollment_id, organization_id, now):
        expires_at = now + ENROLLMENT_RENEWAL_TTL
        scope = (
            EnrollmentRecord.enrollment_id == str(enrollment_id),
            EnrollmentRecord.organization_id == str(OrganizationId.parse(organization_id)),
        )
        with self._database_manager.get_db() as session:
            changed = session.execute(update(EnrollmentRecord).where(
                *scope,
                EnrollmentRecord.status.in_((EnrollmentStatus.PENDING.value, EnrollmentStatus.EXPIRED.value)),
                EnrollmentRecord.expires_at <= _store(now),
                EnrollmentRecord.created_at >= _store(expires_at - ENROLLMENT_RENEWAL_MAX_AGE),
                EnrollmentRecord.consumed_at.is_(None),
                EnrollmentRecord.revoked_at.is_(None),
            ).values(status=EnrollmentStatus.PENDING.value, expires_at=_store(expires_at)))
            record = session.execute(select(EnrollmentRecord).where(*scope)).scalar_one_or_none()
            if record is None:
                raise KeyError("enrollment authorization not found")
            if changed.rowcount != 1:
                raise ValueError("enrollment authorization cannot be renewed")
            return record_to_authorization(record)

    def revoke_authorization_for_organization(self, enrollment_id, organization_id, now):
        owner = str(OrganizationId.parse(organization_id))
        with self._database_manager.get_db() as session:
            changed = session.execute(update(EnrollmentRecord).where(
                EnrollmentRecord.enrollment_id == str(enrollment_id),
                EnrollmentRecord.organization_id == owner,
                EnrollmentRecord.status.in_((EnrollmentStatus.PENDING.value, EnrollmentStatus.EXPIRED.value)),
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
                raise ValueError("enrollment authorization is no longer unused")
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
            session.execute(update(EnrollmentRecord).where(
                EnrollmentRecord.enrollment_id == str(enrollment_id),
                EnrollmentRecord.status == EnrollmentStatus.PENDING.value,
                EnrollmentRecord.expires_at <= _store(now),
            ).values(status=EnrollmentStatus.EXPIRED.value))

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
            if record.status == EnrollmentStatus.EXPIRED.value or _store(now) >= record.expires_at:
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

    def get_organization_status(self, organization_id: OrganizationId) -> Optional[str]:
        with self._database_manager.get_db() as session:
            record = session.get(OrganizationRecord, str(OrganizationId.parse(organization_id)))
            return record.status if record is not None else None

    def get_credential(self, credential_id: CredentialId) -> Optional[EndpointCredential]:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointCredentialRecord, str(credential_id))
            return self._with_lineage(session, record) if record else None

    def list_credentials(self, endpoint_id: EndpointId) -> Tuple[EndpointCredential, ...]:
        with self._database_manager.get_db() as session:
            statement = select(EndpointCredentialRecord).where(
                EndpointCredentialRecord.endpoint_id == str(endpoint_id)
            ).order_by(EndpointCredentialRecord.issued_at, EndpointCredentialRecord.credential_id)
            records = tuple(session.execute(statement).scalars())
            renewals = tuple(record_to_renewal(item) for item in session.execute(
                select(EndpointCredentialRenewalRecord).where(
                    EndpointCredentialRenewalRecord.endpoint_id == str(endpoint_id))).scalars())
            by_successor = {str(item.successor_credential_id): item for item in renewals}
            by_predecessor = {str(item.predecessor_credential_id): item for item in renewals}
            return tuple(record_to_credential(item, as_successor=by_successor.get(item.credential_id),
                                              as_predecessor=by_predecessor.get(item.credential_id))
                         for item in records)

    def get_renewal_for_successor(self, successor_credential_id) -> Optional[CredentialRenewal]:
        with self._database_manager.get_db() as session:
            record = session.get(EndpointCredentialRenewalRecord, str(successor_credential_id))
            return record_to_renewal(record) if record else None

    def get_renewal_for_predecessor(self, predecessor_credential_id) -> Optional[CredentialRenewal]:
        with self._database_manager.get_db() as session:
            record = self._renewal_by_predecessor(session, str(predecessor_credential_id))
            return record_to_renewal(record) if record else None

    def rotate_credential(self, old_credential_id, replacement, now) -> None:
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            old = session.execute(
                select(EndpointCredentialRecord).where(
                    EndpointCredentialRecord.credential_id == str(old_credential_id)
                ).with_for_update()
            ).scalar_one_or_none()
            if old is None or old.status != CredentialStatus.ACTIVE.value:
                raise ValueError("only an active credential can be rotated")
            old.status = CredentialStatus.ROTATED.value
            old.rotated_at = _store(now)
            session.add(credential_to_record(replacement))

    def renew_credential(self, *, endpoint_id, predecessor_credential_id, successor, now, overlap,
                         renewal_window) -> RenewalDecision:
        try:
            with self._database_manager.get_db() as session:
                begin_serialized_write(session)
                return self._renew_serialized(session, str(EndpointId(str(endpoint_id))),
                                              str(predecessor_credential_id), successor, now, overlap,
                                              renewal_window)
        except IntegrityError:
            # Defence in depth: the unique predecessor/successor constraints
            # reject a second lineage even if the serialized checks were bypassed.
            return RenewalDecision(RenewalDecisionKind.CONFLICT)

    def _renew_serialized(self, session, endpoint_id, predecessor_id, successor, now, overlap, renewal_window):
        endpoint = session.execute(select(EndpointRecord).where(
            EndpointRecord.endpoint_id == endpoint_id).with_for_update()).scalar_one_or_none()
        if endpoint is None or endpoint.status == EndpointStatus.REVOKED.value:
            return RenewalDecision(RenewalDecisionKind.ENDPOINT_REJECTED)
        if endpoint.status != EndpointStatus.ACTIVE.value:
            return RenewalDecision(RenewalDecisionKind.ENDPOINT_NOT_ACTIVE)
        predecessor = session.execute(select(EndpointCredentialRecord).where(
            EndpointCredentialRecord.credential_id == predecessor_id).with_for_update()).scalar_one_or_none()
        if predecessor is None or predecessor.endpoint_id != endpoint_id:
            return RenewalDecision(RenewalDecisionKind.PREDECESSOR_REJECTED)
        existing = self._renewal_by_predecessor(session, predecessor_id)
        predecessor_view = self._with_lineage(session, predecessor, as_predecessor=existing)
        if not predecessor_view.is_usable(now):
            return RenewalDecision(RenewalDecisionKind.PREDECESSOR_REJECTED)
        if existing is not None:
            renewal = record_to_renewal(existing)
            current_successor = session.get(EndpointCredentialRecord, existing.successor_credential_id)
            kind = (RenewalDecisionKind.EXISTING if existing.successor_credential_id == str(successor.credential_id)
                    else RenewalDecisionKind.CONFLICT)
            return RenewalDecision(kind, renewal, self._with_lineage(session, current_successor, as_successor=existing)
                                   if current_successor is not None else None)
        if predecessor_view.status is not CredentialStatus.ACTIVE:
            return RenewalDecision(RenewalDecisionKind.PREDECESSOR_REJECTED)
        if predecessor_view.expires_at is not None and predecessor_view.expires_at - now > renewal_window:
            return RenewalDecision(RenewalDecisionKind.NOT_DUE)
        if session.get(EndpointCredentialRecord, str(successor.credential_id)) is not None:
            return RenewalDecision(RenewalDecisionKind.CONFLICT)
        valid_until = now + overlap
        if predecessor_view.expires_at is not None:
            valid_until = min(valid_until, predecessor_view.expires_at)
        renewal = CredentialRenewal(
            predecessor_credential_id=predecessor_view.credential_id,
            successor_credential_id=successor.credential_id,
            endpoint_id=EndpointId(endpoint_id),
            issued_at=now,
            predecessor_valid_until=valid_until,
            organization_id=endpoint.organization_id,
        )
        session.add(credential_to_record(successor))
        session.flush()
        predecessor.status = CredentialStatus.ROTATED.value
        predecessor.rotated_at = _store(now)
        session.add(EndpointCredentialRenewalRecord(
            successor_credential_id=str(renewal.successor_credential_id),
            predecessor_credential_id=str(renewal.predecessor_credential_id),
            endpoint_id=endpoint_id,
            organization_id=endpoint.organization_id,
            issued_at=_store(renewal.issued_at),
            predecessor_valid_until=_store(renewal.predecessor_valid_until),
        ))
        session.flush()
        return RenewalDecision(RenewalDecisionKind.CREATED, renewal,
                               successor.with_renewal_lineage(as_successor=renewal))

    def confirm_credential_renewal(self, successor_credential_id, now) -> Optional[CredentialRenewal]:
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = session.execute(select(EndpointCredentialRenewalRecord).where(
                EndpointCredentialRenewalRecord.successor_credential_id == str(successor_credential_id),
            ).with_for_update()).scalar_one_or_none()
            if record is None:
                return None
            if record.confirmed_at is None:
                record.confirmed_at = _store(now)
            if record.predecessor_closed_at is None:
                record.predecessor_closed_at = _store(now)
                record.closed_reason = "confirmed"
            session.flush()
            return record_to_renewal(record)

    def list_open_renewal_lineages(self):
        with self._database_manager.get_db() as session:
            records = session.execute(select(EndpointCredentialRenewalRecord).order_by(
                EndpointCredentialRenewalRecord.issued_at, EndpointCredentialRenewalRecord.successor_credential_id
            )).scalars()
            return tuple(record_to_renewal(item) for item in records
                         if item.predecessor_closed_at is None or item.confirmed_at is None)

    def count_active_keyed_verifiers(self) -> int:
        with self._database_manager.get_db() as session:
            return int(session.execute(select(func.count()).select_from(EndpointCredentialRecord).where(
                EndpointCredentialRecord.status == CredentialStatus.ACTIVE.value,
                EndpointCredentialRecord.verifier.like("token-hmac-v2$%"),
            )).scalar_one())

    def revoke_credential(self, credential_id, now, reason=None, cascade_descendants=True):
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = session.execute(select(EndpointCredentialRecord).where(
                EndpointCredentialRecord.credential_id == str(credential_id)).with_for_update()).scalar_one_or_none()
            if record is None:
                raise KeyError("credential not found")
            revoked = []
            current = record
            descendant_reason = "lineage_compromise"
            while current is not None:
                if current.endpoint_id != record.endpoint_id:
                    break
                if current.status != CredentialStatus.REVOKED.value:
                    current.status = CredentialStatus.REVOKED.value
                    current.revoked_at = _store(now)
                    current.revocation_reason = reason if current.credential_id == record.credential_id else descendant_reason
                    revoked.append(CredentialId(current.credential_id))
                as_successor = session.get(EndpointCredentialRenewalRecord, current.credential_id)
                if as_successor is not None:
                    self._close_predecessor(as_successor, now, "successor_revoked")
                as_predecessor = self._renewal_by_predecessor(session, current.credential_id)
                if as_predecessor is not None:
                    self._close_predecessor(as_predecessor, now, "predecessor_revoked")
                    if not cascade_descendants:
                        break
                    nxt = session.execute(select(EndpointCredentialRecord).where(
                        EndpointCredentialRecord.credential_id == as_predecessor.successor_credential_id
                    ).with_for_update()).scalar_one_or_none()
                    current = nxt
                    continue
                break
            return tuple(revoked)

    @staticmethod
    def _close_predecessor(record, now, reason) -> None:
        if record.predecessor_closed_at is None:
            record.predecessor_closed_at = _store(now)
            record.closed_reason = reason

    @staticmethod
    def _renewal_by_predecessor(session, predecessor_id):
        return session.execute(select(EndpointCredentialRenewalRecord).where(
            EndpointCredentialRenewalRecord.predecessor_credential_id == predecessor_id,
        )).scalar_one_or_none()

    def _with_lineage(self, session, record, *, as_successor=None, as_predecessor=None):
        if as_successor is None:
            as_successor = session.get(EndpointCredentialRenewalRecord, record.credential_id)
        if as_predecessor is None:
            as_predecessor = self._renewal_by_predecessor(session, record.credential_id)
        return record_to_credential(
            record,
            as_successor=record_to_renewal(as_successor) if as_successor is not None else None,
            as_predecessor=record_to_renewal(as_predecessor) if as_predecessor is not None else None,
        )
