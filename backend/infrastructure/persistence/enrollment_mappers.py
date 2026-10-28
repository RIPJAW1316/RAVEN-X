"""Mappings for enrollment/credential domain values."""

from datetime import datetime, timezone

from ...core.database.models import EndpointCredentialRecord, EndpointCredentialRenewalRecord, EnrollmentRecord
from ...domain.endpoint import EndpointId
from ...domain.enrollment import (
    CredentialId,
    CredentialKind,
    CredentialRenewal,
    CredentialStatus,
    EndpointCredential,
    EnrollmentAuthorization,
    EnrollmentId,
    EnrollmentStatus,
)


def _store(value):
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value is not None else None


def _load(value, name, required=False):
    if value is None:
        if required:
            raise ValueError(f"persisted {name} is required")
        return None
    if not isinstance(value, datetime):
        raise ValueError(f"persisted {name} must be a datetime")
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def authorization_to_record(value: EnrollmentAuthorization) -> EnrollmentRecord:
    return EnrollmentRecord(
        enrollment_id=str(value.enrollment_id), token_verifier=value.token_verifier,
        organization_id=str(value.organization_id) if value.organization_id else None,
        status=value.status.value, created_at=_store(value.created_at), expires_at=_store(value.expires_at),
        consumed_at=_store(value.consumed_at), revoked_at=_store(value.revoked_at),
        enrollment_metadata=dict(value.metadata),
    )


def record_to_authorization(record: EnrollmentRecord) -> EnrollmentAuthorization:
    try:
        status = EnrollmentStatus(record.status)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid persisted enrollment status") from error
    return EnrollmentAuthorization(
        enrollment_id=EnrollmentId(record.enrollment_id), token_verifier=record.token_verifier,
        organization_id=record.organization_id,
        status=status, created_at=_load(record.created_at, "created_at", True),
        expires_at=_load(record.expires_at, "expires_at", True), consumed_at=_load(record.consumed_at, "consumed_at"),
        revoked_at=_load(record.revoked_at, "revoked_at"), metadata=dict(record.enrollment_metadata or {}),
    )


def credential_to_record(value: EndpointCredential) -> EndpointCredentialRecord:
    return EndpointCredentialRecord(
        credential_id=str(value.credential_id), endpoint_id=str(value.endpoint_id),
        credential_kind=value.kind.value, verifier=value.verifier, status=value.status.value,
        issued_at=_store(value.issued_at), expires_at=_store(value.expires_at), rotated_at=_store(value.rotated_at),
        revoked_at=_store(value.revoked_at), revocation_reason=value.revocation_reason,
        credential_metadata=dict(value.metadata),
    )


def record_to_credential(record: EndpointCredentialRecord, *, as_successor: CredentialRenewal = None,
                         as_predecessor: CredentialRenewal = None) -> EndpointCredential:
    try:
        kind = CredentialKind(record.credential_kind)
        status = CredentialStatus(record.status)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid persisted credential state") from error
    credential = EndpointCredential(
        credential_id=CredentialId(record.credential_id), endpoint_id=EndpointId(record.endpoint_id), kind=kind,
        verifier=record.verifier, status=status,
        issued_at=_load(record.issued_at, "issued_at", True), expires_at=_load(record.expires_at, "expires_at"),
        rotated_at=_load(record.rotated_at, "rotated_at"), revoked_at=_load(record.revoked_at, "revoked_at"),
        revocation_reason=record.revocation_reason, metadata=dict(record.credential_metadata or {}),
    )
    if as_successor is None and as_predecessor is None:
        return credential
    return credential.with_renewal_lineage(as_successor=as_successor, as_predecessor=as_predecessor)


def renewal_to_record(value: CredentialRenewal) -> EndpointCredentialRenewalRecord:
    return EndpointCredentialRenewalRecord(
        successor_credential_id=str(value.successor_credential_id),
        predecessor_credential_id=str(value.predecessor_credential_id),
        endpoint_id=str(value.endpoint_id),
        organization_id=str(value.organization_id) if value.organization_id else None,
        issued_at=_store(value.issued_at), predecessor_valid_until=_store(value.predecessor_valid_until),
        confirmed_at=_store(value.confirmed_at), predecessor_closed_at=_store(value.predecessor_closed_at),
        closed_reason=value.closed_reason,
    )


def record_to_renewal(record: EndpointCredentialRenewalRecord) -> CredentialRenewal:
    return CredentialRenewal(
        predecessor_credential_id=CredentialId(record.predecessor_credential_id),
        successor_credential_id=CredentialId(record.successor_credential_id),
        endpoint_id=EndpointId(record.endpoint_id),
        issued_at=_load(record.issued_at, "issued_at", True),
        predecessor_valid_until=_load(record.predecessor_valid_until, "predecessor_valid_until", True),
        organization_id=record.organization_id,
        confirmed_at=_load(record.confirmed_at, "confirmed_at"),
        predecessor_closed_at=_load(record.predecessor_closed_at, "predecessor_closed_at"),
        closed_reason=record.closed_reason,
    )
