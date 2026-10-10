"""Enrollment and credential application service.

This service establishes identity proof; it does not authorize commands or
provide a network transport.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Tuple

from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus
from ...domain.organization import OrganizationId
from ...domain.enrollment import (
    CredentialId,
    CredentialKind,
    CredentialStatus,
    EndpointCredential,
    EnrollmentAuthorization,
    EnrollmentId,
    EnrollmentRequest,
    EnrollmentStatus,
)
from ...infrastructure.security import generate_secret, hash_secret, hash_token, verify_secret
from ...domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent,
    SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal, PrincipalType,
)


class EnrollmentError(Exception):
    """Base class for explicit enrollment failures."""


class EnrollmentNotFoundError(EnrollmentError): ...
class EnrollmentExpiredError(EnrollmentError): ...
class EnrollmentRevokedError(EnrollmentError): ...
class EnrollmentAlreadyUsedError(EnrollmentError): ...
class CredentialRejectedError(EnrollmentError): ...
class CredentialExpiredError(CredentialRejectedError): ...


class IssuedSecret:
    """A raw secret intentionally returned to the caller once."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or not value:
            raise ValueError("issued secret must not be empty")
        self._value = value

    @property
    def value(self) -> str:
        return self._value

    @property
    def secret(self) -> str:
        """Explicit opt-in alias for callers that name the material secret."""
        return self._value

    def __repr__(self) -> str:
        return "IssuedSecret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def to_dict(self) -> Mapping[str, str]:
        return {"value": "<redacted>"}


class EnrollmentService:
    def __init__(self, repository, *, authorization_service=None, audit_sink=None,
                 principal: Optional[SecurityPrincipal] = None, membership_id: Optional[str] = None):
        self._repository = repository
        self._authorization = authorization_service
        self._audit_sink = audit_sink
        self._principal = principal or SecurityPrincipal.system()
        self._membership_id = membership_id

    def create_enrollment_authorization(
        self,
        *,
        ttl: timedelta = timedelta(hours=1),
        now: Optional[datetime] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        organization_id: Optional[OrganizationId] = None,
    ) -> Tuple[EnrollmentAuthorization, IssuedSecret]:
        now = _utc(now or datetime.now(timezone.utc))
        self._authorize(AuthorizationAction.ENROLLMENT_CREATE, "enrollment", None)
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        raw = generate_secret()
        authorization = EnrollmentAuthorization(
            enrollment_id=EnrollmentId.new(),
            token_verifier=hash_secret(raw),
            status=EnrollmentStatus.PENDING,
            created_at=now,
            expires_at=now + ttl,
            metadata=dict(metadata or {}),
            organization_id=organization_id,
        )
        self._repository.add_authorization(authorization)
        self._audit(SecurityAuditEventType.ENROLLMENT_CREATED, enrollment_id=str(authorization.enrollment_id),
                    organization_id=organization_id)
        return authorization, IssuedSecret(raw)

    def accept_enrollment(
        self,
        enrollment_id: EnrollmentId,
        presented_token: str,
        request: EnrollmentRequest,
        *,
        now: Optional[datetime] = None,
        credential_ttl: timedelta = timedelta(days=30),
    ) -> Tuple[Endpoint, EndpointCredential, IssuedSecret]:
        now = _utc(now or datetime.now(timezone.utc))
        if credential_ttl is None or not timedelta(0) < credential_ttl <= timedelta(days=30):
            raise ValueError("credential_ttl must be between zero and 30 days")
        authorization = self._repository.get_authorization(enrollment_id)
        if authorization is None:
            raise EnrollmentNotFoundError("enrollment authorization not found")
        if authorization.status is EnrollmentStatus.CONSUMED:
            raise EnrollmentAlreadyUsedError("enrollment authorization has already been consumed")
        if authorization.status is EnrollmentStatus.REVOKED:
            raise EnrollmentRevokedError("enrollment authorization has been revoked")
        if now >= authorization.expires_at:
            self._repository.expire_authorization(enrollment_id, now)
            raise EnrollmentExpiredError("enrollment authorization has expired")
        if not verify_secret(presented_token, authorization.token_verifier):
            self._audit(SecurityAuditEventType.ENROLLMENT_CONSUMPTION_FAILED, reason_code="invalid_enrollment_token")
            raise EnrollmentError("invalid enrollment token")

        endpoint_id = EndpointId.new()
        endpoint = Endpoint(
            endpoint_id=endpoint_id,
            hostname=request.hostname,
            platform=request.platform,
            status=EndpointStatus.NEW,
            capabilities=request.capabilities,
            agent=request.agent,
            created_at=now,
            metadata={**dict(request.metadata), "enrollment_id": str(enrollment_id), "capabilities_trust": "unverified"},
            organization_id=authorization.organization_id,
        )
        raw_credential = generate_secret()
        credential = EndpointCredential(
            credential_id=CredentialId.new(),
            endpoint_id=endpoint_id,
            kind=CredentialKind.OPAQUE,
            verifier=hash_token(raw_credential),
            status=CredentialStatus.ACTIVE,
            issued_at=now,
            expires_at=now + credential_ttl,
        )
        self._repository.complete_enrollment(enrollment_id, presented_token, endpoint, credential, now)
        self._audit(SecurityAuditEventType.ENROLLMENT_CONSUMED, endpoint_id=str(endpoint_id),
                    metadata={"enrollment_id": str(enrollment_id)}, organization_id=authorization.organization_id)
        self._audit(SecurityAuditEventType.CREDENTIAL_ISSUED, endpoint_id=str(endpoint_id),
                    metadata={"credential_id": str(credential.credential_id)}, organization_id=authorization.organization_id)
        return endpoint, credential, IssuedSecret(raw_credential)

    def revoke_authorization(self, enrollment_id: EnrollmentId, *, now: Optional[datetime] = None) -> None:
        self._authorize(AuthorizationAction.ENROLLMENT_REVOKE, "enrollment", str(enrollment_id))
        authorization = self._repository.get_authorization(enrollment_id)
        if authorization is None:
            raise EnrollmentNotFoundError("enrollment authorization not found")
        self._repository.revoke_authorization(enrollment_id, _utc(now or datetime.now(timezone.utc)))
        self._audit(SecurityAuditEventType.ENROLLMENT_REVOKED, metadata={"enrollment_id": str(enrollment_id)},
                    organization_id=authorization.organization_id)

    def verify_credential(
        self,
        endpoint_id: EndpointId,
        presented_secret: str,
        *,
        now: Optional[datetime] = None,
    ) -> EndpointCredential:
        now = _utc(now or datetime.now(timezone.utc))
        endpoint = self._repository.get_endpoint(endpoint_id)
        if endpoint is None or endpoint.status is EndpointStatus.REVOKED:
            self._audit_auth(False, endpoint_id, "endpoint_rejected")
            raise CredentialRejectedError("credential rejected")
        for credential in self._repository.list_credentials(endpoint_id):
            if not credential.is_usable(now):
                continue
            if verify_secret(presented_secret, credential.verifier):
                self._audit_auth(True, endpoint_id, "credential_valid")
                return credential
        self._audit_auth(False, endpoint_id, "credential_rejected")
        raise CredentialExpiredError("credential rejected")

    def get_endpoint(self, endpoint_id: EndpointId) -> Optional[Endpoint]:
        return self._repository.get_endpoint(endpoint_id)

    def authorization_organization(self, enrollment_id: EnrollmentId) -> Optional[OrganizationId]:
        authorization = self._repository.get_authorization(enrollment_id)
        return authorization.organization_id if authorization is not None else None

    def verify_presented_credential(
        self,
        credential_id: CredentialId,
        endpoint_id: EndpointId,
        presented_secret: str,
        *,
        now: Optional[datetime] = None,
    ) -> EndpointCredential:
        now = _utc(now or datetime.now(timezone.utc))
        credential = self._repository.get_credential(credential_id)
        endpoint = self._repository.get_endpoint(endpoint_id)
        if endpoint is None or endpoint.status is EndpointStatus.REVOKED:
            self._audit_auth(False, endpoint_id, "endpoint_rejected")
            raise CredentialRejectedError("credential rejected")
        if credential is None or credential.endpoint_id != endpoint_id or not credential.is_usable(now):
            self._audit_auth(False, endpoint_id, "credential_rejected")
            raise CredentialRejectedError("credential rejected")
        if not verify_secret(presented_secret, credential.verifier):
            self._audit_auth(False, endpoint_id, "credential_rejected")
            raise CredentialRejectedError("credential rejected")
        self._audit_auth(True, endpoint_id, "credential_valid")
        return credential

    def rotate_credential(
        self,
        credential_id: CredentialId,
        *,
        now: Optional[datetime] = None,
        ttl: timedelta = timedelta(days=30),
    ) -> Tuple[EndpointCredential, IssuedSecret]:
        now = _utc(now or datetime.now(timezone.utc))
        if ttl is None or not timedelta(0) < ttl <= timedelta(days=30):
            raise ValueError("credential ttl must be between zero and 30 days")
        old = self._repository.get_credential(credential_id)
        if old is None:
            raise CredentialRejectedError("credential not found")
        if old.status is not CredentialStatus.ACTIVE:
            raise CredentialRejectedError("only active credentials can be rotated")
        endpoint = self._repository.get_endpoint(old.endpoint_id)
        if endpoint is None or endpoint.status is EndpointStatus.REVOKED or not old.is_usable(now):
            raise CredentialRejectedError("credential rejected")
        self._authorize(AuthorizationAction.CREDENTIAL_ROTATE, "credential", str(credential_id), endpoint_id=old.endpoint_id)
        raw = generate_secret()
        replacement = EndpointCredential(
            credential_id=CredentialId.new(), endpoint_id=old.endpoint_id, kind=old.kind,
            verifier=hash_token(raw), status=CredentialStatus.ACTIVE, issued_at=now,
            expires_at=now + ttl,
        )
        self._repository.rotate_credential(credential_id, replacement, now)
        self._audit(SecurityAuditEventType.CREDENTIAL_ROTATED, endpoint_id=str(old.endpoint_id),
                    metadata={"credential_id": str(credential_id), "replacement_credential_id": str(replacement.credential_id)})
        return replacement, IssuedSecret(raw)

    def revoke_credential(self, credential_id: CredentialId, *, now: Optional[datetime] = None, reason: Optional[str] = None) -> None:
        credential = self._repository.get_credential(credential_id)
        if credential is None:
            raise CredentialRejectedError("credential not found")
        self._authorize(AuthorizationAction.CREDENTIAL_REVOKE, "credential", str(credential_id), endpoint_id=credential.endpoint_id)
        self._repository.revoke_credential(credential_id, _utc(now or datetime.now(timezone.utc)), reason)
        self._audit(SecurityAuditEventType.CREDENTIAL_REVOKED, endpoint_id=str(credential.endpoint_id),
                    metadata={"credential_id": str(credential_id), "reason": reason})

    def _authorize(self, action, resource_type, resource_id, *, endpoint_id=None):
        if self._authorization is None:
            return
        self._authorization.require(AuthorizationRequest(
            self._principal, action, AuthorizationResource(resource_type, resource_id,
                {"endpoint_id": str(endpoint_id)} if endpoint_id else {})
        ))

    def _audit(self, event_type, *, endpoint_id=None, assessment_id=None, enrollment_id=None,
               reason_code=None, metadata=None, organization_id=None):
        if self._audit_sink is not None:
            self._audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value, principal=self._principal,
                outcome=SecurityAuditOutcome.DENIED if reason_code else SecurityAuditOutcome.SUCCESS,
                reason_code=reason_code, endpoint_id=endpoint_id, assessment_id=assessment_id,
                organization_id=str(organization_id) if organization_id else None,
                user_id=self._principal.principal_id if self._principal.principal_type is PrincipalType.HUMAN else None,
                membership_id=self._membership_id,
                metadata={**(metadata or {}), "enrollment_id": enrollment_id} if enrollment_id else (metadata or {}),
            ))

    def _audit_auth(self, success, endpoint_id, reason):
        self._audit(SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_SUCCEEDED if success else SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_FAILED,
                    endpoint_id=str(endpoint_id), reason_code=None if success else reason)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)
