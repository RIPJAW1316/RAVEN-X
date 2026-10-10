from datetime import datetime, timedelta, timezone

import pytest

from backend.application.enrollment import (
    CredentialExpiredError,
    CredentialRejectedError,
    EnrollmentAlreadyUsedError,
    EnrollmentError,
    EnrollmentExpiredError,
    EnrollmentService,
)
from backend.domain.endpoint import EndpointId, EndpointStatus, PlatformInfo
from backend.domain.enrollment import CredentialStatus, EnrollmentRequest, EnrollmentStatus
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _service():
    repository = InMemoryEnrollmentRepository()
    return EnrollmentService(repository), repository


def _request():
    return EnrollmentRequest(hostname="workstation", platform=PlatformInfo("Windows", "11", "x86_64"))


def test_token_is_one_way_single_use_and_redacted():
    service, repository = _service()
    authorization, token = service.create_enrollment_authorization(now=NOW)
    assert token.value not in repr(token)
    assert token.value not in repr(authorization)
    assert token.value not in repository.authorizations[str(authorization.enrollment_id)].token_verifier
    endpoint, _, credential_secret = service.accept_enrollment(authorization.enrollment_id, token.value, _request(), now=NOW)
    assert repository.authorizations[str(authorization.enrollment_id)].status is EnrollmentStatus.CONSUMED
    with pytest.raises(EnrollmentAlreadyUsedError):
        service.accept_enrollment(authorization.enrollment_id, token.value, _request(), now=NOW)
    assert service.verify_credential(endpoint.endpoint_id, credential_secret.value, now=NOW)


def test_invalid_and_expired_tokens_fail():
    service, repository = _service()
    authorization, token = service.create_enrollment_authorization(now=NOW, ttl=timedelta(minutes=1))
    with pytest.raises(EnrollmentError):
        service.accept_enrollment(authorization.enrollment_id, "wrong", _request(), now=NOW)
    with pytest.raises(EnrollmentExpiredError):
        service.accept_enrollment(authorization.enrollment_id, token.value, _request(), now=NOW + timedelta(minutes=1))
    assert repository.authorizations[str(authorization.enrollment_id)].status is EnrollmentStatus.EXPIRED


def test_rotation_and_endpoint_revocation_reject_old_secret():
    service, repository = _service()
    authorization, token = service.create_enrollment_authorization(now=NOW)
    endpoint, credential, secret = service.accept_enrollment(authorization.enrollment_id, token.value, _request(), now=NOW)
    replacement, replacement_secret = service.rotate_credential(credential.credential_id, now=NOW)
    assert repository.credentials[str(credential.credential_id)].status is CredentialStatus.ROTATED
    with pytest.raises(CredentialRejectedError):
        service.verify_credential(endpoint.endpoint_id, secret.value, now=NOW)
    assert service.verify_credential(endpoint.endpoint_id, replacement_secret.value, now=NOW).credential_id == replacement.credential_id
    repository.endpoints[str(endpoint.endpoint_id)] = endpoint.transition_to(EndpointStatus.REVOKED, NOW)
    with pytest.raises(CredentialRejectedError):
        service.verify_credential(endpoint.endpoint_id, replacement_secret.value, now=NOW)


def test_credential_expiry_and_wrong_endpoint_are_rejected():
    service, _ = _service()
    authorization, token = service.create_enrollment_authorization(now=NOW)
    endpoint, _, secret = service.accept_enrollment(
        authorization.enrollment_id, token.value, _request(), now=NOW,
        credential_ttl=timedelta(minutes=1),
    )
    with pytest.raises(CredentialExpiredError):
        service.verify_credential(endpoint.endpoint_id, secret.value, now=NOW + timedelta(minutes=1))
    with pytest.raises(CredentialRejectedError):
        service.verify_credential(EndpointId.new(), secret.value, now=NOW)


def test_enrollment_revocation_is_explicit():
    service, repository = _service()
    authorization, _ = service.create_enrollment_authorization(now=NOW)
    service.revoke_authorization(authorization.enrollment_id, now=NOW)
    assert repository.authorizations[str(authorization.enrollment_id)].status is EnrollmentStatus.REVOKED
