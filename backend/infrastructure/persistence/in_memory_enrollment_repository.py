"""Small deterministic repository useful for unit tests and local composition."""

from threading import RLock

from ...application.enrollment.service import EnrollmentAlreadyUsedError, EnrollmentExpiredError, EnrollmentRevokedError
from ...domain.enrollment import EnrollmentStatus
from ...infrastructure.security import verify_secret


class InMemoryEnrollmentRepository:
    def __init__(self):
        self.authorizations = {}
        self.endpoints = {}
        self.credentials = {}
        self._lock = RLock()

    def add_authorization(self, authorization):
        with self._lock:
            self.authorizations[str(authorization.enrollment_id)] = authorization

    def get_authorization(self, enrollment_id):
        with self._lock:
            return self.authorizations.get(str(enrollment_id))

    def get_authorization_for_organization(self, enrollment_id, organization_id):
        with self._lock:
            item = self.authorizations.get(str(enrollment_id))
            return item if item is not None and str(item.organization_id) == str(organization_id) else None

    def list_authorizations_for_organization(self, organization_id):
        with self._lock:
            return tuple(sorted(
                (item for item in self.authorizations.values() if str(item.organization_id) == str(organization_id)),
                key=lambda item: (item.created_at, str(item.enrollment_id)), reverse=True,
            ))

    def revoke_authorization_for_organization(self, enrollment_id, organization_id, now):
        with self._lock:
            item = self.get_authorization_for_organization(enrollment_id, organization_id)
            if item is None:
                raise KeyError("enrollment authorization not found")
            if item.status is EnrollmentStatus.REVOKED:
                return False
            if item.status is not EnrollmentStatus.PENDING:
                raise ValueError("enrollment authorization is no longer pending")
            from dataclasses import replace
            self.authorizations[str(enrollment_id)] = replace(item, status=EnrollmentStatus.REVOKED, revoked_at=now)
            return True

    def revoke_authorization(self, enrollment_id, now):
        with self._lock:
            authorization = self.authorizations.get(str(enrollment_id))
            if authorization is None:
                raise KeyError("enrollment authorization not found")
            if authorization.status is EnrollmentStatus.CONSUMED:
                raise ValueError("consumed enrollment authorization cannot be revoked")
            from dataclasses import replace
            self.authorizations[str(enrollment_id)] = replace(
                authorization, status=EnrollmentStatus.REVOKED, revoked_at=now
            )

    def expire_authorization(self, enrollment_id, now):
        with self._lock:
            authorization = self.authorizations.get(str(enrollment_id))
            if authorization is not None and authorization.status is EnrollmentStatus.PENDING:
                from dataclasses import replace
                self.authorizations[str(enrollment_id)] = replace(authorization, status=EnrollmentStatus.EXPIRED)

    def complete_enrollment(self, enrollment_id, presented_token, endpoint, credential, now):
        with self._lock:
            authorization = self.authorizations.get(str(enrollment_id))
            if authorization is None:
                raise KeyError("enrollment authorization not found")
            if authorization.status is EnrollmentStatus.CONSUMED:
                raise EnrollmentAlreadyUsedError("enrollment authorization has already been consumed")
            if authorization.status is EnrollmentStatus.REVOKED:
                raise EnrollmentRevokedError("enrollment authorization has been revoked")
            if now >= authorization.expires_at:
                raise EnrollmentExpiredError("enrollment authorization has expired")
            if not verify_secret(presented_token, authorization.token_verifier):
                raise ValueError("invalid enrollment token")
            from dataclasses import replace
            self.endpoints[str(endpoint.endpoint_id)] = endpoint
            self.credentials[str(credential.credential_id)] = credential
            self.authorizations[str(enrollment_id)] = replace(
                authorization, status=EnrollmentStatus.CONSUMED, consumed_at=now
            )

    def get_endpoint(self, endpoint_id):
        return self.endpoints.get(str(endpoint_id))

    def get_credential(self, credential_id):
        return self.credentials.get(str(credential_id))

    def list_credentials(self, endpoint_id):
        return tuple(item for item in self.credentials.values() if str(item.endpoint_id) == str(endpoint_id))

    def rotate_credential(self, old_credential_id, replacement, now):
        with self._lock:
            old = self.credentials.get(str(old_credential_id))
            if old is None or old.status.value != "active":
                raise ValueError("only an active credential can be rotated")
            from dataclasses import replace
            self.credentials[str(old_credential_id)] = replace(old, status=old.status.ROTATED, rotated_at=now)
            self.credentials[str(replacement.credential_id)] = replacement

    def revoke_credential(self, credential_id, now, reason=None):
        with self._lock:
            old = self.credentials.get(str(credential_id))
            if old is None:
                raise KeyError("credential not found")
            from dataclasses import replace
            self.credentials[str(credential_id)] = replace(old, status=old.status.REVOKED, revoked_at=now, revocation_reason=reason)
