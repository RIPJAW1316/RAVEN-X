"""Small deterministic repository useful for unit tests and local composition."""

from dataclasses import replace
from threading import RLock

from ...application.enrollment.service import EnrollmentAlreadyUsedError, EnrollmentExpiredError, EnrollmentRevokedError
from ...application.ports.enrollment_repository import RenewalDecision, RenewalDecisionKind
from ...domain.endpoint import EndpointStatus
from ...domain.enrollment import CredentialId, CredentialRenewal, CredentialStatus, EnrollmentStatus
from ...domain.enrollment.models import ENROLLMENT_RENEWAL_TTL
from ...infrastructure.security import verify_secret


class InMemoryEnrollmentRepository:
    def __init__(self):
        self.authorizations = {}
        self.endpoints = {}
        self.credentials = {}
        # Optional organization directory for lifecycle checks: str(id) -> Organization.
        self.organizations = {}
        # Renewal lineage keyed by successor id, plus the predecessor index.
        self.renewals = {}
        self._successor_by_predecessor = {}
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

    def renew_expired_authorization(self, enrollment_id, organization_id, now):
        with self._lock:
            item = self.get_authorization_for_organization(enrollment_id, organization_id)
            if item is None:
                raise KeyError("enrollment authorization not found")
            if not item.can_renew(now):
                raise ValueError("enrollment authorization cannot be renewed")
            renewed = replace(item, status=EnrollmentStatus.PENDING, expires_at=now + ENROLLMENT_RENEWAL_TTL)
            self.authorizations[str(enrollment_id)] = renewed
            return renewed

    def revoke_authorization_for_organization(self, enrollment_id, organization_id, now):
        with self._lock:
            item = self.get_authorization_for_organization(enrollment_id, organization_id)
            if item is None:
                raise KeyError("enrollment authorization not found")
            if item.status is EnrollmentStatus.REVOKED:
                return False
            if item.status not in (EnrollmentStatus.PENDING, EnrollmentStatus.EXPIRED):
                raise ValueError("enrollment authorization is no longer unused")
            self.authorizations[str(enrollment_id)] = replace(item, status=EnrollmentStatus.REVOKED, revoked_at=now)
            return True

    def revoke_authorization(self, enrollment_id, now):
        with self._lock:
            authorization = self.authorizations.get(str(enrollment_id))
            if authorization is None:
                raise KeyError("enrollment authorization not found")
            if authorization.status is EnrollmentStatus.CONSUMED:
                raise ValueError("consumed enrollment authorization cannot be revoked")
            self.authorizations[str(enrollment_id)] = replace(
                authorization, status=EnrollmentStatus.REVOKED, revoked_at=now
            )

    def expire_authorization(self, enrollment_id, now):
        with self._lock:
            authorization = self.authorizations.get(str(enrollment_id))
            if (authorization is not None and authorization.status is EnrollmentStatus.PENDING
                    and authorization.expires_at <= now):
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
            if authorization.status is EnrollmentStatus.EXPIRED or now >= authorization.expires_at:
                raise EnrollmentExpiredError("enrollment authorization has expired")
            if not verify_secret(presented_token, authorization.token_verifier):
                raise ValueError("invalid enrollment token")
            self.endpoints[str(endpoint.endpoint_id)] = endpoint
            self.credentials[str(credential.credential_id)] = credential
            self.authorizations[str(enrollment_id)] = replace(
                authorization, status=EnrollmentStatus.CONSUMED, consumed_at=now
            )

    def get_endpoint(self, endpoint_id):
        with self._lock:
            return self.endpoints.get(str(endpoint_id))

    def register_organization(self, organization):
        with self._lock:
            self.organizations[str(organization.organization_id)] = organization

    def get_organization_status(self, organization_id):
        with self._lock:
            organization = self.organizations.get(str(organization_id))
            return organization.status.value if organization is not None else None

    def get_credential(self, credential_id):
        with self._lock:
            return self._decorate(self.credentials.get(str(credential_id)))

    def list_credentials(self, endpoint_id):
        with self._lock:
            return tuple(self._decorate(item) for item in self.credentials.values()
                         if str(item.endpoint_id) == str(endpoint_id))

    def get_renewal_for_successor(self, successor_credential_id):
        with self._lock:
            return self.renewals.get(str(successor_credential_id))

    def get_renewal_for_predecessor(self, predecessor_credential_id):
        with self._lock:
            successor_id = self._successor_by_predecessor.get(str(predecessor_credential_id))
            return self.renewals.get(successor_id) if successor_id else None

    def rotate_credential(self, old_credential_id, replacement, now):
        with self._lock:
            old = self.credentials.get(str(old_credential_id))
            if old is None or old.status is not CredentialStatus.ACTIVE:
                raise ValueError("only an active credential can be rotated")
            self.credentials[str(old_credential_id)] = replace(old, status=CredentialStatus.ROTATED, rotated_at=now)
            self.credentials[str(replacement.credential_id)] = replacement

    def renew_credential(self, *, endpoint_id, predecessor_credential_id, successor, now, overlap, renewal_window):
        with self._lock:
            endpoint = self.endpoints.get(str(endpoint_id))
            if endpoint is None or endpoint.status is EndpointStatus.REVOKED:
                return RenewalDecision(RenewalDecisionKind.ENDPOINT_REJECTED)
            if endpoint.status is not EndpointStatus.ACTIVE:
                return RenewalDecision(RenewalDecisionKind.ENDPOINT_NOT_ACTIVE)
            predecessor = self._decorate(self.credentials.get(str(predecessor_credential_id)))
            if predecessor is None or str(predecessor.endpoint_id) != str(endpoint_id) or not predecessor.is_usable(now):
                return RenewalDecision(RenewalDecisionKind.PREDECESSOR_REJECTED)
            existing = self.get_renewal_for_predecessor(predecessor.credential_id)
            if existing is not None:
                kind = (RenewalDecisionKind.EXISTING if existing.successor_credential_id == successor.credential_id
                        else RenewalDecisionKind.CONFLICT)
                return RenewalDecision(kind, existing,
                                       self._decorate(self.credentials.get(str(existing.successor_credential_id))))
            if predecessor.status is not CredentialStatus.ACTIVE:
                return RenewalDecision(RenewalDecisionKind.PREDECESSOR_REJECTED)
            if predecessor.expires_at is not None and predecessor.expires_at - now > renewal_window:
                return RenewalDecision(RenewalDecisionKind.NOT_DUE)
            if str(successor.credential_id) in self.credentials:
                return RenewalDecision(RenewalDecisionKind.CONFLICT)
            valid_until = now + overlap
            if predecessor.expires_at is not None:
                valid_until = min(valid_until, predecessor.expires_at)
            renewal = CredentialRenewal(
                predecessor_credential_id=predecessor.credential_id,
                successor_credential_id=successor.credential_id,
                endpoint_id=endpoint.endpoint_id,
                issued_at=now,
                predecessor_valid_until=valid_until,
                organization_id=endpoint.organization_id,
            )
            raw_predecessor = self.credentials[str(predecessor.credential_id)]
            self.credentials[str(predecessor.credential_id)] = replace(
                raw_predecessor, status=CredentialStatus.ROTATED, rotated_at=now)
            self.credentials[str(successor.credential_id)] = successor
            self.renewals[str(successor.credential_id)] = renewal
            self._successor_by_predecessor[str(predecessor.credential_id)] = str(successor.credential_id)
            return RenewalDecision(RenewalDecisionKind.CREATED, renewal, self._decorate(successor))

    def confirm_credential_renewal(self, successor_credential_id, now):
        with self._lock:
            renewal = self.renewals.get(str(successor_credential_id))
            if renewal is None:
                return None
            if renewal.confirmed_at is None:
                renewal = replace(renewal, confirmed_at=now)
            if renewal.predecessor_closed_at is None:
                renewal = replace(renewal, predecessor_closed_at=now, closed_reason="confirmed")
            self.renewals[str(successor_credential_id)] = renewal
            return renewal

    def list_open_renewal_lineages(self):
        with self._lock:
            return tuple(item for item in self.renewals.values()
                         if item.predecessor_closed_at is None or item.confirmed_at is None)

    def count_active_keyed_verifiers(self) -> int:
        with self._lock:
            return sum(1 for item in self.credentials.values()
                       if item.status is CredentialStatus.ACTIVE
                       and isinstance(item.verifier, str)
                       and item.verifier.startswith("token-hmac-v2$"))

    def revoke_credential(self, credential_id, now, reason=None, cascade_descendants=True):
        with self._lock:
            old = self.credentials.get(str(credential_id))
            if old is None:
                raise KeyError("credential not found")
            revoked = []
            current = old
            while current is not None:
                if str(current.endpoint_id) != str(old.endpoint_id):
                    break
                if current.status is not CredentialStatus.REVOKED:
                    reason_text = reason if str(current.credential_id) == str(old.credential_id) else "lineage_compromise"
                    self.credentials[str(current.credential_id)] = replace(
                        current, status=CredentialStatus.REVOKED, revoked_at=now, revocation_reason=reason_text)
                    revoked.append(current.credential_id if isinstance(current.credential_id, CredentialId)
                                   else CredentialId(str(current.credential_id)))
                as_successor = self.renewals.get(str(current.credential_id))
                if as_successor is not None:
                    self._close_predecessor(as_successor, now, "successor_revoked")
                as_predecessor = self.get_renewal_for_predecessor(current.credential_id)
                if as_predecessor is not None:
                    self._close_predecessor(as_predecessor, now, "predecessor_revoked")
                    if not cascade_descendants:
                        break
                    current = self.credentials.get(str(as_predecessor.successor_credential_id))
                    continue
                break
            return tuple(revoked)

    def _close_predecessor(self, renewal, now, reason):
        if renewal.predecessor_closed_at is None:
            self.renewals[str(renewal.successor_credential_id)] = replace(
                renewal, predecessor_closed_at=now, closed_reason=reason)

    def _decorate(self, credential):
        if credential is None:
            return None
        key = str(credential.credential_id)
        successor_id = self._successor_by_predecessor.get(key)
        return credential.with_renewal_lineage(
            as_successor=self.renewals.get(key),
            as_predecessor=self.renewals.get(successor_id) if successor_id else None,
        )
