"""Persistence boundary for enrollment and machine credentials."""

from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Optional, Protocol, Tuple

from ...domain.endpoint import Endpoint, EndpointId
from ...domain.organization import OrganizationId
from ...domain.enrollment import (
    CredentialId,
    CredentialRenewal,
    EndpointCredential,
    EnrollmentAuthorization,
    EnrollmentId,
)


class RenewalDecisionKind(str, Enum):
    """Outcome of one serialized renewal transaction."""

    CREATED = "created"                        # successor inserted, predecessor rotated
    EXISTING = "existing"                      # predecessor already renewed to the proposed successor
    CONFLICT = "conflict"                      # predecessor already renewed to a different successor
    NOT_DUE = "not_due"                        # predecessor is outside the renewal window
    ENDPOINT_REJECTED = "endpoint_rejected"    # endpoint missing or revoked
    ENDPOINT_NOT_ACTIVE = "endpoint_not_active"
    PREDECESSOR_REJECTED = "predecessor_rejected"


@dataclass(frozen=True)
class RenewalDecision:
    kind: RenewalDecisionKind
    renewal: Optional[CredentialRenewal] = None
    successor: Optional[EndpointCredential] = None


class EnrollmentRepository(Protocol):
    def add_authorization(self, authorization: EnrollmentAuthorization) -> None: ...
    def get_authorization(self, enrollment_id: EnrollmentId) -> Optional[EnrollmentAuthorization]: ...
    def get_authorization_for_organization(self, enrollment_id: EnrollmentId, organization_id: OrganizationId) -> Optional[EnrollmentAuthorization]: ...
    def list_authorizations_for_organization(self, organization_id: OrganizationId) -> Tuple[EnrollmentAuthorization, ...]: ...
    def renew_expired_authorization(self, enrollment_id: EnrollmentId, organization_id: OrganizationId, now) -> EnrollmentAuthorization: ...
    def revoke_authorization_for_organization(self, enrollment_id: EnrollmentId, organization_id: OrganizationId, now) -> bool: ...
    def revoke_authorization(self, enrollment_id: EnrollmentId, now) -> None: ...
    def expire_authorization(self, enrollment_id: EnrollmentId, now) -> None: ...
    def complete_enrollment(
        self,
        enrollment_id: EnrollmentId,
        presented_token: str,
        endpoint: Endpoint,
        credential: EndpointCredential,
        now,
    ) -> None: ...
    def get_endpoint(self, endpoint_id: EndpointId) -> Optional[Endpoint]: ...
    def get_organization_status(self, organization_id: OrganizationId) -> Optional[str]: ...
    def get_credential(self, credential_id: CredentialId) -> Optional[EndpointCredential]: ...
    def list_credentials(self, endpoint_id: EndpointId) -> Tuple[EndpointCredential, ...]: ...
    def rotate_credential(
        self,
        old_credential_id: CredentialId,
        replacement: EndpointCredential,
        now,
    ) -> None: ...
    def renew_credential(
        self,
        *,
        endpoint_id: EndpointId,
        predecessor_credential_id: CredentialId,
        successor: EndpointCredential,
        now,
        overlap: timedelta,
        renewal_window: timedelta,
    ) -> RenewalDecision:
        """Atomically re-validate and either insert the successor or report the existing lineage."""
    def confirm_credential_renewal(self, successor_credential_id: CredentialId, now) -> Optional[CredentialRenewal]:
        """Record first proof of successor possession and permanently close the predecessor window."""
    def get_renewal_for_successor(self, successor_credential_id: CredentialId) -> Optional[CredentialRenewal]: ...
    def get_renewal_for_predecessor(self, predecessor_credential_id: CredentialId) -> Optional[CredentialRenewal]: ...
    def revoke_credential(self, credential_id: CredentialId, now, reason: Optional[str] = None,
                          cascade_descendants: bool = True) -> Tuple[CredentialId, ...]:
        """Revoke the credential and, by default, every same-endpoint descendant."""
    def list_open_renewal_lineages(self) -> Tuple[CredentialRenewal, ...]:
        """Renewals whose predecessor window is still open or unconfirmed."""
    def count_active_keyed_verifiers(self) -> int:
        """ACTIVE credentials whose verifier requires the WS-01 HMAC key."""
