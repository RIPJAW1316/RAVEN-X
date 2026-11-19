"""Enrollment and credential application service.

This service establishes identity proof; it does not authorize commands or
provide a network transport.

Agent credential renewal (WS-01) is agent-prepared: the endpoint generates the
successor credential identifier and secret, stores them durably, and proves
possession of a usable predecessor when proposing them. The server stores only
a verifier, records exactly one successor per predecessor, and fixes the
predecessor's remaining authority when the renewal is first committed.
See docs/architecture/agent-credential-renewal.md.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
import secrets as _secrets
from typing import Any, Mapping, Optional, Tuple

from ...domain.endpoint import Endpoint, EndpointId, EndpointStatus, is_approved_for_agent_trust
from ...domain.organization import OrganizationId, OrganizationStatus
from ...domain.enrollment import (
    CredentialId,
    CredentialKind,
    CredentialRenewal,
    CredentialRevocationKind,
    CredentialStatus,
    EndpointCredential,
    EnrollmentAuthorization,
    EnrollmentId,
    EnrollmentRequest,
    EnrollmentStatus,
)
from ...infrastructure.security import generate_secret, hash_bearer_secret, hash_secret, hash_token, verify_secret
from ...domain.security import (
    AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityAuditEvent,
    SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal, PrincipalType,
)
from ..ports.control_plane_authorization import AuthorizationFailure, AuthorizationService, ConservativeControlPlaneAuthorizer
from ..ports.enrollment_repository import RenewalDecision, RenewalDecisionKind


MAX_CREDENTIAL_TTL = timedelta(days=30)
DEFAULT_RENEWAL_OVERLAP = timedelta(minutes=15)
# A credential may only be renewed during the final part of its life. This
# bounds lineage churn and how quickly any holder can roll a credential forward.
DEFAULT_RENEWAL_WINDOW = timedelta(days=10)
DEFAULT_RENEWAL_OVERLAP_TTL = DEFAULT_RENEWAL_OVERLAP
_SUCCESSOR_SECRET = re.compile(r"[A-Za-z0-9_-]{43,128}")


class EnrollmentError(Exception):
    """Base class for explicit enrollment failures."""


class EnrollmentNotFoundError(EnrollmentError): ...
class EnrollmentExpiredError(EnrollmentError): ...
class EnrollmentRevokedError(EnrollmentError): ...
class EnrollmentAlreadyUsedError(EnrollmentError): ...
class CredentialRejectedError(EnrollmentError): ...
class CredentialExpiredError(CredentialRejectedError): ...


class AgentOrganizationSuspendedError(EnrollmentError):
    """The credential is valid but its organization is suspended; no agent operation is allowed."""


class EndpointNotActiveForRenewalError(EnrollmentError): ...
class CredentialRenewalReplayError(EnrollmentError): ...


class CredentialRenewalConflictError(EnrollmentError):
    """The predecessor has already been renewed to a different successor."""


class CredentialRenewalNotDueError(EnrollmentError):
    """The predecessor is not yet inside the renewal window."""


class CredentialRenewalProposalError(EnrollmentError):
    """The proposed successor identifier or secret is malformed or reuses the predecessor."""


class CredentialLineageRevocationError(EnrollmentError):
    """The named credential does not exist or cannot be lineage-revoked."""


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


@dataclass(frozen=True)
class CredentialRenewalResult:
    """Committed renewal lineage; intentionally carries no secret material."""

    endpoint: Endpoint
    credential: EndpointCredential
    renewal: CredentialRenewal
    created: bool


class EnrollmentService:
    def __init__(self, repository, *, authorization_service=None, audit_sink=None,
                 principal: Optional[SecurityPrincipal] = None, membership_id: Optional[str] = None,
                 organization_repository=None, renewal_overlap: timedelta = DEFAULT_RENEWAL_OVERLAP,
                 renewal_window: timedelta = DEFAULT_RENEWAL_WINDOW,
                 renewed_credential_ttl: timedelta = MAX_CREDENTIAL_TTL,
                 verifier_key: Optional[bytes] = None, defer_verifier_key: bool = False):
        if not timedelta(0) < renewal_overlap <= timedelta(hours=1):
            raise ValueError("renewal_overlap must be between zero and one hour")
        if not timedelta(0) < renewal_window <= timedelta(days=31):
            raise ValueError("renewal_window must be positive and at most 31 days")
        if not timedelta(0) < renewed_credential_ttl <= MAX_CREDENTIAL_TTL:
            raise ValueError("renewed_credential_ttl must be between zero and 30 days")
        self._repository = repository
        self._authorization = authorization_service
        self._audit_sink = audit_sink
        self._principal = principal or SecurityPrincipal.system()
        self._membership_id = membership_id
        self._organization_repository = organization_repository
        self._renewal_overlap = renewal_overlap
        self._renewal_window = renewal_window
        self._renewed_credential_ttl = renewed_credential_ttl
        if defer_verifier_key:
            if verifier_key is not None:
                raise ValueError("deferred verifier key cannot be supplied at construction")
            self._verifier_key = b""
            self._verifier_bound = False
        else:
            self._verifier_key = bytes(verifier_key) if verifier_key is not None else _secrets.token_bytes(32)
            if len(self._verifier_key) < 32:
                raise ValueError("credential verifier key must be at least 32 bytes")
            self._verifier_bound = True
        # Endpoint self-actions always use the conservative, self-scoped policy.
        self._endpoint_authorization = AuthorizationService(ConservativeControlPlaneAuthorizer(), audit_sink)

    def bind_verifier_key(self, key: bytes) -> None:
        """Install the process verifier key after startup custody checks."""
        key = bytes(key)
        if len(key) < 32:
            raise ValueError("credential verifier key must be at least 32 bytes")
        self._verifier_key = key
        self._verifier_bound = True

    def _require_verifier_key(self) -> bytes:
        if not self._verifier_bound:
            raise RuntimeError("credential verifier key is not bound")
        return self._verifier_key

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
        credential_ttl: timedelta = MAX_CREDENTIAL_TTL,
    ) -> Tuple[Endpoint, EndpointCredential, IssuedSecret]:
        now = _utc(now or datetime.now(timezone.utc))
        if credential_ttl is None or not timedelta(0) < credential_ttl <= MAX_CREDENTIAL_TTL:
            raise ValueError("credential_ttl must be between zero and 30 days")
        authorization = self._repository.get_authorization(enrollment_id)
        if authorization is None:
            raise EnrollmentNotFoundError("enrollment authorization not found")
        if authorization.status is EnrollmentStatus.CONSUMED:
            raise EnrollmentAlreadyUsedError("enrollment authorization has already been consumed")
        if authorization.status is EnrollmentStatus.REVOKED:
            raise EnrollmentRevokedError("enrollment authorization has been revoked")
        if authorization.status is EnrollmentStatus.EXPIRED or now >= authorization.expires_at:
            self._repository.expire_authorization(enrollment_id, now)
            raise EnrollmentExpiredError("enrollment authorization has expired")
        if not verify_secret(presented_token, authorization.token_verifier):
            self._audit(SecurityAuditEventType.ENROLLMENT_CONSUMPTION_FAILED, enrollment_id=str(enrollment_id),
                        reason_code="invalid_enrollment_token", organization_id=authorization.organization_id)
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
        return self._authenticate_agent(endpoint_id, presented_secret, now)[1]

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
        return self._authenticate_agent(endpoint_id, presented_secret, now, credential_id=credential_id)[1]

    def rotate_credential(
        self,
        credential_id: CredentialId,
        *,
        now: Optional[datetime] = None,
        ttl: timedelta = MAX_CREDENTIAL_TTL,
    ) -> Tuple[EndpointCredential, IssuedSecret]:
        """Administrative rotation (system/internal principals only); no overlap is granted."""
        now = _utc(now or datetime.now(timezone.utc))
        if ttl is None or not timedelta(0) < ttl <= MAX_CREDENTIAL_TTL:
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
        self._audit(
            SecurityAuditEventType.CREDENTIAL_ROTATED,
            endpoint_id=str(old.endpoint_id),
            metadata={"credential_id": str(credential_id), "replacement_credential_id": str(replacement.credential_id)},
            organization_id=endpoint.organization_id,
        )
        return replacement, IssuedSecret(raw)

    def renew_credential(
        self,
        endpoint_id: EndpointId,
        presented_secret: str,
        *,
        claimed_credential_id: Any,
        successor_credential_id: Any,
        successor_secret: str,
        now: Optional[datetime] = None,
        claimed_endpoint_id: Optional[Any] = None,
        claimed_organization_id: Optional[Any] = None,
        message_id: Optional[Any] = None,
        replay_guard: Optional[Any] = None,
        replay_ttl: timedelta = timedelta(minutes=11),
    ) -> CredentialRenewalResult:
        """Activate an agent-prepared successor for the authenticated predecessor.

        Identical retries (same successor identifier and secret) return the
        committed lineage without mutating it. A different successor for an
        already-renewed predecessor is a conflict; it never revokes the first.
        """
        now = _utc(now or datetime.now(timezone.utc))
        claimed = self._parse_claimed_credential(endpoint_id, claimed_credential_id, message_id)
        endpoint, predecessor = self._authenticate_agent(endpoint_id, presented_secret, now,
                                                         credential_id=claimed, message_id=message_id)
        principal = SecurityPrincipal.endpoint(endpoint.endpoint_id)
        self._require_claims(endpoint, principal, message_id, claimed_endpoint_id=claimed_endpoint_id,
                             claimed_organization_id=claimed_organization_id)
        if endpoint.organization_id is None:
            self._deny(principal, endpoint, "organization_required", message_id)
            raise EndpointNotActiveForRenewalError("credential renewal requires an organization-owned endpoint")
        if endpoint.status is not EndpointStatus.ACTIVE:
            self._deny(principal, endpoint, "endpoint_not_active", message_id,
                       metadata={"endpoint_status": endpoint.status.value})
            raise EndpointNotActiveForRenewalError("endpoint is not active for credential renewal")
        try:
            self._endpoint_authorization.require(AuthorizationRequest(
                principal, AuthorizationAction.CREDENTIAL_RENEW,
                AuthorizationResource("credential", str(predecessor.credential_id),
                                      {"endpoint_id": str(endpoint.endpoint_id),
                                       "organization_id": str(endpoint.organization_id)}),
            ))
        except AuthorizationFailure as error:
            raise EndpointNotActiveForRenewalError("endpoint is not authorized to renew this credential") from error
        successor_id = self._validate_successor(successor_credential_id, successor_secret, predecessor,
                                                principal, endpoint, message_id)
        self._claim_message(replay_guard, message_id, endpoint, principal, now, replay_ttl)
        successor = EndpointCredential(
            credential_id=successor_id, endpoint_id=endpoint.endpoint_id, kind=predecessor.kind,
            verifier=hash_bearer_secret(successor_secret, key=self._require_verifier_key(), binding=str(successor_id)),
            status=CredentialStatus.ACTIVE, issued_at=now,
            expires_at=now + self._renewed_credential_ttl,
        )
        decision = self._repository.renew_credential(
            endpoint_id=endpoint.endpoint_id, predecessor_credential_id=predecessor.credential_id,
            successor=successor, now=now, overlap=self._renewal_overlap, renewal_window=self._renewal_window,
        )
        return self._apply_renewal_decision(decision, endpoint, principal, predecessor, successor_secret, now,
                                            message_id)

    def confirm_credential_renewal(
        self,
        endpoint_id: EndpointId,
        presented_secret: str,
        *,
        claimed_credential_id: Any,
        now: Optional[datetime] = None,
        replaces_credential_id: Optional[Any] = None,
        claimed_endpoint_id: Optional[Any] = None,
        message_id: Optional[Any] = None,
        replay_guard: Optional[Any] = None,
        replay_ttl: timedelta = timedelta(minutes=11),
    ) -> EndpointCredential:
        """Prove possession of a renewed credential; closes the predecessor's window permanently.

        Also serves as the recovery probe: an agent whose renewal response was
        lost authenticates with its locally prepared successor here.
        """
        now = _utc(now or datetime.now(timezone.utc))
        claimed = self._parse_claimed_credential(endpoint_id, claimed_credential_id, message_id)
        endpoint, credential = self._authenticate_agent(endpoint_id, presented_secret, now,
                                                        credential_id=claimed, message_id=message_id)
        principal = SecurityPrincipal.endpoint(endpoint.endpoint_id)
        self._require_claims(endpoint, principal, message_id, claimed_endpoint_id=claimed_endpoint_id)
        if replaces_credential_id is not None:
            try:
                expected = _credential_id(replaces_credential_id)
            except ValueError:
                expected = None
            if expected is None or credential.replaces_credential_id != expected:
                self._reject(principal, endpoint, "renewal_lineage_mismatch", message_id)
        if not is_approved_for_agent_trust(endpoint.status):
            self._deny(principal, endpoint, "endpoint_not_approved", message_id,
                       metadata={"endpoint_status": endpoint.status.value})
            raise EndpointNotActiveForRenewalError("endpoint is not approved for renewal confirmation")
        self._claim_message(replay_guard, message_id, endpoint, principal, now, replay_ttl)
        return credential

    def revoke_compromised_credential(
        self,
        credential_id: CredentialId,
        *,
        now: Optional[datetime] = None,
        reason: str,
    ) -> Tuple[CredentialId, ...]:
        """Contain a suspected leak: revoke this credential and every descendant.

        This is not ``rotate_credential``. Rotation issues a replacement for one
        ACTIVE credential and does not walk historical renewal descendants.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("compromise revocation requires an operator reason")
        return self.revoke_credential(
            credential_id, now=now, reason=reason.strip(), kind=CredentialRevocationKind.COMPROMISE,
        )

    def revoke_credential(
        self,
        credential_id: CredentialId,
        *,
        now: Optional[datetime] = None,
        reason: Optional[str] = None,
        kind: CredentialRevocationKind = CredentialRevocationKind.ADMINISTRATIVE,
    ) -> Tuple[CredentialId, ...]:
        """Revoke a credential and every renewal descendant on the same endpoint.

        Historical rows remain. Secrets are never written to audit metadata.
        """
        kind = CredentialRevocationKind(kind)
        credential = self._repository.get_credential(credential_id)
        if credential is None:
            raise CredentialRejectedError("credential not found")
        endpoint = self._repository.get_endpoint(credential.endpoint_id)
        self._authorize(AuthorizationAction.CREDENTIAL_REVOKE, "credential", str(credential_id), endpoint_id=credential.endpoint_id)
        revoked = self._repository.revoke_credential(
            credential_id, _utc(now or datetime.now(timezone.utc)),
            reason or kind.value, cascade_descendants=True,
        )
        organization_id = endpoint.organization_id if endpoint is not None else None
        descendant_ids = [str(item) for item in revoked[1:]]
        self._audit(
            SecurityAuditEventType.CREDENTIAL_REVOKED,
            endpoint_id=str(credential.endpoint_id),
            metadata={"credential_id": str(credential_id), "reason": reason or kind.value,
                      "revocation_kind": kind.value, "descendant_count": len(descendant_ids)},
            organization_id=organization_id,
        )
        if descendant_ids:
            self._audit(
                SecurityAuditEventType.CREDENTIAL_LINEAGE_REVOKED,
                endpoint_id=str(credential.endpoint_id),
                metadata={"credential_id": str(credential_id), "revocation_kind": kind.value,
                          "descendant_credential_ids": descendant_ids, "reason": reason or kind.value},
                organization_id=organization_id,
            )
        return revoked

    def _authenticate_agent(self, endpoint_id, presented_secret, now, *, credential_id=None, message_id=None):
        """Single authentication path for every agent operation.

        Order matters: endpoint and organization revocation are rejected before
        any secret comparison, so a revoked tenant cannot use any credential;
        suspension is reported (403) only after the secret proves possession,
        so it is not an oracle for unauthenticated callers.
        """
        endpoint_id = endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(str(endpoint_id))
        principal = SecurityPrincipal.endpoint(endpoint_id)
        endpoint = self._repository.get_endpoint(endpoint_id)
        organization_id = endpoint.organization_id if endpoint is not None else None

        def reject(reason, error=CredentialRejectedError):
            self._audit_endpoint(SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_FAILED, principal,
                                 endpoint_id=endpoint_id, organization_id=organization_id,
                                 reason_code=reason, message_id=message_id)
            raise error("credential rejected")

        if (not isinstance(presented_secret, str) or not presented_secret or len(presented_secret) > 128
                or not presented_secret.isascii() or any(ch.isspace() for ch in presented_secret)):
            reject("credential_rejected")
        if endpoint is None or endpoint.status is EndpointStatus.REVOKED:
            reject("endpoint_rejected")
        organization_status = None
        if organization_id is not None:
            organization_status = self._organization_status(organization_id)
            if organization_status == OrganizationStatus.REVOKED.value:
                reject("organization_revoked")
            if organization_status not in (OrganizationStatus.ACTIVE.value, OrganizationStatus.SUSPENDED.value):
                reject("organization_missing")
        if credential_id is not None:
            candidate = self._repository.get_credential(credential_id)
            candidates = (candidate,) if candidate is not None and candidate.endpoint_id == endpoint_id else ()
        else:
            candidates = self._repository.list_credentials(endpoint_id)
        matched, expired_match = None, False
        for candidate in candidates:
            if not self._verify_presented(presented_secret, candidate):
                continue
            if candidate.is_usable(now):
                matched = candidate
                break
            expired_match = expired_match or (candidate.expires_at is not None and now >= candidate.expires_at)
        if matched is None:
            if expired_match:
                reject("credential_expired", CredentialExpiredError)
            reject("credential_rejected")
        if organization_status == OrganizationStatus.SUSPENDED.value:
            self._audit_endpoint(SecurityAuditEventType.AUTHORIZATION_DENIED, principal, endpoint_id=endpoint_id,
                                 organization_id=organization_id, reason_code="organization_suspended",
                                 message_id=message_id)
            raise AgentOrganizationSuspendedError("endpoint organization is suspended")
        if matched.awaiting_renewal_confirmation:
            matched = self._confirm_on_use(matched, principal, endpoint, now, message_id)
        self._audit_endpoint(SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_SUCCEEDED, principal,
                             endpoint_id=endpoint_id, organization_id=organization_id, message_id=message_id,
                             metadata={"credential_id": str(matched.credential_id)})
        return endpoint, matched

    def _confirm_on_use(self, credential, principal, endpoint, now, message_id):
        """First proof of successor possession confirms the renewal and closes the predecessor."""
        confirm = getattr(self._repository, "confirm_credential_renewal", None)
        if confirm is None:
            return credential
        renewal = confirm(credential.credential_id, now)
        if renewal is None:
            return credential
        if renewal.confirmed_at == now:
            self._audit_endpoint(SecurityAuditEventType.CREDENTIAL_RENEWAL_CONFIRMED, principal,
                                 endpoint_id=endpoint.endpoint_id, organization_id=endpoint.organization_id,
                                 message_id=message_id,
                                 metadata={"credential_id": str(renewal.predecessor_credential_id),
                                           "replacement_credential_id": str(renewal.successor_credential_id)})
        refreshed = self._repository.get_credential(credential.credential_id)
        return refreshed if refreshed is not None else credential

    def _apply_renewal_decision(self, decision: RenewalDecision, endpoint, principal, predecessor,
                                successor_secret, now, message_id) -> CredentialRenewalResult:
        kind = decision.kind
        if kind in (RenewalDecisionKind.CREATED, RenewalDecisionKind.EXISTING):
            successor = decision.successor
            if kind is RenewalDecisionKind.EXISTING and (
                    successor is None or not self._verify_presented(successor_secret, successor)):
                kind = RenewalDecisionKind.CONFLICT
            elif not successor.is_usable(now):
                self._reject(principal, endpoint, "successor_rejected", message_id)
            else:
                renewal = decision.renewal
                self._audit_endpoint(
                    SecurityAuditEventType.CREDENTIAL_RENEWED, principal,
                    action=AuthorizationAction.CREDENTIAL_RENEW,
                    resource=AuthorizationResource("credential", str(successor.credential_id),
                                                   {"endpoint_id": str(endpoint.endpoint_id)}),
                    endpoint_id=endpoint.endpoint_id, organization_id=endpoint.organization_id,
                    message_id=message_id,
                    metadata={"credential_id": str(renewal.predecessor_credential_id),
                              "replacement_credential_id": str(renewal.successor_credential_id),
                              "predecessor_valid_until": renewal.predecessor_valid_until.isoformat(),
                              "reason": "agent_renewal" if kind is RenewalDecisionKind.CREATED else "idempotent_retry"},
                )
                return CredentialRenewalResult(endpoint, successor, renewal, kind is RenewalDecisionKind.CREATED)
        if kind is RenewalDecisionKind.CONFLICT:
            self._audit_endpoint(SecurityAuditEventType.CREDENTIAL_RENEWAL_CONFLICT, principal,
                                 action=AuthorizationAction.CREDENTIAL_RENEW, endpoint_id=endpoint.endpoint_id,
                                 organization_id=endpoint.organization_id, reason_code="predecessor_already_renewed",
                                 message_id=message_id, metadata={"credential_id": str(predecessor.credential_id)})
            raise CredentialRenewalConflictError("credential has already been renewed to a different successor")
        if kind is RenewalDecisionKind.NOT_DUE:
            self._deny(principal, endpoint, "renewal_not_due", message_id)
            raise CredentialRenewalNotDueError("credential is not yet inside the renewal window")
        if kind is RenewalDecisionKind.ENDPOINT_NOT_ACTIVE:
            self._deny(principal, endpoint, "endpoint_not_active", message_id)
            raise EndpointNotActiveForRenewalError("endpoint is not active for credential renewal")
        self._reject(principal, endpoint, kind.value, message_id)

    def _parse_claimed_credential(self, endpoint_id, claimed_credential_id, message_id):
        try:
            return _credential_id(claimed_credential_id)
        except ValueError:
            endpoint_id = endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(str(endpoint_id))
            endpoint = self._repository.get_endpoint(endpoint_id)
            self._audit_endpoint(SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_FAILED,
                                 SecurityPrincipal.endpoint(endpoint_id), endpoint_id=endpoint_id,
                                 organization_id=endpoint.organization_id if endpoint is not None else None,
                                 reason_code="credential_mismatch", message_id=message_id)
            raise CredentialRejectedError("credential rejected")

    def _require_claims(self, endpoint, principal, message_id, *, claimed_endpoint_id=None,
                        claimed_organization_id=None):
        """Client-supplied identity is only ever compared with authenticated server records."""
        if claimed_endpoint_id is not None:
            try:
                claimed = (claimed_endpoint_id if isinstance(claimed_endpoint_id, EndpointId)
                           else EndpointId(str(claimed_endpoint_id)))
            except ValueError:
                claimed = None
            if claimed != endpoint.endpoint_id:
                self._reject(principal, endpoint, "endpoint_mismatch", message_id)
        if claimed_organization_id is not None:
            try:
                claimed_org = OrganizationId.parse(claimed_organization_id)
            except ValueError:
                claimed_org = None
            if endpoint.organization_id is None or claimed_org != endpoint.organization_id:
                self._reject(principal, endpoint, "organization_mismatch", message_id)

    def _verify_presented(self, secret, credential) -> bool:
        return verify_secret(secret, credential.verifier, key=self._require_verifier_key(),
                             binding=str(credential.credential_id))

    def _validate_successor(self, successor_credential_id, successor_secret, predecessor, principal, endpoint,
                            message_id) -> CredentialId:
        try:
            successor_id = _credential_id(successor_credential_id)
        except ValueError:
            successor_id = None
        valid = (
            successor_id is not None
            and successor_id != predecessor.credential_id
            and isinstance(successor_secret, str)
            and _SUCCESSOR_SECRET.fullmatch(successor_secret) is not None
            and not self._verify_presented(successor_secret, predecessor)
        )
        if not valid:
            self._deny(principal, endpoint, "invalid_renewal_proposal", message_id)
            raise CredentialRenewalProposalError("successor credential proposal is invalid")
        return successor_id

    def _claim_message(self, replay_guard, message_id, endpoint, principal, now, replay_ttl):
        if replay_guard is None or message_id is None:
            return
        if not _claim_replay(replay_guard, message_id, endpoint.endpoint_id, now, now + replay_ttl):
            self._audit_endpoint(SecurityAuditEventType.AGENT_MESSAGE_REPLAY_REJECTED, principal,
                                 action=AuthorizationAction.CREDENTIAL_RENEW, endpoint_id=endpoint.endpoint_id,
                                 organization_id=endpoint.organization_id, reason_code="replayed_message",
                                 message_id=message_id)
            raise CredentialRenewalReplayError("message_id has already been accepted")

    def _organization_status(self, organization_id) -> str:
        """Lifecycle of the endpoint's tenant; a missing record fails closed."""
        if self._organization_repository is not None:
            organization = self._organization_repository.get(organization_id)
            return organization.status.value if organization is not None else "missing"
        lookup = getattr(self._repository, "get_organization_status", None)
        status = lookup(organization_id) if lookup is not None else None
        return status if status in {item.value for item in OrganizationStatus} else "missing"

    def _reject(self, principal, endpoint, reason, message_id):
        self._audit_endpoint(SecurityAuditEventType.CREDENTIAL_AUTHENTICATION_FAILED, principal,
                             endpoint_id=endpoint.endpoint_id, organization_id=endpoint.organization_id,
                             reason_code=reason, message_id=message_id)
        raise CredentialRejectedError("credential rejected")

    def _deny(self, principal, endpoint, reason, message_id, *, metadata=None):
        self._audit_endpoint(SecurityAuditEventType.AUTHORIZATION_DENIED, principal,
                             action=AuthorizationAction.CREDENTIAL_RENEW, endpoint_id=endpoint.endpoint_id,
                             organization_id=endpoint.organization_id, reason_code=reason, message_id=message_id,
                             metadata=metadata)

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

    def _audit_endpoint(self, event_type, principal, *, action=None, resource=None, endpoint_id=None,
                        organization_id=None, reason_code=None, message_id=None, metadata=None):
        if self._audit_sink is not None:
            self._audit_sink.append(SecurityAuditEvent(
                event_type=event_type.value,
                principal=principal,
                action=action,
                resource=resource,
                outcome=SecurityAuditOutcome.DENIED if reason_code else SecurityAuditOutcome.SUCCESS,
                reason_code=reason_code,
                endpoint_id=str(endpoint_id) if endpoint_id is not None else None,
                organization_id=str(organization_id) if organization_id is not None else None,
                message_id=str(message_id) if message_id is not None else None,
                metadata=dict(metadata or {}),
            ))


def _credential_id(value) -> CredentialId:
    if isinstance(value, CredentialId):
        return value
    try:
        return CredentialId(str(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("invalid credential id") from error


def _claim_replay(guard, message_id, endpoint_id, now: datetime, expires_at: datetime) -> bool:
    from ...protocol.agent import MessageId
    parsed_id = message_id if isinstance(message_id, MessageId) else MessageId(str(message_id))
    if hasattr(guard, "claim"):
        return bool(guard.claim(parsed_id, endpoint_id, now, expires_at))
    if guard.seen(parsed_id):
        return False
    guard.record(parsed_id)
    return True


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)
