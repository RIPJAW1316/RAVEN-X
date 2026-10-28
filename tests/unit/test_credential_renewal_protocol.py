"""WS-01 renewal protocol properties at the service boundary, on a fixed clock.

Every timestamp here is explicit, so the predecessor deadline, the renewal
window and organization lifecycle transitions are deterministic.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import secrets
from threading import Barrier
from types import SimpleNamespace

import pytest

from backend.application.enrollment import (
    AgentOrganizationSuspendedError,
    CredentialExpiredError,
    CredentialRejectedError,
    CredentialRenewalConflictError,
    CredentialRenewalNotDueError,
    CredentialRenewalProposalError,
    CredentialRenewalReplayError,
    EndpointNotActiveForRenewalError,
    EnrollmentService,
)
from backend.domain.audit import derive_severity
from backend.domain.endpoint import EndpointStatus, PlatformInfo
from backend.domain.enrollment import CredentialId, CredentialStatus, EnrollmentRequest
from backend.domain.organization import Organization, OrganizationId, OrganizationStatus
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.security import hash_bearer_secret, hash_token, verify_secret
from backend.protocol.agent import InMemoryReplayGuard, MessageId, ProtocolValidationPolicy


T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
RENEW_AT = T0 + timedelta(days=1)
MINUTE = timedelta(minutes=1)


def _enroll(service, repository, organization_id, *, ttl, approve=True, hostname="win-01"):
    authorization, token = service.create_enrollment_authorization(now=T0, organization_id=organization_id)
    endpoint, credential, secret = service.accept_enrollment(
        authorization.enrollment_id, token.value, EnrollmentRequest(hostname, PlatformInfo("Windows")),
        now=T0, credential_ttl=ttl)
    if approve:
        endpoint = endpoint.transition_to(EndpointStatus.ACTIVE, T0 + timedelta(seconds=1))
        repository.endpoints[str(endpoint.endpoint_id)] = endpoint
    return endpoint, credential, secret.value


def _stack(*, ttl=timedelta(days=5), approve=True):
    repository = InMemoryEnrollmentRepository()
    organizations = InMemoryOrganizationRepository()
    audit = InMemorySecurityAuditRepository()
    organization = Organization(OrganizationId.new(), "Tenant A", created_at=T0 - timedelta(days=1),
                                updated_at=T0 - timedelta(days=1))
    organizations.add(organization)
    verifier_key = secrets.token_bytes(32)
    service = EnrollmentService(repository, audit_sink=audit, organization_repository=organizations,
                                verifier_key=verifier_key)
    endpoint, credential, secret = _enroll(service, repository, organization.organization_id, ttl=ttl, approve=approve)
    return SimpleNamespace(repository=repository, organizations=organizations, audit=audit, service=service,
                           organization=organization, endpoint=endpoint, credential=credential, secret=secret,
                           verifier_key=verifier_key)


def _successor():
    return CredentialId.new(), secrets.token_urlsafe(32)


def _renew(stack, successor, now, *, secret=None, claimed=None, endpoint_id=None, **kwargs):
    successor_id, successor_secret = successor
    return stack.service.renew_credential(
        endpoint_id or stack.endpoint.endpoint_id, secret or stack.secret,
        claimed_credential_id=claimed or stack.credential.credential_id,
        successor_credential_id=successor_id, successor_secret=successor_secret, now=now, **kwargs)


def _verify(stack, secret, now):
    return stack.service.verify_credential(stack.endpoint.endpoint_id, secret, now=now)


def _confirm(stack, successor, now, **kwargs):
    return stack.service.confirm_credential_renewal(
        stack.endpoint.endpoint_id, successor[1], claimed_credential_id=successor[0], now=now, **kwargs)


def _set_organization(stack, status, at):
    current = stack.organizations.get(stack.organization.organization_id)
    stack.organizations.update(current.transition_to(status, at))


def _active_credentials(stack):
    return {str(item.credential_id) for item in stack.repository.credentials.values()
            if item.status is CredentialStatus.ACTIVE}


def test_agent_prepared_successor_is_committed_and_no_secret_is_returned():
    stack = _stack()
    successor = _successor()
    result = _renew(stack, successor, RENEW_AT)

    assert result.created
    assert result.credential.credential_id == successor[0]
    assert result.credential.verifier.startswith("token-hmac-v2$")
    assert verify_secret(successor[1], result.credential.verifier, key=stack.verifier_key,
                         binding=str(successor[0]))
    assert result.renewal.predecessor_credential_id == stack.credential.credential_id
    assert result.renewal.predecessor_valid_until == RENEW_AT + 15 * MINUTE
    assert successor[1] not in repr(result) and successor[1] not in str(asdict(result))
    predecessor = stack.repository.get_credential(stack.credential.credential_id)
    assert predecessor.status is CredentialStatus.ROTATED
    assert predecessor.successor_credential_id == successor[0]
    # The predecessor may still authenticate during the overlap, without confirming anything.
    assert _verify(stack, stack.secret, RENEW_AT + MINUTE).credential_id == stack.credential.credential_id
    assert stack.repository.get_renewal_for_successor(successor[0]).confirmed_at is None


def test_retries_at_minutes_0_1_and_14_never_move_the_fixed_predecessor_deadline():
    stack = _stack()
    successor = _successor()
    deadline = RENEW_AT + 15 * MINUTE
    results = [_renew(stack, successor, RENEW_AT + offset * MINUTE) for offset in (0, 0, 1, 14)]

    assert [item.created for item in results] == [True, False, False, False]
    assert {item.renewal.predecessor_valid_until for item in results} == {deadline}
    assert {item.credential.credential_id for item in results} == {successor[0]}
    assert stack.repository.get_renewal_for_predecessor(stack.credential.credential_id).predecessor_valid_until == deadline
    assert _verify(stack, stack.secret, deadline - timedelta(seconds=1)).credential_id == stack.credential.credential_id
    with pytest.raises(CredentialRejectedError):
        _verify(stack, stack.secret, deadline)
    for late in (deadline, deadline + MINUTE):
        with pytest.raises(CredentialRejectedError):
            _renew(stack, successor, late)
    assert stack.repository.get_renewal_for_predecessor(stack.credential.credential_id).predecessor_valid_until == deadline
    assert _verify(stack, successor[1], deadline + 5 * MINUTE).credential_id == successor[0]


def test_predecessor_window_never_outlives_the_predecessor_itself():
    stack = _stack(ttl=timedelta(minutes=10))
    successor = _successor()
    result = _renew(stack, successor, T0 + 5 * MINUTE)

    assert result.renewal.predecessor_valid_until == T0 + 10 * MINUTE
    with pytest.raises(CredentialExpiredError):
        _verify(stack, stack.secret, T0 + 10 * MINUTE)


def test_confirmation_closes_the_predecessor_permanently_and_retries_cannot_reopen_it():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    confirmed = _confirm(stack, successor, RENEW_AT + 2 * MINUTE, replaces_credential_id=stack.credential.credential_id)

    assert confirmed.renewal_confirmed_at == RENEW_AT + 2 * MINUTE
    for at in (RENEW_AT + 3 * MINUTE, RENEW_AT + 14 * MINUTE):
        with pytest.raises(CredentialRejectedError):
            _verify(stack, stack.secret, at)
        with pytest.raises(CredentialRejectedError):
            _renew(stack, successor, at)
    renewal = stack.repository.get_renewal_for_predecessor(stack.credential.credential_id)
    assert renewal.predecessor_closed_at == RENEW_AT + 2 * MINUTE
    assert renewal.closed_reason == "confirmed"
    assert renewal.predecessor_valid_until == RENEW_AT + 15 * MINUTE
    # Confirmation is idempotent and does not touch the closed window again.
    _confirm(stack, successor, RENEW_AT + 4 * MINUTE)
    assert stack.repository.get_renewal_for_predecessor(stack.credential.credential_id).predecessor_closed_at == RENEW_AT + 2 * MINUTE


def test_first_use_of_the_successor_confirms_it_and_closes_the_predecessor():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)

    assert _verify(stack, successor[1], RENEW_AT + MINUTE).renewal_confirmed_at == RENEW_AT + MINUTE
    with pytest.raises(CredentialRejectedError):
        _verify(stack, stack.secret, RENEW_AT + 2 * MINUTE)
    confirmations = stack.audit.list(event_type="credential.renewal_confirmed")
    assert len(confirmations) == 1
    assert confirmations[0].organization_id == str(stack.organization.organization_id)


def test_a_different_successor_for_a_renewed_predecessor_is_a_conflict_and_never_revokes_the_first():
    stack = _stack()
    first, second = _successor(), _successor()
    _renew(stack, first, RENEW_AT)

    with pytest.raises(CredentialRenewalConflictError):
        _renew(stack, second, RENEW_AT + MINUTE)
    assert stack.repository.credentials[str(first[0])].status is CredentialStatus.ACTIVE
    assert str(second[0]) not in stack.repository.credentials
    assert _active_credentials(stack) == {str(first[0])}
    assert stack.repository.get_renewal_for_predecessor(stack.credential.credential_id).predecessor_valid_until == RENEW_AT + 15 * MINUTE
    assert _verify(stack, first[1], RENEW_AT + 2 * MINUTE).credential_id == first[0]
    conflicts = stack.audit.list(event_type="credential.renewal_conflict")
    assert len(conflicts) == 1
    assert conflicts[0].organization_id == str(stack.organization.organization_id)
    assert derive_severity(conflicts[0].event_type, conflicts[0].outcome.value).value == "critical"


def test_a_retry_naming_the_same_successor_with_another_secret_is_a_conflict():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)

    with pytest.raises(CredentialRenewalConflictError):
        _renew(stack, (successor[0], secrets.token_urlsafe(32)), RENEW_AT + MINUTE)
    assert stack.repository.credentials[str(successor[0])].verifier.startswith("token-hmac-v2$")


def test_renewal_outside_the_renewal_window_is_refused_without_side_effects():
    stack = _stack(ttl=timedelta(days=30))
    successor = _successor()

    with pytest.raises(CredentialRenewalNotDueError):
        _renew(stack, successor, T0 + timedelta(days=19, hours=23))
    assert str(successor[0]) not in stack.repository.credentials
    assert stack.repository.credentials[str(stack.credential.credential_id)].status is CredentialStatus.ACTIVE
    assert _renew(stack, successor, T0 + timedelta(days=20)).created


def test_identity_claims_are_only_compared_with_authenticated_records():
    stack = _stack()
    organization_b = Organization(OrganizationId.new(), "Tenant B", created_at=T0 - timedelta(days=1),
                                  updated_at=T0 - timedelta(days=1))
    stack.organizations.add(organization_b)
    endpoint_b, credential_b, secret_b = _enroll(stack.service, stack.repository, organization_b.organization_id,
                                                 ttl=timedelta(days=5), hostname="win-b")
    successor = _successor()

    attempts = (
        dict(endpoint_id=endpoint_b.endpoint_id),                         # A's secret presented for B
        dict(claimed=credential_b.credential_id),                         # credential substitution
        dict(claimed_endpoint_id=endpoint_b.endpoint_id),                 # endpoint claim substitution
        dict(claimed_organization_id=organization_b.organization_id),    # tenant substitution
        dict(claimed_organization_id="not-a-uuid"),
        dict(claimed="not-a-uuid"),
    )
    for attempt in attempts:
        with pytest.raises(CredentialRejectedError):
            _renew(stack, successor, RENEW_AT, **attempt)
    assert str(successor[0]) not in stack.repository.credentials
    assert stack.repository.get_renewal_for_predecessor(stack.credential.credential_id) is None
    assert stack.repository.get_renewal_for_predecessor(credential_b.credential_id) is None
    # B's own credential renews only B, attributed to B's tenant.
    result = stack.service.renew_credential(endpoint_b.endpoint_id, secret_b,
                                            claimed_credential_id=credential_b.credential_id,
                                            successor_credential_id=successor[0], successor_secret=successor[1],
                                            claimed_organization_id=organization_b.organization_id, now=RENEW_AT)
    assert result.endpoint.endpoint_id == endpoint_b.endpoint_id
    assert result.renewal.organization_id == organization_b.organization_id


@pytest.mark.parametrize("status", [EndpointStatus.NEW, EndpointStatus.DEGRADED, EndpointStatus.OFFLINE])
def test_only_approved_active_endpoints_can_renew(status):
    stack = _stack(approve=False)
    if status is not EndpointStatus.NEW:
        active = stack.endpoint.transition_to(EndpointStatus.ACTIVE, T0 + timedelta(seconds=1))
        stack.repository.endpoints[str(stack.endpoint.endpoint_id)] = active.transition_to(status, T0 + timedelta(seconds=2))
    successor = _successor()

    with pytest.raises(EndpointNotActiveForRenewalError):
        _renew(stack, successor, RENEW_AT)
    assert str(successor[0]) not in stack.repository.credentials
    denials = stack.audit.list(event_type="authorization.denied")
    assert denials and denials[-1].reason_code == "endpoint_not_active"


@pytest.mark.parametrize("successor_id,successor_secret", [
    ("not-a-uuid", "A" * 43),
    (None, "A" * 43),
    ("SAME_AS_PREDECESSOR", "A" * 43),
    ("NEW", "short-secret"),
    ("NEW", "A" * 42 + " "),
    ("NEW", "A" * 129),
    ("NEW", "SAME_AS_PREDECESSOR"),
])
def test_malformed_or_reused_successor_proposals_are_rejected(successor_id, successor_secret):
    stack = _stack()
    if successor_id == "SAME_AS_PREDECESSOR":
        successor_id = stack.credential.credential_id
    elif successor_id == "NEW":
        successor_id = CredentialId.new()
    if successor_secret == "SAME_AS_PREDECESSOR":
        successor_secret = stack.secret

    with pytest.raises(CredentialRenewalProposalError):
        _renew(stack, (successor_id, successor_secret), RENEW_AT)
    assert stack.repository.get_renewal_for_predecessor(stack.credential.credential_id) is None
    assert stack.repository.credentials[str(stack.credential.credential_id)].status is CredentialStatus.ACTIVE


def test_renewal_message_ids_are_single_use_but_the_logical_renewal_stays_idempotent():
    stack = _stack()
    successor = _successor()
    guard = InMemoryReplayGuard()
    message_id = MessageId()
    _renew(stack, successor, RENEW_AT, message_id=message_id, replay_guard=guard)

    with pytest.raises(CredentialRenewalReplayError):
        _renew(stack, successor, RENEW_AT, message_id=message_id, replay_guard=guard)
    retry = _renew(stack, successor, RENEW_AT + MINUTE, message_id=MessageId(), replay_guard=guard)
    assert not retry.created and retry.credential.credential_id == successor[0]
    assert stack.audit.list(event_type="agent.message_replay_rejected")


def test_concurrent_renewals_with_distinct_message_ids_converge_on_one_successor():
    stack = _stack()
    successor = _successor()
    guard = InMemoryReplayGuard()
    barrier = Barrier(6)

    def attempt(_):
        barrier.wait(timeout=10)
        return _renew(stack, successor, RENEW_AT, message_id=MessageId(), replay_guard=guard)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, range(6)))
    assert sum(item.created for item in results) == 1
    assert {item.credential.credential_id for item in results} == {successor[0]}
    assert {item.renewal.predecessor_valid_until for item in results} == {RENEW_AT + 15 * MINUTE}
    assert _active_credentials(stack) == {str(successor[0])}


def test_endpoint_revocation_after_commit_rejects_both_credentials_and_every_renewal_path():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    endpoint = stack.repository.endpoints[str(stack.endpoint.endpoint_id)]
    stack.repository.endpoints[str(stack.endpoint.endpoint_id)] = endpoint.transition_to(
        EndpointStatus.REVOKED, RENEW_AT + MINUTE)

    at = RENEW_AT + 2 * MINUTE
    for secret in (stack.secret, successor[1]):
        with pytest.raises(CredentialRejectedError):
            _verify(stack, secret, at)
    with pytest.raises(CredentialRejectedError):
        _renew(stack, successor, at)
    with pytest.raises(CredentialRejectedError):
        _confirm(stack, successor, at)


def test_revoking_the_predecessor_closes_its_window_and_revokes_an_unconfirmed_successor():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    stack.service.revoke_credential(stack.credential.credential_id, now=RENEW_AT + MINUTE, reason="suspected_theft")

    renewal = stack.repository.get_renewal_for_predecessor(stack.credential.credential_id)
    assert renewal.predecessor_closed_at == RENEW_AT + MINUTE and renewal.closed_reason == "predecessor_revoked"
    assert stack.repository.credentials[str(successor[0])].status is CredentialStatus.REVOKED
    for secret in (stack.secret, successor[1]):
        with pytest.raises(CredentialRejectedError):
            _verify(stack, secret, RENEW_AT + 2 * MINUTE)


def test_revoking_a_successor_closes_the_predecessor_window_immediately():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    stack.service.revoke_credential(successor[0], now=RENEW_AT + MINUTE, reason="operator")

    with pytest.raises(CredentialRejectedError):
        _verify(stack, stack.secret, RENEW_AT + 2 * MINUTE)
    with pytest.raises(CredentialRejectedError):
        _renew(stack, successor, RENEW_AT + 2 * MINUTE)
    revoked = stack.audit.list(event_type="credential.revoked")
    assert revoked and revoked[-1].organization_id == str(stack.organization.organization_id)


def test_organization_suspension_denies_old_and_new_credentials_without_destroying_them():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    _set_organization(stack, OrganizationStatus.SUSPENDED, RENEW_AT + MINUTE)

    at = RENEW_AT + 2 * MINUTE
    for secret in (stack.secret, successor[1]):
        with pytest.raises(AgentOrganizationSuspendedError):
            _verify(stack, secret, at)
    with pytest.raises(AgentOrganizationSuspendedError):
        _renew(stack, successor, at)
    with pytest.raises(AgentOrganizationSuspendedError):
        _confirm(stack, successor, at)
    with pytest.raises(CredentialRejectedError) as wrong_secret:
        _verify(stack, "wrong-secret-value", at)
    assert not isinstance(wrong_secret.value, AgentOrganizationSuspendedError)
    assert stack.repository.get_renewal_for_successor(successor[0]).confirmed_at is None
    denials = [item for item in stack.audit.list(event_type="authorization.denied")
               if item.reason_code == "organization_suspended"]
    assert denials and all(item.organization_id == str(stack.organization.organization_id) for item in denials)

    _set_organization(stack, OrganizationStatus.ACTIVE, RENEW_AT + 3 * MINUTE)
    assert _verify(stack, successor[1], RENEW_AT + 4 * MINUTE).credential_id == successor[0]


def test_organization_revocation_rejects_every_credential_and_renewal_path():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    _set_organization(stack, OrganizationStatus.REVOKED, RENEW_AT + MINUTE)

    at = RENEW_AT + 2 * MINUTE
    for secret in (stack.secret, successor[1]):
        with pytest.raises(CredentialRejectedError) as rejected:
            _verify(stack, secret, at)
        assert not isinstance(rejected.value, AgentOrganizationSuspendedError)
    with pytest.raises(CredentialRejectedError):
        _renew(stack, successor, at)
    with pytest.raises(CredentialRejectedError):
        _confirm(stack, successor, at)
    failures = [item for item in stack.audit.list(event_type="credential.authentication_failed")
                if item.reason_code == "organization_revoked"]
    assert failures and all(item.organization_id == str(stack.organization.organization_id) for item in failures)


def test_an_endpoint_whose_organization_record_is_missing_fails_closed():
    repository = InMemoryEnrollmentRepository()
    service = EnrollmentService(repository)
    endpoint, credential, secret = _enroll(service, repository, OrganizationId.new(), ttl=timedelta(days=5))

    with pytest.raises(CredentialRejectedError):
        service.verify_credential(endpoint.endpoint_id, secret, now=RENEW_AT)


def test_legacy_unassigned_endpoint_keeps_ordinary_authentication_but_cannot_renew():
    repository = InMemoryEnrollmentRepository()
    service = EnrollmentService(repository)
    endpoint, credential, secret = _enroll(service, repository, None, ttl=timedelta(days=5))
    successor = _successor()

    assert service.verify_credential(endpoint.endpoint_id, secret, now=RENEW_AT).credential_id == credential.credential_id
    with pytest.raises(EndpointNotActiveForRenewalError):
        service.renew_credential(endpoint.endpoint_id, secret, claimed_credential_id=credential.credential_id,
                                 successor_credential_id=successor[0], successor_secret=successor[1], now=RENEW_AT)


def test_a_stolen_predecessor_mints_at_most_one_successor_and_gains_no_lasting_authority():
    stack = _stack()
    thief, legitimate = _successor(), _successor()
    _renew(stack, thief, RENEW_AT)

    with pytest.raises(CredentialRenewalConflictError):
        _renew(stack, legitimate, RENEW_AT + MINUTE)
    with pytest.raises(CredentialRenewalConflictError):
        _renew(stack, _successor(), RENEW_AT + 2 * MINUTE)
    with pytest.raises(CredentialRejectedError):
        _verify(stack, stack.secret, RENEW_AT + 15 * MINUTE)
    # The fresh successor cannot immediately be rolled forward either.
    with pytest.raises(CredentialRenewalNotDueError):
        nxt = _successor()
        stack.service.renew_credential(stack.endpoint.endpoint_id, thief[1], claimed_credential_id=thief[0],
                                       successor_credential_id=nxt[0], successor_secret=nxt[1],
                                       now=RENEW_AT + 16 * MINUTE)
    assert len(stack.audit.list(event_type="credential.renewal_conflict")) == 2
    assert _active_credentials(stack) == {str(thief[0])}


def test_renewal_audit_trail_is_tenant_attributed_and_never_contains_secrets():
    stack = _stack()
    successor, rival = _successor(), _successor()
    _renew(stack, successor, RENEW_AT)
    _renew(stack, successor, RENEW_AT + MINUTE)
    with pytest.raises(CredentialRenewalConflictError):
        _renew(stack, rival, RENEW_AT + 2 * MINUTE)
    with pytest.raises(CredentialRejectedError):
        _verify(stack, "wrong-secret-value", RENEW_AT + 2 * MINUTE)
    _confirm(stack, successor, RENEW_AT + 3 * MINUTE)

    events = [item for item in stack.audit.list() if item.endpoint_id == str(stack.endpoint.endpoint_id)]
    assert {"credential.renewed", "credential.renewal_conflict", "credential.renewal_confirmed",
            "credential.authentication_failed"} <= {item.event_type for item in events}
    assert all(item.organization_id == str(stack.organization.organization_id) for item in events)
    serialized = str([item.to_dict() for item in stack.audit.list()])
    for secret in (stack.secret, successor[1], rival[1]):
        assert secret not in serialized


def test_compromise_revocation_of_a_predecessor_invalidates_its_confirmed_successor():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    _confirm(stack, successor, RENEW_AT + MINUTE)
    assert _verify(stack, successor[1], RENEW_AT + 2 * MINUTE).credential_id == successor[0]

    revoked = stack.service.revoke_compromised_credential(
        stack.credential.credential_id, now=RENEW_AT + 3 * MINUTE, reason="stolen predecessor")
    assert {str(item) for item in revoked} == {str(stack.credential.credential_id), str(successor[0])}
    for secret in (stack.secret, successor[1]):
        with pytest.raises(CredentialRejectedError):
            _verify(stack, secret, RENEW_AT + 4 * MINUTE)
    with pytest.raises(CredentialRejectedError):
        _confirm(stack, successor, RENEW_AT + 4 * MINUTE)
    with pytest.raises(CredentialRejectedError):
        nxt = _successor()
        stack.service.renew_credential(stack.endpoint.endpoint_id, successor[1],
                                       claimed_credential_id=successor[0],
                                       successor_credential_id=nxt[0], successor_secret=nxt[1],
                                       now=RENEW_AT + 4 * MINUTE)
    events = stack.audit.list(event_type="credential.lineage_revoked")
    assert events and events[-1].organization_id == str(stack.organization.organization_id)
    assert events[-1].metadata["revocation_kind"] == "compromise"
    assert events[-1].metadata["descendant_credential_ids"] == "<redacted>"
    assert stack.audit.list(event_type="credential.revoked")[-1].metadata["descendant_count"] == 1
    serialized = str([item.to_dict() for item in stack.audit.list()])
    assert successor[1] not in serialized and stack.secret not in serialized


def test_compromise_revocation_walks_two_confirmed_generations():
    stack = _stack()
    first = _successor()
    _renew(stack, first, RENEW_AT)
    _confirm(stack, first, RENEW_AT + MINUTE)
    second = _successor()
    stack.service.renew_credential(stack.endpoint.endpoint_id, first[1], claimed_credential_id=first[0],
                                   successor_credential_id=second[0], successor_secret=second[1],
                                   now=RENEW_AT + timedelta(days=21))
    _confirm(stack, second, RENEW_AT + timedelta(days=21) + MINUTE)

    revoked = stack.service.revoke_compromised_credential(
        stack.credential.credential_id, now=RENEW_AT + timedelta(days=22), reason="lineage leak")
    assert len(revoked) == 3
    for secret in (stack.secret, first[1], second[1]):
        with pytest.raises(CredentialRejectedError):
            _verify(stack, secret, RENEW_AT + timedelta(days=22) + MINUTE)


def test_administrative_rotation_does_not_contain_a_confirmed_descendant():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    _confirm(stack, successor, RENEW_AT + MINUTE)
    replacement, replacement_secret = stack.service.rotate_credential(successor[0], now=RENEW_AT + 2 * MINUTE)

    assert stack.repository.credentials[str(successor[0])].status is CredentialStatus.ROTATED
    assert stack.repository.credentials[str(stack.credential.credential_id)].status is CredentialStatus.ROTATED
    assert _verify(stack, replacement_secret.value, RENEW_AT + 3 * MINUTE).credential_id == replacement.credential_id
    assert not stack.audit.list(event_type="credential.lineage_revoked")


def test_compromise_revocation_is_isolated_to_the_named_endpoint():
    first, second = _stack(), _stack()
    successor = _successor()
    _renew(first, successor, RENEW_AT)
    _confirm(first, successor, RENEW_AT + MINUTE)
    first.service.revoke_compromised_credential(
        first.credential.credential_id, now=RENEW_AT + 2 * MINUTE, reason="one endpoint")

    assert _verify(second, second.secret, RENEW_AT + 3 * MINUTE).credential_id == second.credential.credential_id
    with pytest.raises(CredentialRejectedError):
        _verify(first, successor[1], RENEW_AT + 3 * MINUTE)


def test_concurrent_renewal_and_compromise_revocation_leave_no_authorized_successor():
    stack = _stack()
    successor = _successor()
    start = Barrier(2)
    outcomes = []

    def renew(_):
        start.wait()
        try:
            outcomes.append(("renew", _renew(stack, successor, RENEW_AT)))
        except Exception as error:
            outcomes.append(("renew", error))

    def revoke(_):
        start.wait()
        try:
            outcomes.append(("revoke", stack.service.revoke_compromised_credential(
                stack.credential.credential_id, now=RENEW_AT, reason="race")))
        except Exception as error:
            outcomes.append(("revoke", error))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda fn: fn(None), (renew, revoke)))
    with pytest.raises(CredentialRejectedError):
        _verify(stack, successor[1], RENEW_AT + MINUTE)
    with pytest.raises(CredentialRejectedError):
        _verify(stack, stack.secret, RENEW_AT + MINUTE)


def test_constant_and_malformed_successor_secrets_cannot_be_verified_from_the_database_alone():
    stack = _stack()
    constant = (CredentialId.new(), "A" * 43)
    result = _renew(stack, constant, RENEW_AT)
    assert result.credential.verifier.startswith("token-hmac-v2$")
    assert verify_secret(constant[1], result.credential.verifier, key=stack.verifier_key, binding=str(constant[0]))
    assert not verify_secret(constant[1], result.credential.verifier)
    assert not verify_secret(constant[1], result.credential.verifier, key=secrets.token_bytes(32),
                             binding=str(constant[0]))
    with pytest.raises(CredentialRenewalProposalError):
        _renew(stack, (CredentialId.new(), "short"), RENEW_AT)
    with pytest.raises(CredentialRenewalProposalError):
        _renew(stack, (CredentialId.new(), "not a secret with spaces!!!!"), RENEW_AT)
    with pytest.raises(CredentialRenewalProposalError):
        _renew(stack, (stack.credential.credential_id, secrets.token_urlsafe(32)), RENEW_AT)
    with pytest.raises(CredentialRenewalProposalError):
        _renew(stack, (CredentialId.new(), stack.secret), RENEW_AT)


def test_degraded_and_offline_endpoints_may_confirm_but_new_endpoints_may_not():
    stack = _stack()
    successor = _successor()
    _renew(stack, successor, RENEW_AT)
    endpoint = stack.repository.endpoints[str(stack.endpoint.endpoint_id)]
    stack.repository.endpoints[str(stack.endpoint.endpoint_id)] = endpoint.transition_to(
        EndpointStatus.DEGRADED, RENEW_AT + MINUTE)
    assert _confirm(stack, successor, RENEW_AT + 2 * MINUTE).credential_id == successor[0]

    later = _stack()
    nxt = _successor()
    _renew(later, nxt, RENEW_AT)
    later_endpoint = later.repository.endpoints[str(later.endpoint.endpoint_id)]
    later.repository.endpoints[str(later.endpoint.endpoint_id)] = later_endpoint.transition_to(
        EndpointStatus.OFFLINE, RENEW_AT + MINUTE)
    with pytest.raises(EndpointNotActiveForRenewalError):
        later.service.renew_credential(later.endpoint.endpoint_id, later.secret,
                                       claimed_credential_id=later.credential.credential_id,
                                       successor_credential_id=CredentialId.new(),
                                       successor_secret=secrets.token_urlsafe(32), now=RENEW_AT + 2 * MINUTE)
    assert _confirm(later, nxt, RENEW_AT + 2 * MINUTE).credential_id == nxt[0]

    unapproved = _stack(approve=False)
    with pytest.raises(EndpointNotActiveForRenewalError):
        unapproved.service.confirm_credential_renewal(
            unapproved.endpoint.endpoint_id, unapproved.secret,
            claimed_credential_id=unapproved.credential.credential_id, now=RENEW_AT)


def test_future_dated_replay_is_still_claimed_after_the_full_freshness_window():
    stack = _stack()
    guard = InMemoryReplayGuard()
    policy = ProtocolValidationPolicy()
    message_id = MessageId()
    successor = _successor()
    _renew(stack, successor, RENEW_AT, message_id=message_id, replay_guard=guard, replay_ttl=policy.replay_retention)
    assert policy.replay_retention == timedelta(minutes=11)
    with pytest.raises(CredentialRenewalReplayError):
        _renew(stack, successor, RENEW_AT + timedelta(minutes=10, seconds=30),
               message_id=message_id, replay_guard=guard, replay_ttl=policy.replay_retention)
    retry = _renew(stack, successor, RENEW_AT + timedelta(minutes=11, seconds=1),
                   message_id=MessageId(), replay_guard=guard, replay_ttl=policy.replay_retention)
    assert retry.credential.credential_id == successor[0]
