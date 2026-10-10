from datetime import datetime, timedelta, timezone
import pytest

from backend.application.identity.service import AuthenticationFailure, HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator
from backend.domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType, SecurityPrincipal)
from backend.domain.user import UserId, UserStatus
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository
from backend.infrastructure.persistence.in_memory_user_repository import InMemoryUserRepository
from backend.infrastructure.security import PasswordHasher
from backend.infrastructure.security import hash_secret, hash_token
from backend.application.ports.control_plane_authorization import ConservativeControlPlaneAuthorizer

PASSWORD = "correct horse battery staple"

def test_user_id_is_opaque_and_email_is_canonicalized():
    repo = InMemoryUserRepository(); audit = InMemorySecurityAuditRepository()
    user = HumanIdentityService(repo, audit_sink=audit).create_initial_user(" Ops@Example.COM ", "Operator", PASSWORD)
    assert user.email == "ops@example.com"
    assert UserId.parse(str(user.user_id)) == user.user_id
    assert str(user.user_id) not in user.email

def test_password_and_session_secrets_are_never_stored_or_repr_exposed():
    repo = InMemoryUserRepository(); user = HumanIdentityService(repo).create_initial_user("a@example.com", "A", PASSWORD)
    credential = repo.get_password_credential(user.user_id)
    assert PASSWORD not in credential.verifier and PASSWORD not in repr(credential)
    token, session, _ = HumanAuthenticationService(repo).authenticate(user.email, PASSWORD)
    assert token not in repr(session)
    assert token not in repr(repo.get_session(session.session_id))

def test_authentication_returns_human_principal_and_default_policy_denies():
    repo = InMemoryUserRepository(); user = HumanIdentityService(repo).create_initial_user("a@example.com", "A", PASSWORD)
    token, session, principal = HumanAuthenticationService(repo).authenticate(user.email, PASSWORD)
    assert principal.principal_type is PrincipalType.HUMAN
    decision = ConservativeControlPlaneAuthorizer().authorize(AuthorizationRequest(principal, AuthorizationAction.ASSESSMENT_CREATE, AuthorizationResource("assessment", "x")))
    assert not decision.allowed
    assert token not in principal.to_dict().__repr__()

def test_disabled_and_revoked_users_cannot_authenticate_or_validate_existing_session():
    repo = InMemoryUserRepository(); service = HumanIdentityService(repo); user = service.create_initial_user("a@example.com", "A", PASSWORD)
    token, session, _ = HumanAuthenticationService(repo).authenticate(user.email, PASSWORD)
    service.disable_user(user.user_id, principal=SecurityPrincipal.system())
    with pytest.raises(AuthenticationFailure): HumanAuthenticationService(repo).authenticate(user.email, PASSWORD)
    with pytest.raises(AuthenticationFailure): HumanSessionAuthenticator(repo).validate(token, session.session_id)

def test_bootstrap_is_single_use_and_failed_login_is_generic_and_audited():
    repo = InMemoryUserRepository(); audit = InMemorySecurityAuditRepository(); identity = HumanIdentityService(repo, audit_sink=audit)
    identity.create_initial_user("a@example.com", "A", PASSWORD)
    with pytest.raises(ValueError): identity.create_initial_user("b@example.com", "B", PASSWORD)
    with pytest.raises(AuthenticationFailure) as error: HumanAuthenticationService(repo, audit_sink=audit).authenticate("missing@example.com", PASSWORD)
    assert str(error.value) == "invalid credentials" and "missing@example.com" not in str(error.value)
    assert any(event.event_type == "human.authentication_failed" for event in audit.list())

def test_session_expiry_and_explicit_revocation():
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    clock = lambda: now[0]
    repo = InMemoryUserRepository(); user = HumanIdentityService(repo, clock=clock).create_initial_user("a@example.com", "A", PASSWORD)
    token, session, _ = HumanAuthenticationService(repo, clock=clock, session_lifetime=timedelta(minutes=1)).authenticate(user.email, PASSWORD)
    assert HumanSessionAuthenticator(repo, clock=clock).validate(token, session.session_id).principal_type is PrincipalType.HUMAN
    HumanSessionAuthenticator(repo, clock=clock).revoke_session(session.session_id)
    with pytest.raises(AuthenticationFailure): HumanSessionAuthenticator(repo, clock=clock).validate(token, session.session_id)


def test_bearer_authentication_enforces_expiry_revocation_and_user_status():
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    clock = lambda: now[0]
    repo = InMemoryUserRepository()
    identity = HumanIdentityService(repo, clock=clock)
    user = identity.create_initial_user("a@example.com", "A", PASSWORD)
    login = HumanAuthenticationService(repo, clock=clock, session_lifetime=timedelta(minutes=1))
    authenticator = HumanSessionAuthenticator(repo, clock=clock)

    expired_token, _, _ = login.authenticate(user.email, PASSWORD)
    now[0] += timedelta(minutes=2)
    with pytest.raises(AuthenticationFailure) as expired:
        authenticator.authenticate_bearer(expired_token)
    assert expired.value.reason_code == "SESSION_EXPIRED"

    revoked_token, revoked_session, _ = login.authenticate(user.email, PASSWORD)
    authenticator.revoke_session(revoked_session.session_id)
    with pytest.raises(AuthenticationFailure) as revoked:
        authenticator.authenticate_bearer(revoked_token)
    assert revoked.value.reason_code == "SESSION_REVOKED"

    inactive_token, _, _ = login.authenticate(user.email, PASSWORD)
    identity.disable_user(user.user_id, principal=SecurityPrincipal.system())
    with pytest.raises(AuthenticationFailure) as inactive:
        authenticator.authenticate_bearer(inactive_token)
    assert inactive.value.reason_code == "USER_INACTIVE"


def test_old_salted_session_requires_relogin_for_bearer_but_explicit_id_still_works():
    repo = InMemoryUserRepository()
    user = HumanIdentityService(repo).create_initial_user("a@example.com", "A", PASSWORD)
    token, session, _ = HumanAuthenticationService(repo).authenticate(user.email, PASSWORD)
    session.token_verifier = hash_secret(token)
    repo.update_session(session)
    authenticator = HumanSessionAuthenticator(repo)
    assert authenticator.authenticate(token, session.session_id).principal_type is PrincipalType.HUMAN
    with pytest.raises(AuthenticationFailure):
        authenticator.authenticate_bearer(token)


def test_fast_token_verifier_is_deterministic_and_bounded():
    token = "A" * 43
    assert hash_token(token) == hash_token(token)
    assert token not in hash_token(token)
    with pytest.raises(ValueError):
        hash_token("A" * 129)
