"""Local human authentication without HTTP, roles, organizations, or RBAC."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import secrets
from uuid import uuid4
from ...domain.security import (AuthorizationAction, AuthorizationRequest, AuthorizationResource,
    SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal)
from ...domain.user import CredentialKind, HumanCredential, User, UserId, UserSession, UserStatus, canonicalize_email
from ...infrastructure.security import PasswordHasher, generate_secret, hash_token, verify_secret
from ...application.ports.user_repository import UserRepository

class AuthenticationFailure(ValueError):
    """Generic externally safe authentication failure."""
    def __init__(self, reason_code="INVALID_CREDENTIALS"): super().__init__("invalid credentials"); self.reason_code=reason_code

def _now(clock=None): return (clock or (lambda: datetime.now(timezone.utc)))()

@dataclass(frozen=True)
class AuthenticationResult:
    session_token: str = field(repr=False)
    session: UserSession
    principal: SecurityPrincipal
    @property
    def token(self): return self.session_token
    @property
    def raw_token(self): return self.session_token
    def __iter__(self):
        yield self.session_token; yield self.session; yield self.principal

class HumanIdentityService:
    def __init__(self, repository: UserRepository, *, audit_sink=None, authorization_service=None, clock=None, password_hasher=None):
        self.repository=repository; self.audit_sink=audit_sink; self.authorization_service=authorization_service; self.clock=clock; self.hasher=password_hasher or PasswordHasher()
    def create_initial_user(self, email, display_name, password, *, principal=None):
        if self.repository.count_users(): raise ValueError("bootstrap user already exists")
        principal = principal or SecurityPrincipal.system()
        self._require(principal, AuthorizationAction.USER_CREATE, "user")
        now=_now(self.clock); user=User(UserId.new(),email,display_name,UserStatus.ACTIVE,now,now)
        self.repository.add_user(user)
        self.repository.add_credential(HumanCredential(uuid4(),user.user_id,CredentialKind.PASSWORD,self.hasher.hash(password),now,now))
        self._audit(SecurityAuditEventType.USER_CREATED,user,principal)
        return user
    def create_user(self, email, display_name, password, *, principal):
        if self.repository.count_users()==0: return self.create_initial_user(email,display_name,password,principal=principal)
        self._require(principal, AuthorizationAction.USER_CREATE, "user")
        now=_now(self.clock); user=User(UserId.new(),email,display_name,UserStatus.ACTIVE,now,now); self.repository.add_user(user)
        self.repository.add_credential(HumanCredential(uuid4(),user.user_id,CredentialKind.PASSWORD,self.hasher.hash(password),now,now)); self._audit(SecurityAuditEventType.USER_CREATED,user,principal); return user
    def disable_user(self,user_id,*,principal): return self._change_status(user_id,UserStatus.DISABLED,principal)
    def revoke_user(self,user_id,*,principal): return self._change_status(user_id,UserStatus.REVOKED,principal)
    def _change_status(self,user_id,status,principal):
        self._require(principal, AuthorizationAction.USER_DISABLE if status is UserStatus.DISABLED else AuthorizationAction.USER_REVOKE, "user", str(user_id)); user=self.repository.get_user(user_id)
        if user is None: raise KeyError("user does not exist")
        user.status=status; user.updated_at=_now(self.clock); self.repository.update_user(user); self._audit(SecurityAuditEventType.USER_DISABLED if status is UserStatus.DISABLED else SecurityAuditEventType.USER_REVOKED,user,principal); return user
    def _require(self,principal,action,resource_type,resource_id=None):
        if self.authorization_service: self.authorization_service.require(AuthorizationRequest(principal,action,AuthorizationResource(resource_type,resource_id)))
    def _audit(self,event_type,user,principal,outcome=SecurityAuditOutcome.SUCCESS,reason_code=None,metadata=None):
        if self.audit_sink: self.audit_sink.append(SecurityAuditEvent(event_type=event_type.value,principal=principal,outcome=outcome,reason_code=reason_code,resource=AuthorizationResource("user",str(user.user_id)),metadata=metadata or {"email":user.email}))

class HumanAuthenticationService:
    def __init__(self, repository: UserRepository, *, audit_sink=None, clock=None, session_lifetime=timedelta(hours=8), password_hasher=None, telemetry=None):
        self.repository=repository; self.audit_sink=audit_sink; self.clock=clock; self.session_lifetime=session_lifetime; self.hasher=password_hasher or PasswordHasher(); self.telemetry=telemetry
    def authenticate(self,email,password):
        canonical=canonicalize_email(email); user=self.repository.get_user_by_email(canonical); credential=self.repository.get_password_credential(user.user_id) if user else None
        valid = bool(user and credential and user.status is UserStatus.ACTIVE and credential.revoked_at is None and self.hasher.verify(password,credential.verifier))
        if not valid:
            self._telemetry(False)
            self._audit(SecurityAuditEventType.HUMAN_AUTHENTICATION_FAILED, user, "INVALID_CREDENTIALS", {"login":canonical}); raise AuthenticationFailure()
        now=_now(self.clock); token=generate_secret(); session=UserSession(uuid4(),user.user_id,hash_token(token),now,now+self.session_lifetime)
        self.repository.add_session(session); user.last_authenticated_at=now; user.updated_at=now; self.repository.update_user(user)
        self._telemetry(True)
        self._audit(SecurityAuditEventType.HUMAN_AUTHENTICATION_SUCCEEDED,user,None,{"session_id":str(session.session_id)})
        self._audit(SecurityAuditEventType.SESSION_ISSUED,user,None,{"session_id":str(session.session_id)})
        return AuthenticationResult(token, session, SecurityPrincipal.human(user.user_id))
    login = authenticate
    def _telemetry(self,success):
        # Authentication precedes tenant selection, so this is process-wide.
        # Telemetry must never be able to fail a sign-in.
        if self.telemetry is None: return
        try: self.telemetry.record_authentication(success=success)
        except Exception: pass
    def _audit(self,event_type,user,reason=None,metadata=None):
        if self.audit_sink: self.audit_sink.append(SecurityAuditEvent(event_type=event_type.value,principal=SecurityPrincipal.human(user.user_id) if user else SecurityPrincipal.system(),outcome=SecurityAuditOutcome.DENIED if event_type is SecurityAuditEventType.HUMAN_AUTHENTICATION_FAILED else SecurityAuditOutcome.SUCCESS,reason_code=reason,user_id=str(user.user_id) if user else None,metadata=metadata or {}))

class HumanSessionAuthenticator:
    def __init__(self, repository: UserRepository, *, audit_sink=None, clock=None): self.repository=repository; self.audit_sink=audit_sink; self.clock=clock
    def authenticate(self, token, session_id):
        session=self.repository.get_session(session_id); user=self.repository.get_user(session.user_id) if session else None; now=_now(self.clock)
        reason=None
        if not session or not verify_secret(token,session.token_verifier): reason="INVALID_SESSION"
        elif session.revoked_at is not None: reason="SESSION_REVOKED"
        elif session.is_expired(now): reason="SESSION_EXPIRED"
        elif not user or user.status is not UserStatus.ACTIVE: reason="USER_INACTIVE"
        if reason:
            if reason == "SESSION_EXPIRED" and self.audit_sink:
                self.audit_sink.append(SecurityAuditEvent(event_type=SecurityAuditEventType.SESSION_EXPIRED.value,
                    principal=SecurityPrincipal.human(session.user_id) if session else SecurityPrincipal.system(),
                    outcome=SecurityAuditOutcome.DENIED, reason_code=reason,
                    metadata={"session_id": str(session.session_id)} if session else {}))
            raise AuthenticationFailure(reason)
        session.last_used_at=now; self.repository.update_session(session); return SecurityPrincipal.human(user.user_id)
    validate = authenticate
    def authenticate_bearer(self, token):
        """Validate an opaque bearer token without exposing session identifiers.

        The repository owns the token-verifier lookup; callers only receive the
        normal HUMAN principal.  This keeps HTTP presentation separate from
        the session model and avoids putting a session id in a bearer header.
        """
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationFailure()
        session = self.repository.get_session_for_token(token)
        if session is None:
            raise AuthenticationFailure()
        return self.authenticate(token, session.session_id)
    def revoke_session(self,session_id,*,principal=None):
        session=self.repository.get_session(session_id)
        if not session: raise KeyError("session does not exist")
        session.revoked_at=_now(self.clock); self.repository.update_session(session)
        if self.audit_sink: self.audit_sink.append(SecurityAuditEvent(event_type=SecurityAuditEventType.SESSION_REVOKED.value,principal=principal or SecurityPrincipal.human(session.user_id),outcome=SecurityAuditOutcome.SUCCESS,metadata={"session_id":str(session.session_id)}))
