"""SQLAlchemy adapter for human identity and server-side sessions."""
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from ...core.database.database import DatabaseManager
from ...core.database.models import UserRecord, UserCredentialRecord, HumanSessionRecord
from ...domain.user import CredentialKind, HumanCredential, User, UserId, UserSession, canonicalize_email
from ...application.ports.user_repository import DuplicateCredentialError, DuplicateUserError
from ...infrastructure.security import hash_token

def _store(dt): return dt.astimezone(__import__('datetime').timezone.utc).replace(tzinfo=None) if dt else None
def _load(dt): return dt.replace(tzinfo=__import__('datetime').timezone.utc) if dt else None

class SQLAlchemyUserRepository:
    def __init__(self, database_manager: DatabaseManager): self._database_manager = database_manager
    def add_user(self, user):
        try:
            with self._database_manager.get_db() as s:
                s.add(UserRecord(user_id=str(user.user_id), email=user.email, display_name=user.display_name, status=user.status.value,
                                 created_at=_store(user.created_at), updated_at=_store(user.updated_at), last_authenticated_at=_store(user.last_authenticated_at), user_metadata=dict(user.metadata)))
                s.flush()
        except IntegrityError as e: raise DuplicateUserError("user already exists") from e
    def get_user(self, user_id):
        with self._database_manager.get_db() as s: return _user(s.get(UserRecord, str(UserId.parse(user_id))))
    def get_user_by_email(self, email):
        with self._database_manager.get_db() as s: return _user(s.execute(select(UserRecord).where(UserRecord.email == canonicalize_email(email))).scalar_one_or_none())
    def count_users(self):
        with self._database_manager.get_db() as s: return len(s.execute(select(UserRecord.user_id)).all())
    def update_user(self, user):
        with self._database_manager.get_db() as s:
            r=s.get(UserRecord,str(user.user_id))
            if r is None: raise KeyError("user does not exist")
            r.email=user.email; r.display_name=user.display_name; r.status=user.status.value; r.updated_at=_store(user.updated_at); r.last_authenticated_at=_store(user.last_authenticated_at); r.user_metadata=dict(user.metadata)
    def add_credential(self, c):
        try:
            with self._database_manager.get_db() as s:
                s.add(UserCredentialRecord(credential_id=str(c.credential_id),user_id=str(c.user_id),credential_kind=c.kind.value,verifier=c.verifier,created_at=_store(c.created_at),updated_at=_store(c.updated_at),revoked_at=_store(c.revoked_at))); s.flush()
        except IntegrityError as e: raise DuplicateCredentialError("credential already exists") from e
    def get_password_credential(self,user_id):
        with self._database_manager.get_db() as s: return _credential(s.execute(select(UserCredentialRecord).where(UserCredentialRecord.user_id==str(UserId.parse(user_id)),UserCredentialRecord.credential_kind==CredentialKind.PASSWORD.value)).scalar_one_or_none())
    def add_session(self, session):
        with self._database_manager.get_db() as s: s.add(_session_record(session)); s.flush()
    def get_session(self, session_id):
        with self._database_manager.get_db() as s: return _session(s.get(HumanSessionRecord,str(UUID(str(session_id)))))
    def get_session_for_token(self, token):
        # New bearer tokens are random and have an indexable verifier.  Do not
        # scan legacy salted sessions: one invalid header could otherwise
        # trigger a scrypt call for every historical session.
        try:
            verifier = hash_token(token)
        except ValueError:
            return None
        with self._database_manager.get_db() as s:
            record = s.execute(select(HumanSessionRecord).where(
                HumanSessionRecord.token_verifier == verifier)).scalar_one_or_none()
            return _session(record)
    def update_session(self, session):
        with self._database_manager.get_db() as s:
            r=s.get(HumanSessionRecord,str(session.session_id))
            if r is None: raise KeyError("session does not exist")
            r.revoked_at=_store(session.revoked_at); r.last_used_at=_store(session.last_used_at)

    add = add_user
    get = get_user
    get_by_email = get_user_by_email

def _user(r):
    return User(UserId.parse(r.user_id),r.email,r.display_name,r.status,_load(r.created_at),_load(r.updated_at),_load(r.last_authenticated_at),r.user_metadata or {}) if r else None
def _credential(r):
    return HumanCredential(UUID(r.credential_id),UserId.parse(r.user_id),r.credential_kind,r.verifier,_load(r.created_at),_load(r.updated_at),_load(r.revoked_at)) if r else None
def _session_record(x):
    return HumanSessionRecord(session_id=str(x.session_id),user_id=str(x.user_id),token_verifier=x.token_verifier,created_at=_store(x.created_at),expires_at=_store(x.expires_at),revoked_at=_store(x.revoked_at),last_used_at=_store(x.last_used_at),authentication_method=x.authentication_method.value)
def _session(r):
    return UserSession(UUID(r.session_id),UserId.parse(r.user_id),r.token_verifier,_load(r.created_at),_load(r.expires_at),r.authentication_method,_load(r.revoked_at),_load(r.last_used_at)) if r else None
