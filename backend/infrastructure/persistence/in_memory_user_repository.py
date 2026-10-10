"""Deterministic in-memory user persistence for composition/tests."""
from copy import deepcopy
from uuid import UUID
from ...infrastructure.security import hash_token
from ...domain.user import HumanCredential, User, UserId, UserSession, canonicalize_email
from ...application.ports.user_repository import DuplicateCredentialError, DuplicateUserError

class InMemoryUserRepository:
    def __init__(self):
        self.users = {}; self.credentials = {}; self.sessions = {}; self._session_verifiers = {}
    def add_user(self, user):
        if user.user_id in self.users or self.get_user_by_email(user.email): raise DuplicateUserError("user already exists")
        self.users[user.user_id] = deepcopy(user)
    def get_user(self, user_id): return deepcopy(self.users.get(UserId.parse(user_id)))
    def get_user_by_email(self, email):
        email = canonicalize_email(email)
        return next((deepcopy(u) for u in self.users.values() if u.email == email), None)
    def count_users(self): return len(self.users)
    def update_user(self, user):
        if UserId.parse(user.user_id) not in self.users: raise KeyError("user does not exist")
        self.users[user.user_id] = deepcopy(user)
    def add_credential(self, credential):
        if credential.credential_id in self.credentials: raise DuplicateCredentialError("credential already exists")
        self.credentials[credential.user_id] = deepcopy(credential)
    def get_password_credential(self, user_id): return deepcopy(self.credentials.get(UserId.parse(user_id)))
    def add_session(self, session):
        session_id = UUID(str(session.session_id))
        self.sessions[session_id] = deepcopy(session)
        self._session_verifiers[session.token_verifier] = session_id
    def get_session(self, session_id): return deepcopy(self.sessions.get(UUID(str(session_id))))
    def get_session_for_token(self, token):
        try:
            session_id = self._session_verifiers.get(hash_token(token))
        except ValueError:
            return None
        return deepcopy(self.sessions.get(session_id))
    def update_session(self, session):
        session_id = UUID(str(session.session_id))
        previous = self.sessions.get(session_id)
        if previous is None: raise KeyError("session does not exist")
        if previous.token_verifier != session.token_verifier:
            self._session_verifiers.pop(previous.token_verifier, None)
        self.sessions[session_id] = deepcopy(session)
        self._session_verifiers[session.token_verifier] = session_id

    # Short aliases make the port convenient for application composition while
    # retaining explicit names at the protocol boundary.
    add = add_user
    get = get_user
    get_by_email = get_user_by_email
    exists = lambda self, user_id: UserId.parse(user_id) in self.users
