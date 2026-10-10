"""Dedicated password hashing boundary; raw passwords never leave this module."""
from .secret_verifiers import hash_secret, verify_secret

class PasswordHasher:
    minimum_length = 12
    def hash(self, password: str) -> str:
        if not isinstance(password, str) or len(password) < self.minimum_length:
            raise ValueError(f"password must be at least {self.minimum_length} characters")
        return hash_secret(password)
    def verify(self, password: str, verifier: str) -> bool:
        return isinstance(password, str) and verify_secret(password, verifier)
