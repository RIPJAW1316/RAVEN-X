"""Compatibility import for the human authentication application boundary."""
from ..identity.service import AuthenticationFailure, AuthenticationResult, HumanAuthenticationService, HumanIdentityService, HumanSessionAuthenticator

__all__ = ["AuthenticationFailure", "AuthenticationResult", "HumanAuthenticationService", "HumanIdentityService", "HumanSessionAuthenticator"]
