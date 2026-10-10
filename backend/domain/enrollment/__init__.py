"""Pure enrollment and credential contracts.

These objects describe trust-boundary state only; they contain no transport,
authentication framework, or persistence dependencies.
"""

from .models import (
    CredentialId,
    CredentialKind,
    CredentialStatus,
    EndpointCredential,
    EnrollmentAuthorization,
    EnrollmentId,
    EnrollmentRequest,
    EnrollmentStatus,
)

__all__ = [
    "CredentialId",
    "CredentialKind",
    "CredentialStatus",
    "EndpointCredential",
    "EnrollmentAuthorization",
    "EnrollmentId",
    "EnrollmentRequest",
    "EnrollmentStatus",
]
