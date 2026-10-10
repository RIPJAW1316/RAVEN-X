# Human authentication security boundary

Implemented now: scrypt password verifiers, generic invalid-credential failures
to reduce user enumeration, opaque high-entropy server-side session tokens,
expiry, revocation, inactive-user enforcement, and durable secret-safe audit
events. Repr/serialization paths redact credential and session verifier fields.

Partial: process-local callers must still protect session tokens in transit and
at rest; no login HTTP endpoint exists yet. Rate limiting, account throttling,
MFA, password reset, OIDC/SSO, and browser/session transport controls are
deferred until the control-plane authentication ingress is designed.

Threats such as database theft and offline password cracking are mitigated by
one-way salted scrypt hashing but remain dependent on password strength. Session
theft/replay is limited by opaque expiry and revocation; TLS and transport
binding are deferred to the future human HTTP-auth phase. A compromised control
plane remains trusted infrastructure and is not addressed here.
