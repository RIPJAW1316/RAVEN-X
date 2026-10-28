"""Agent-side credential renewal state machine (WS-01).

States, all persisted under the protected agent directory:

* CURRENT        credential.bin holds the usable credential; no renewal.bin.
* PREPARED       renewal.bin holds an agent-generated successor for the current
                 credential. Written durably before any request is sent.
* PROMOTED       credential.bin holds the successor; renewal.bin is removed (a
                 leftover file naming the current credential is discarded).

Transitions on every ``advance()`` (under the OS renewal lock):

1. CURRENT and outside the renewal threshold: nothing to do.
2. CURRENT and inside the threshold: write renewal.bin, then go to 3.
3. PREPARED and the stored credential is unexpired: propose the successor
   authenticated by the stored credential. A receipt naming exactly this
   successor promotes it. A retry of the same successor is idempotent.
4. PREPARED and the stored credential is rejected (401) or expired: probe with
   the prepared successor via the confirmation route. Success means the server
   committed it earlier (e.g. the response was lost); promote it.
5. Both rejected: the endpoint, its organization, or the lineage is revoked, or
   the stored credential expired before any successor was committed. Operator
   re-enrollment is required; expired credentials are never sent.

Transient failures leave renewal.bin untouched and are retried later, so no
outcome depends on receiving one particular HTTP response.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import random
import time

from ..infrastructure.transport.http.client import HttpTransportError
from .runtime import AgentCredential
from .windows_store import AgentStateError, RenewalLockBusyError


class ReEnrollmentRequiredError(AgentStateError):
    """Neither the stored nor the prepared credential is accepted; an operator must re-enroll."""


class RenewalConflictError(AgentStateError):
    """The server holds a different successor for the stored credential."""


class RenewalOutcome(str, Enum):
    NOT_DUE = "not_due"
    WAITING = "waiting"
    BUSY = "busy"
    RENEWED = "renewed"
    RECOVERED = "recovered"
    DEFERRED = "deferred"


# Failures that end automatic renewal or indicate a broken server contract.
_TERMINAL_CODES = frozenset({
    "authentication_failed", "renewal_conflict", "invalid_response", "endpoint_mismatch",
    "missing_credential", "missing_endpoint_id", "payload_too_large",
})
_MAX_RENEWED_LIFETIME = timedelta(days=31)


class CredentialRenewalCoordinator:
    def __init__(self, store, transport, *, now_fn=None, clock=time.monotonic, jitter=random.uniform,
                 threshold: timedelta = timedelta(days=7), retry_interval: timedelta = timedelta(seconds=60)):
        if threshold <= timedelta(0) or retry_interval < timedelta(0):
            raise ValueError("renewal threshold must be positive and retry interval non-negative")
        self._store = store
        self._transport = transport
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._clock = clock
        self._jitter = jitter
        self._threshold = threshold
        self._retry_seconds = retry_interval.total_seconds()
        self._next_attempt = 0.0

    def advance(self) -> RenewalOutcome:
        """Run at most one renewal step. Raises only when the agent cannot continue safely."""
        record = self._store.load_record()
        if record is None:
            raise AgentStateError("endpoint is not enrolled")
        if record.credential_expires_at > self._now() and self._clock() < self._next_attempt:
            return RenewalOutcome.WAITING
        try:
            with self._store.renewal_lock():
                return self._advance_locked(self._now())
        except RenewalLockBusyError:
            return RenewalOutcome.BUSY

    def _advance_locked(self, now: datetime) -> RenewalOutcome:
        record, pending = self._store.reconcile_renewal_state()
        if record is None:
            raise AgentStateError("endpoint is not enrolled")
        current_valid = record.credential_expires_at > now
        if pending is None:
            if not current_valid:
                raise ReEnrollmentRequiredError("endpoint credential has expired; enroll again")
            if record.credential_expires_at - now > self._threshold:
                return RenewalOutcome.NOT_DUE
            pending = self._store.prepare_renewal(now=now)
        try:
            if current_valid:
                outcome = self._propose(record, pending, now)
                if outcome is not None:
                    return outcome
            return self._recover(record, pending, now)
        except HttpTransportError as error:
            if error.code in _TERMINAL_CODES:
                raise
            self._next_attempt = self._clock() + self._jitter(self._retry_seconds * 0.8, self._retry_seconds)
            if not current_valid:
                # Nothing else can authenticate; let the host back off and retry.
                raise
            return RenewalOutcome.DEFERRED

    def _propose(self, record, pending, now):
        try:
            receipt = self._transport.renew_credential(
                credential=AgentCredential(record.credential_id, record.credential_secret),
                successor_credential_id=str(pending.successor_credential_id),
                successor_credential_secret=pending.successor_credential_secret,
                protocol_version=record.protocol_version,
                timestamp=now,
            )
        except HttpTransportError as error:
            if error.code == "authentication_failed":
                return None
            if error.code == "renewal_conflict":
                raise RenewalConflictError(
                    "the stored credential was already renewed to a different successor; "
                    "possible credential compromise, operator re-enrollment required") from error
            raise
        self._promote(pending, receipt.credential_expires_at, now)
        try:
            self._transport.confirm_renewal(
                credential=pending.as_credential(),
                replaces_credential_id=str(pending.predecessor_credential_id),
                protocol_version=record.protocol_version, timestamp=now,
            )
        except HttpTransportError:
            pass  # The first request authenticated with the successor confirms it implicitly.
        return RenewalOutcome.RENEWED

    def _recover(self, record, pending, now):
        try:
            confirmation = self._transport.confirm_renewal(
                credential=pending.as_credential(),
                replaces_credential_id=str(pending.predecessor_credential_id),
                protocol_version=record.protocol_version, timestamp=now,
            )
        except HttpTransportError as error:
            if error.code == "authentication_failed":
                raise ReEnrollmentRequiredError(
                    "neither the stored nor the prepared credential is accepted; "
                    "operator re-enrollment is required") from error
            raise
        self._promote(pending, confirmation.credential_expires_at, now)
        return RenewalOutcome.RECOVERED

    def _promote(self, pending, expires_at: datetime, now: datetime) -> None:
        if not now < expires_at <= now + _MAX_RENEWED_LIFETIME:
            raise AgentStateError("server reported an invalid renewed credential lifetime")
        self._store.promote_renewal(pending, credential_expires_at=expires_at)
