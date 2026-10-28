"""FastAPI ingress for authenticated outbound agent traffic."""

import json
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ....application.agent.processor import AgentMessageProcessor, EnrollmentMessageProcessor, MessageAcceptanceError
from ....application.enrollment.service import (
    AgentOrganizationSuspendedError,
    CredentialRenewalConflictError,
    CredentialRenewalNotDueError,
    CredentialRenewalProposalError,
    CredentialRenewalReplayError,
    EndpointNotActiveForRenewalError,
    EnrollmentError,
    EnrollmentService,
)
from ....application.ports.agent_transport import PresentedCredential
from ....domain.endpoint import EndpointId, EndpointStatus
from ....domain.enrollment import EnrollmentId
from ....infrastructure.operational.rate_limiter import InMemoryRateLimiter
from ....protocol.agent import (
    AgentMessageEnvelope,
    CredentialRenewalConfirmationPayload,
    CredentialRenewalConfirmPayload,
    CredentialRenewalRequestPayload,
    CredentialRenewalResponsePayload,
    EnrollmentRequestPayload,
    InMemoryReplayGuard,
    ProtocolError,
    ProtocolValidationPolicy,
)
from .outbox import PendingWorkQueue


_RENEW_FIELDS = frozenset({
    "message_id", "timestamp", "nonce", "protocol_version", "credential_id",
    "successor_credential_id", "successor_credential_secret", "endpoint_id", "organization_id",
})
_CONFIRM_FIELDS = frozenset({
    "message_id", "timestamp", "nonce", "protocol_version", "credential_id", "replaces_credential_id", "endpoint_id",
})


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentHttpIngress:
    def __init__(self, processor: AgentMessageProcessor, enrollment_service: EnrollmentService,
                 outbox: PendingWorkQueue, *, work_repository=None, policy: Optional[ProtocolValidationPolicy] = None,
                 lease_duration=timedelta(minutes=5), max_attempts=3, retry_delay=timedelta(seconds=0),
                 enrollment_rate_limiter=None, credential_rate_limiter=None, replay_guard=None,
                 clock: Optional[Callable[[], datetime]] = None):
        self.processor = processor
        self.enrollment_service = enrollment_service
        self.outbox = outbox
        self.work_repository = work_repository
        self.policy = policy or ProtocolValidationPolicy()
        self.lease_duration = lease_duration
        self.max_attempts = max_attempts
        self.retry_delay = retry_delay
        self.enrollment_rate_limiter = enrollment_rate_limiter or InMemoryRateLimiter(10, 60)
        self.credential_rate_limiter = credential_rate_limiter or InMemoryRateLimiter(60, 60)
        # Renewal shares the protocol message-id namespace with /messages.
        self.replay_guard = replay_guard or getattr(processor, "replay_guard", None) or InMemoryReplayGuard()
        self._clock = clock or _utc_now

    async def enroll(self, request: Request):
        peer = request.client.host if request.client else "unknown"
        decision = self.enrollment_rate_limiter.check(f"enroll:{peer}")
        if not decision.allowed:
            return JSONResponse({"error": "enrollment_rejected"}, status_code=429,
                                headers={"Retry-After": str(decision.retry_after), "Cache-Control": "no-store"})
        body = await self._read_json_body(request, max_payload_bytes=16 * 1024)
        token = _bearer(request)
        enrollment_id = request.headers.get("X-Raven-Enrollment-Id")
        if token is None or len(token) > 128 or not enrollment_id or any(ch.isspace() for ch in token):
            return _enrollment_rejected()
        if not isinstance(body, dict) or set(body) - {"hostname", "platform", "agent_version", "protocol_version", "request_id", "nonce"}:
            return _enrollment_rejected()
        try:
            payload = EnrollmentRequestPayload.from_wire_dict({
                **body, "enrollment_token": token, "enrollment_id": str(EnrollmentId.parse(enrollment_id)),
            })
            if len(payload.hostname) > 255 or len(payload.agent_version) > 100 or len(payload.request_id or "") > 100 or len(payload.nonce or "") > 100:
                return _enrollment_rejected()
            if await run_in_threadpool(self.enrollment_service.authorization_organization, payload.enrollment_id) is None:
                return _enrollment_rejected()
            result = await run_in_threadpool(EnrollmentMessageProcessor(self.enrollment_service).process, payload)
            return JSONResponse(result.to_wire_dict(), status_code=201, headers={"Cache-Control": "no-store"})
        except (EnrollmentError, ProtocolError, ValueError, KeyError, TypeError):
            return _enrollment_rejected()

    async def message(self, request: Request):
        limited = self._credential_limit(request)
        if limited is not None:
            return limited
        body = await self._read_json_body(request)
        secret = _bearer(request)
        if secret is None:
            return _error(401, "authentication_failed")
        try:
            envelope = AgentMessageEnvelope.from_dict(body)
            await run_in_threadpool(self.processor.process, envelope, PresentedCredential(secret, method="bearer"),
                                    now=self._clock())
            return JSONResponse({"accepted": True, "message_id": str(envelope.message_id)})
        except MessageAcceptanceError as error:
            return _processor_error(error)
        except (ProtocolError, ValueError, TypeError, KeyError):
            return _error(422, "malformed_protocol")

    async def work(self, request: Request):
        limited = self._credential_limit(request)
        if limited is not None:
            return limited
        secret = _bearer(request)
        endpoint_header = request.headers.get("X-Raven-Endpoint-Id")
        if secret is None or not endpoint_header:
            return _error(401, "authentication_failed")
        now = self._clock()
        try:
            endpoint_id = EndpointId(endpoint_header)
            await run_in_threadpool(self.enrollment_service.verify_credential, endpoint_id, secret, now=now)
            endpoint = await run_in_threadpool(self.enrollment_service.get_endpoint, endpoint_id)
            if endpoint is None or endpoint.status is not EndpointStatus.ACTIVE:
                return _error(403, "endpoint_not_active")
        except AgentOrganizationSuspendedError:
            return _error(403, "endpoint_not_active")
        except (EnrollmentError, ValueError):
            return _error(401, "authentication_failed")
        if self.work_repository is not None:
            leased = await run_in_threadpool(self.work_repository.lease_next, endpoint_id,
                                             now=now,
                                             lease_duration=self.lease_duration, max_attempts=self.max_attempts,
                                             retry_delay=self.retry_delay)
            if leased is None:
                return JSONResponse({"message": None, "work": None})
            item = leased.item
            return JSONResponse({"message": item.envelope, "work": {
                "work_id": str(item.work_id), "lease_token": leased.lease_token,
                "lease_expires_at": item.lease_expires_at.isoformat(),
            }})
        envelope = await run_in_threadpool(self.outbox.lease, endpoint_id)
        return JSONResponse({"message": envelope.to_dict() if envelope else None,
                             "work": {"work_id": str(envelope.message_id), "lease_token": "legacy-lease",
                                       "lease_expires_at": (now + timedelta(minutes=5)).isoformat()} if envelope else None})

    async def renew(self, request: Request):
        """Activate an agent-prepared successor; the response never contains credential material."""
        limited = self._credential_limit(request)
        if limited is not None:
            return limited
        body = await self._read_json_body(request, max_payload_bytes=16 * 1024)
        secret = _bearer(request)
        endpoint_header = request.headers.get("X-Raven-Endpoint-Id")
        if secret is None or not endpoint_header:
            return _error(401, "authentication_failed")
        if not isinstance(body, dict) or set(body) - _RENEW_FIELDS:
            return _error(422, "malformed_protocol")
        try:
            endpoint_id = EndpointId(endpoint_header)
            payload = CredentialRenewalRequestPayload.from_wire_dict(body)
            payload.protocol_version.ensure_supported()
        except (ProtocolError, ValueError, TypeError, KeyError):
            return _error(422, "malformed_protocol")
        now = self._clock()
        if abs((now - payload.timestamp).total_seconds()) > self.policy.max_clock_skew.total_seconds():
            return _error(400, "stale_or_future_message")
        header_organization = request.headers.get("X-Raven-Organization-Id")
        if payload.organization_id and header_organization and payload.organization_id != header_organization:
            return _error(401, "authentication_failed")
        try:
            result = await run_in_threadpool(
                self.enrollment_service.renew_credential, endpoint_id, secret,
                claimed_credential_id=payload.credential_id,
                successor_credential_id=payload.successor_credential_id,
                successor_secret=payload.successor_credential_secret,
                now=now,
                claimed_endpoint_id=payload.endpoint_id,
                claimed_organization_id=payload.organization_id or header_organization,
                message_id=payload.message_id,
                replay_guard=self.replay_guard,
                replay_ttl=self.policy.replay_retention,
            )
        except CredentialRenewalReplayError:
            return _error(409, "replayed_message")
        except CredentialRenewalConflictError:
            return _error(409, "renewal_conflict")
        except CredentialRenewalNotDueError:
            return _error(409, "renewal_not_due")
        except (EndpointNotActiveForRenewalError, AgentOrganizationSuspendedError):
            return _error(403, "endpoint_not_active")
        except CredentialRenewalProposalError:
            return _error(422, "invalid_renewal_proposal")
        except (EnrollmentError, ValueError, PermissionError):
            return _error(401, "authentication_failed")
        receipt = CredentialRenewalResponsePayload(
            endpoint_id=result.endpoint.endpoint_id,
            organization_id=str(result.endpoint.organization_id),
            credential_id=str(result.credential.credential_id),
            replaces_credential_id=str(result.renewal.predecessor_credential_id),
            credential_expires_at=result.credential.expires_at.isoformat(),
            predecessor_valid_until=result.renewal.predecessor_valid_until.isoformat(),
            protocol_version=payload.protocol_version,
            status=result.credential.status.value,
        )
        return JSONResponse(receipt.to_dict(), status_code=200, headers={"Cache-Control": "no-store"})

    async def confirm_renewal(self, request: Request):
        """Prove successor possession; also the recovery probe after a lost renewal response."""
        limited = self._credential_limit(request)
        if limited is not None:
            return limited
        body = await self._read_json_body(request, max_payload_bytes=16 * 1024)
        secret = _bearer(request)
        endpoint_header = request.headers.get("X-Raven-Endpoint-Id")
        if secret is None or not endpoint_header:
            return _error(401, "authentication_failed")
        if not isinstance(body, dict) or set(body) - _CONFIRM_FIELDS:
            return _error(422, "malformed_protocol")
        try:
            endpoint_id = EndpointId(endpoint_header)
            payload = CredentialRenewalConfirmPayload.from_wire_dict(body)
            payload.protocol_version.ensure_supported()
        except (ProtocolError, ValueError, TypeError, KeyError):
            return _error(422, "malformed_protocol")
        now = self._clock()
        if abs((now - payload.timestamp).total_seconds()) > self.policy.max_clock_skew.total_seconds():
            return _error(400, "stale_or_future_message")
        try:
            credential = await run_in_threadpool(
                self.enrollment_service.confirm_credential_renewal, endpoint_id, secret,
                claimed_credential_id=payload.credential_id,
                now=now,
                replaces_credential_id=payload.replaces_credential_id,
                claimed_endpoint_id=payload.endpoint_id,
                message_id=payload.message_id,
                replay_guard=self.replay_guard,
                replay_ttl=self.policy.replay_retention,
            )
            endpoint = await run_in_threadpool(self.enrollment_service.get_endpoint, endpoint_id)
        except CredentialRenewalReplayError:
            return _error(409, "replayed_message")
        except AgentOrganizationSuspendedError:
            return _error(403, "endpoint_not_active")
        except (EnrollmentError, ValueError, PermissionError):
            return _error(401, "authentication_failed")
        if endpoint is None or endpoint.organization_id is None or credential.expires_at is None:
            return _error(401, "authentication_failed")
        confirmation = CredentialRenewalConfirmationPayload(
            endpoint_id=endpoint.endpoint_id,
            organization_id=str(endpoint.organization_id),
            credential_id=str(credential.credential_id),
            credential_expires_at=credential.expires_at.isoformat(),
            replaces_credential_id=str(credential.replaces_credential_id) if credential.replaces_credential_id else None,
            confirmed=credential.renewal_confirmed_at is not None or credential.replaces_credential_id is None,
        )
        return JSONResponse(confirmation.to_dict(), status_code=200, headers={"Cache-Control": "no-store"})

    def _credential_limit(self, request: Request):
        peer = request.client.host if request.client else "unknown"
        decision = self.credential_rate_limiter.check(f"agent:{peer}")
        if decision.allowed:
            return None
        return JSONResponse({"error": "rate_limited"}, status_code=429,
                            headers={"Retry-After": str(decision.retry_after)})

    async def _read_json_body(self, request: Request, *, max_payload_bytes=None):
        maximum = max_payload_bytes or self.policy.max_payload_bytes
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise _HttpIngressError(415, "unsupported_content_type")
        declared = request.headers.get("content-length")
        if declared:
            try:
                declared_size = int(declared)
            except ValueError:
                raise _HttpIngressError(400, "malformed_request")
            if declared_size > maximum:
                raise _HttpIngressError(413, "payload_too_large")
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > maximum:
                raise _HttpIngressError(413, "payload_too_large")
        try:
            return json.loads(chunks.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _HttpIngressError(400, "malformed_json")


class _HttpIngressError(Exception):
    def __init__(self, status_code, code):
        self.status_code, self.code = status_code, code


def create_agent_http_router(processor: AgentMessageProcessor, enrollment_service: EnrollmentService,
                             outbox: Optional[PendingWorkQueue] = None, *, work_repository=None,
                             policy: Optional[ProtocolValidationPolicy] = None, lease_duration=timedelta(minutes=5),
                             max_attempts=3, retry_delay=timedelta(seconds=0), enrollment_rate_limiter=None,
                             credential_rate_limiter=None, replay_guard=None, clock=None):
    ingress = AgentHttpIngress(processor, enrollment_service, outbox or PendingWorkQueue(), work_repository=work_repository,
                               policy=policy, lease_duration=lease_duration, max_attempts=max_attempts, retry_delay=retry_delay,
                               enrollment_rate_limiter=enrollment_rate_limiter,
                               credential_rate_limiter=credential_rate_limiter,
                               replay_guard=replay_guard, clock=clock)
    router = APIRouter()

    @router.post("/enroll")
    async def enroll(request: Request):
        try:
            return await ingress.enroll(request)
        except _HttpIngressError as error:
            return _error(error.status_code, error.code)
        except Exception:
            return _error(500, "internal_error")

    @router.post("/messages")
    async def messages(request: Request):
        try:
            return await ingress.message(request)
        except _HttpIngressError as error:
            return _error(error.status_code, error.code)
        except Exception:
            return _error(500, "internal_error")

    @router.post("/work")
    async def work(request: Request):
        try:
            return await ingress.work(request)
        except Exception:
            return _error(500, "internal_error")

    @router.post("/renew")
    async def renew(request: Request):
        try:
            return await ingress.renew(request)
        except _HttpIngressError as error:
            return _error(error.status_code, error.code)
        except Exception:
            return _error(500, "internal_error")

    @router.post("/renew/confirm")
    async def confirm_renewal(request: Request):
        try:
            return await ingress.confirm_renewal(request)
        except _HttpIngressError as error:
            return _error(error.status_code, error.code)
        except Exception:
            return _error(500, "internal_error")

    return router


def create_agent_http_app(processor: AgentMessageProcessor, enrollment_service: EnrollmentService,
                          outbox: Optional[PendingWorkQueue] = None, *, work_repository=None,
                          policy: Optional[ProtocolValidationPolicy] = None, lease_duration=timedelta(minutes=5),
                          max_attempts=3, retry_delay=timedelta(seconds=0), enrollment_rate_limiter=None,
                          credential_rate_limiter=None, replay_guard=None, clock=None):
    app = FastAPI(title="RAVEN-X Agent Transport", docs_url=None, redoc_url=None)
    app.include_router(create_agent_http_router(processor, enrollment_service, outbox, work_repository=work_repository,
                                                policy=policy, lease_duration=lease_duration, max_attempts=max_attempts,
                                                retry_delay=retry_delay, enrollment_rate_limiter=enrollment_rate_limiter,
                                                credential_rate_limiter=credential_rate_limiter,
                                                replay_guard=replay_guard, clock=clock), prefix="/api/v1/agent")
    return app


def _bearer(request: Request) -> Optional[str]:
    value = request.headers.get("authorization", "")
    scheme, _, secret = value.partition(" ")
    secret = secret.strip()
    if scheme.lower() != "bearer" or not secret or len(secret) > 128 or any(ch.isspace() for ch in secret):
        return None
    return secret


def _processor_error(error: MessageAcceptanceError):
    mapping = {
        "invalid_credential": 401,
        "endpoint_mismatch": 401,
        "direction_not_allowed": 403,
        "replayed_message": 409,
        "stale_or_future_message": 400,
        "payload_too_large": 413,
        "endpoint_not_active": 403,
    }
    return _error(mapping.get(error.code, 422), "message_rejected")


def _error(status_code: int, code: str):
    return JSONResponse(status_code=status_code, content={"error": code}, headers={"Cache-Control": "no-store"})


def _enrollment_rejected():
    return JSONResponse(status_code=401, content={"error": "enrollment_rejected"},
                        headers={"Cache-Control": "no-store"})
