"""FastAPI ingress for authenticated outbound agent traffic."""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ....application.agent.processor import AgentMessageProcessor, EnrollmentMessageProcessor, MessageAcceptanceError
from ....application.enrollment.service import EnrollmentError, EnrollmentService
from ....application.ports.agent_transport import PresentedCredential
from ....domain.endpoint import EndpointId, EndpointStatus
from ....domain.enrollment import EnrollmentId
from ....infrastructure.operational.rate_limiter import InMemoryRateLimiter
from ....protocol.agent import AgentMessageEnvelope, EnrollmentRequestPayload, ProtocolError, ProtocolValidationPolicy
from .outbox import PendingWorkQueue


class AgentHttpIngress:
    def __init__(self, processor: AgentMessageProcessor, enrollment_service: EnrollmentService,
                 outbox: PendingWorkQueue, *, work_repository=None, policy: Optional[ProtocolValidationPolicy] = None,
                 lease_duration=timedelta(minutes=5), max_attempts=3, retry_delay=timedelta(seconds=0),
                 enrollment_rate_limiter=None, credential_rate_limiter=None):
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
                                    now=datetime.now(timezone.utc))
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
        try:
            endpoint_id = EndpointId(endpoint_header)
            await run_in_threadpool(self.enrollment_service.verify_credential, endpoint_id, secret,
                                    now=datetime.now(timezone.utc))
            endpoint = await run_in_threadpool(self.enrollment_service.get_endpoint, endpoint_id)
            if endpoint is None or endpoint.status is not EndpointStatus.ACTIVE:
                return _error(403, "endpoint_not_active")
        except (EnrollmentError, ValueError):
            return _error(401, "authentication_failed")
        if self.work_repository is not None:
            leased = await run_in_threadpool(self.work_repository.lease_next, endpoint_id,
                                             now=datetime.now(timezone.utc),
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
                                       "lease_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()} if envelope else None})

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
                             credential_rate_limiter=None):
    ingress = AgentHttpIngress(processor, enrollment_service, outbox or PendingWorkQueue(), work_repository=work_repository,
                               policy=policy, lease_duration=lease_duration, max_attempts=max_attempts, retry_delay=retry_delay,
                               enrollment_rate_limiter=enrollment_rate_limiter,
                               credential_rate_limiter=credential_rate_limiter)
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

    return router


def create_agent_http_app(processor: AgentMessageProcessor, enrollment_service: EnrollmentService,
                          outbox: Optional[PendingWorkQueue] = None, *, work_repository=None,
                          policy: Optional[ProtocolValidationPolicy] = None, lease_duration=timedelta(minutes=5),
                          max_attempts=3, retry_delay=timedelta(seconds=0), enrollment_rate_limiter=None,
                          credential_rate_limiter=None):
    app = FastAPI(title="RAVEN-X Agent Transport", docs_url=None, redoc_url=None)
    app.include_router(create_agent_http_router(processor, enrollment_service, outbox, work_repository=work_repository,
                                                policy=policy, lease_duration=lease_duration, max_attempts=max_attempts,
                                                retry_delay=retry_delay, enrollment_rate_limiter=enrollment_rate_limiter,
                                                credential_rate_limiter=credential_rate_limiter), prefix="/api/v1/agent")
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
    return JSONResponse(status_code=status_code, content={"error": code})


def _enrollment_rejected():
    return JSONResponse(status_code=401, content={"error": "enrollment_rejected"},
                        headers={"Cache-Control": "no-store"})
