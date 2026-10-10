"""Outbound-only agent HTTP transport."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID
from typing import Optional, Union

import httpx

from ....application.ports.agent_transport import AgentMessageSender
from ....domain.endpoint import EndpointId
from ....protocol.agent import AgentMessageEnvelope, MessageDirection, message_direction


class HttpTransportError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class LeasedHttpWork:
    envelope: AgentMessageEnvelope
    work_id: str
    lease_token: str
    lease_expires_at: datetime

    def __repr__(self):
        return f"LeasedHttpWork(work_id={self.work_id!r}, lease_token=<redacted>)"


@dataclass(frozen=True)
class HttpTransportConfig:
    base_url: str
    timeout_seconds: float = 10.0
    connect_timeout_seconds: Optional[float] = None
    read_timeout_seconds: Optional[float] = None
    verify: Union[bool, str] = True
    require_https: bool = True
    messages_path: str = "/api/v1/agent/messages"
    work_path: str = "/api/v1/agent/work"
    enroll_path: str = "/api/v1/agent/enroll"

    def __post_init__(self):
        if not self.base_url.strip():
            raise ValueError("base_url is required")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        for value, name in ((self.connect_timeout_seconds, "connect_timeout_seconds"), (self.read_timeout_seconds, "read_timeout_seconds")):
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.require_https and not self.base_url.lower().startswith("https://"):
            raise ValueError("agent transport requires an HTTPS control-plane URL")
        if self.require_https and self.verify is False:
            raise ValueError("TLS certificate verification cannot be disabled")
        parsed = urlsplit(self.base_url)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must be a server origin without credentials or query")
        if parsed.scheme not in ({"https"} if self.require_https else {"http", "https"}):
            raise ValueError("base_url scheme is unsupported")


@dataclass(frozen=True)
class EnrollmentGrant:
    """One-time agent credential returned by the enrollment HTTP boundary."""

    endpoint_id: EndpointId
    credential_id: str
    credential_secret: str = field(repr=False)
    organization_id: str = ""
    protocol_version: str = ""
    status: str = ""
    credential_expires_at: datetime | None = None

    def __repr__(self):
        return (f"EnrollmentGrant(endpoint_id={self.endpoint_id!s}, credential_id={self.credential_id!r}, "
                "credential_secret=<redacted>)")

    @classmethod
    def from_dict(cls, data):
        try:
            endpoint_id = EndpointId(data["endpoint_id"])
            credential_id = str(UUID(data["credential_id"]))
            organization_id = str(UUID(data["organization_id"]))
            secret = data["credential_secret"]
            protocol_version = data["protocol_version"]
            status = data["status"]
            expires = datetime.fromisoformat(data["credential_expires_at"])
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise HttpTransportError("invalid_response", "enrollment response is invalid") from error
        now = datetime.now(timezone.utc)
        if (not isinstance(secret, str) or len(secret) < 32 or
                not isinstance(protocol_version, str) or not protocol_version or
                status != "new" or expires.tzinfo is None or
                not now < expires <= now + timedelta(days=31)):
            raise HttpTransportError("invalid_response", "enrollment response is invalid")
        return cls(endpoint_id, credential_id, secret, organization_id,
                   protocol_version, status, expires.astimezone(timezone.utc))


class HttpAgentEnrollmentClient:
    """Redeem a bootstrap token once; the token is never placed in a body or log."""

    def __init__(self, config: HttpTransportConfig, *, client=None):
        if not config.require_https or config.verify is False:
            raise ValueError("enrollment requires verified HTTPS")
        self.config = config
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(config.timeout_seconds,
                                  connect=config.connect_timeout_seconds or config.timeout_seconds,
                                  read=config.read_timeout_seconds or config.timeout_seconds),
            verify=config.verify, trust_env=False,
        )

    def enroll(self, *, enrollment_id: str, bootstrap_token: str, hostname: str,
               platform_name: str, platform_version: str | None, architecture: str | None,
               agent_version: str, protocol_version: str, request_id: str | None = None,
               nonce: str | None = None) -> EnrollmentGrant:
        try:
            enrollment_id = str(UUID(enrollment_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("enrollment_id must be a UUID") from error
        if (not isinstance(bootstrap_token, str) or not bootstrap_token or
                len(bootstrap_token) > 128 or not bootstrap_token.isascii() or
                any(char.isspace() for char in bootstrap_token)):
            raise ValueError("bootstrap token is required")
        if not hostname.strip() or not platform_name.strip() or not agent_version.strip():
            raise ValueError("machine identity is incomplete")
        payload = {
            "hostname": hostname,
            "platform": {"name": platform_name, "version": platform_version,
                         "architecture": architecture},
            "agent_version": agent_version,
            "protocol_version": protocol_version,
        }
        if request_id is not None:
            payload["request_id"] = request_id
        if nonce is not None:
            payload["nonce"] = nonce
        headers = {"Authorization": f"Bearer {bootstrap_token}",
                   "X-Raven-Enrollment-Id": enrollment_id,
                   "Content-Type": "application/json"}
        url = self.config.base_url.rstrip("/") + self.config.enroll_path
        try:
            response = self._client.request("POST", url, json=payload, headers=headers)
        except httpx.TimeoutException as error:
            raise HttpTransportError("timeout", "enrollment request timed out") from error
        except httpx.RequestError as error:
            raise HttpTransportError("network_error", "enrollment request failed") from error
        if response.status_code != 201:
            # Do not echo a response body, URL, or request headers: each can
            # contain bearer material in misconfigured intermediaries.
            code = "enrollment_rejected" if response.status_code in (401, 403) else "http_error"
            raise HttpTransportError(code, "enrollment was not accepted", status_code=response.status_code)
        try:
            data = response.json()
        except ValueError as error:
            raise HttpTransportError("invalid_response", "enrollment response is invalid") from error
        if not isinstance(data, dict):
            raise HttpTransportError("invalid_response", "enrollment response is invalid")
        return EnrollmentGrant.from_dict(data)

    def close(self):
        if self._owns_client:
            self._client.close()


class HttpAgentTransport(AgentMessageSender):
    """Send protocol envelopes to the control plane over outbound HTTP(S).

    The default client verifies TLS certificates and hostnames. Tests can
    inject an httpx client/ASGI transport without changing production defaults.
    """

    def __init__(self, config: HttpTransportConfig, credential_store, *, client=None, endpoint_id=None):
        self.config = config
        self.credential_store = credential_store
        self.endpoint_id = endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(endpoint_id) if endpoint_id else None
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=config.base_url,
            timeout=httpx.Timeout(
                config.timeout_seconds,
                connect=config.connect_timeout_seconds or config.timeout_seconds,
                read=config.read_timeout_seconds or config.timeout_seconds,
            ),
            verify=config.verify,
            trust_env=False,
        )

    def send(self, envelope: AgentMessageEnvelope) -> None:
        if message_direction(envelope.message_type) is not MessageDirection.AGENT_TO_CONTROL:
            raise HttpTransportError("direction_not_allowed", "agent transport can only submit agent messages")
        response = self._request(
            "POST", self.config.messages_path,
            envelope.to_dict(),
            endpoint_id=envelope.endpoint_id,
        )
        if response.status_code not in (200, 202, 204):
            raise self._response_error(response)

    def poll_once(self, receiver=None) -> Optional[AgentMessageEnvelope]:
        leased = self.poll_work()
        if leased is None:
            return None
        return receiver.receive_leased_work(leased) if receiver is not None else leased.envelope

    def poll_work(self) -> Optional[LeasedHttpWork]:
        endpoint_id = self.endpoint_id
        if endpoint_id is None:
            raise HttpTransportError("missing_endpoint_id", "endpoint identity is required for work polling")
        response = self._request("POST", self.config.work_path, None, endpoint_id=endpoint_id)
        if response.status_code != 200:
            raise self._response_error(response)
        try:
            data = response.json()
            raw_message = data.get("message") if isinstance(data, dict) else None
            if raw_message is None:
                return None
            envelope = AgentMessageEnvelope.from_dict(raw_message)
            if envelope.endpoint_id != endpoint_id:
                raise HttpTransportError("endpoint_mismatch", "work response targets another endpoint")
            if message_direction(envelope.message_type) is not MessageDirection.CONTROL_TO_AGENT:
                raise HttpTransportError("direction_not_allowed", "work response is not a control message")
            metadata = data.get("work") or {}
            if not metadata.get("work_id") or not metadata.get("lease_token") or not metadata.get("lease_expires_at"):
                raise HttpTransportError("invalid_response", "work response omitted lease metadata")
            lease_expires_at = datetime.fromisoformat(metadata["lease_expires_at"])
            if lease_expires_at.tzinfo is None or lease_expires_at <= datetime.now(timezone.utc):
                raise HttpTransportError("invalid_response", "control plane returned an expired lease")
            return LeasedHttpWork(envelope, metadata["work_id"], metadata["lease_token"], lease_expires_at)
        except HttpTransportError:
            raise
        except Exception as error:
            raise HttpTransportError("invalid_response", "control plane returned an invalid work response") from error

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _request(self, method, path, payload, *, endpoint_id):
        credential = self.credential_store.load()
        if credential is None:
            raise HttpTransportError("missing_credential", "agent credential is unavailable")
        headers = {
            "Authorization": f"Bearer {credential.secret}",
            "Content-Type": "application/json",
            "X-Raven-Endpoint-Id": str(endpoint_id),
        }
        try:
            url = self.config.base_url.rstrip("/") + "/" + path.lstrip("/")
            return self._client.request(method, url, json=payload, headers=headers)
        except httpx.TimeoutException as error:
            raise HttpTransportError("timeout", "control-plane request timed out") from error
        except httpx.RequestError as error:
            raise HttpTransportError("network_error", "control-plane request failed") from error

    @staticmethod
    def _response_error(response) -> HttpTransportError:
        if response.status_code == 401:
            return HttpTransportError("authentication_failed", "control-plane authentication failed", status_code=401)
        if response.status_code == 403:
            return HttpTransportError("approval_required", "endpoint is not approved for this operation", status_code=403)
        if response.status_code == 413:
            return HttpTransportError("payload_too_large", "request was rejected as too large", status_code=413)
        return HttpTransportError("http_error", "control-plane rejected the request", status_code=response.status_code)
