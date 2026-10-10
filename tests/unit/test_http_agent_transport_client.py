from datetime import datetime, timezone

import httpx
import pytest

from backend.agent.runtime import AgentCredential, InMemoryAgentCredentialStore
from backend.domain.endpoint import EndpointId
from backend.infrastructure.transport.http import HttpAgentTransport, HttpTransportError, HttpTransportConfig, PendingWorkQueue
from backend.protocol.agent import AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, ProtocolVersion


def _credential():
    return InMemoryAgentCredentialStore(AgentCredential("00000000-0000-0000-0000-000000000001", "secret-value"))


def _heartbeat(endpoint_id):
    now = datetime.now(timezone.utc)
    payload = AgentHeartbeat(endpoint_id, "1.0.0", ProtocolVersion.current(), now)
    return AgentMessageEnvelope(AgentMessageType.HEARTBEAT, payload.to_dict(), endpoint_id=endpoint_id, timestamp=now)


def test_http_client_presents_bearer_secret_without_putting_it_in_payload():
    captured = {}

    def handler(request):
        captured["request"] = request
        return httpx.Response(200, json={"accepted": True})

    endpoint = EndpointId.new()
    transport = HttpAgentTransport(HttpTransportConfig("https://control.example"), _credential(), client=httpx.Client(transport=httpx.MockTransport(handler)))
    envelope = _heartbeat(endpoint)
    transport.send(envelope)
    request = captured["request"]
    assert request.headers["authorization"] == "Bearer secret-value"
    assert "secret-value" not in request.content.decode()
    assert "secret-value" not in envelope.to_dict().__repr__()


def test_http_transport_requires_https_by_default():
    with pytest.raises(ValueError):
        HttpTransportConfig("http://control.example")
    assert HttpTransportConfig("http://local-test", require_https=False).verify is True
    with pytest.raises(ValueError):
        HttpTransportConfig("https://control.example", verify=False)


def test_http_client_maps_timeout_and_network_failures_without_leaking_secret():
    def timeout(_):
        raise httpx.ReadTimeout("timed out")

    transport = HttpAgentTransport(HttpTransportConfig("https://control.example"), _credential(), client=httpx.Client(transport=httpx.MockTransport(timeout)))
    with pytest.raises(HttpTransportError) as error:
        transport.send(_heartbeat(EndpointId.new()))
    assert error.value.code == "timeout"
    assert "secret-value" not in str(error.value)

    def network(_):
        raise httpx.ConnectError("unreachable")

    network_transport = HttpAgentTransport(HttpTransportConfig("https://control.example"), _credential(), client=httpx.Client(transport=httpx.MockTransport(network)))
    with pytest.raises(HttpTransportError) as network_error:
        network_transport.send(_heartbeat(EndpointId.new()))
    assert network_error.value.code == "network_error"


def test_poll_once_supports_no_work_and_rejects_invalid_responses():
    endpoint = EndpointId.new()
    no_work = HttpAgentTransport(
        HttpTransportConfig("https://control.example"), _credential(), endpoint_id=endpoint,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"message": None}))),
    )
    assert no_work.poll_once() is None

    invalid = HttpAgentTransport(
        HttpTransportConfig("https://control.example"), _credential(), endpoint_id=endpoint,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"message": {"bad": True}}))),
    )
    with pytest.raises(HttpTransportError) as error:
        invalid.poll_once()
    assert error.value.code == "invalid_response"


def test_work_queue_is_endpoint_isolated_and_leases_messages():
    queue = PendingWorkQueue()
    first, second = EndpointId.new(), EndpointId.new()
    for endpoint in (first, second):
        queue.enqueue(AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, {"assessment_id": "a", "endpoint_id": str(endpoint), "scanner_ids": ["windows.firewall"], "requested_at": datetime.now(timezone.utc).isoformat()}, endpoint_id=endpoint, timestamp=datetime.now(timezone.utc)))
    assert queue.lease(first).endpoint_id == first
    assert queue.lease(first) is None
    assert queue.lease(second).endpoint_id == second

    with pytest.raises(ValueError):
        queue.enqueue(queue.leased(first)[0])

    with pytest.raises(ValueError):
        queue.enqueue(_heartbeat(first))
