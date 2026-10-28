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


def test_http_client_renew_credential_and_confirm_validate_lineage_and_redact_secret():
    from datetime import timedelta
    from uuid import uuid4

    from backend.infrastructure.transport.http.client import RenewalReceipt

    endpoint = EndpointId.new()
    old_id = "00000000-0000-0000-0000-000000000001"
    new_id = str(uuid4())
    successor_secret = "s" * 48
    org_id = str(uuid4())
    now = datetime.now(timezone.utc)
    captured = []

    def handler(request):
        captured.append(request)
        if request.url.path.endswith("/renew"):
            body = request.read()
            assert successor_secret.encode() in body
            assert b"credential_secret" not in body or successor_secret.encode() in body
            return httpx.Response(200, json={
                "endpoint_id": str(endpoint),
                "organization_id": org_id,
                "credential_id": new_id,
                "credential_expires_at": (now + timedelta(days=30)).isoformat(),
                "replaces_credential_id": old_id,
                "predecessor_valid_until": (now + timedelta(minutes=15)).isoformat(),
                "protocol_version": "1.0",
                "status": "active",
            })
        return httpx.Response(200, json={
            "confirmed": True,
            "endpoint_id": str(endpoint),
            "organization_id": org_id,
            "credential_id": new_id,
            "credential_expires_at": (now + timedelta(days=30)).isoformat(),
            "replaces_credential_id": old_id,
        })

    store = _credential()
    transport = HttpAgentTransport(
        HttpTransportConfig("https://control.example"),
        store,
        endpoint_id=endpoint,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    predecessor = AgentCredential(old_id, "secret-value")
    receipt = transport.renew_credential(
        credential=predecessor,
        successor_credential_id=new_id,
        successor_credential_secret=successor_secret,
        timestamp=now,
    )
    assert isinstance(receipt, RenewalReceipt)
    assert receipt.credential_id == new_id
    assert receipt.replaces_credential_id == old_id
    assert successor_secret not in repr(receipt)
    assert not hasattr(receipt, "credential_secret")
    successor = AgentCredential(new_id, successor_secret)
    transport.confirm_renewal(credential=successor, replaces_credential_id=old_id, timestamp=now)
    assert captured[0].headers["authorization"] == "Bearer secret-value"
    assert captured[1].headers["authorization"] == f"Bearer {successor_secret}"
