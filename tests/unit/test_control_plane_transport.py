from datetime import datetime, timezone

from backend.application.control_plane.transport import InProcessDuplexTransport
from backend.domain.endpoint import EndpointId
from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType


class FakeAgent:
    def __init__(self, endpoint_id):
        self.endpoint_id = endpoint_id
        self.received = []

    def receive(self, envelope):
        self.received.append(envelope)


def test_duplex_transport_routes_control_messages_by_endpoint_identity():
    transport = InProcessDuplexTransport(object())
    first = FakeAgent(EndpointId.new())
    second = FakeAgent(EndpointId.new())
    transport.attach_agent(first)
    transport.attach_agent(second)

    for agent in (first, second):
        envelope = AgentMessageEnvelope(
            AgentMessageType.ASSESSMENT_DISPATCH,
            {"assessment_id": "a", "endpoint_id": str(agent.endpoint_id), "scanner_ids": ["windows.firewall"], "requested_at": "2026-08-23T10:00:00+00:00"},
            endpoint_id=agent.endpoint_id,
            timestamp=datetime.now(timezone.utc),
        )
        transport.send_control_to_agent(envelope)

    assert first.received[0].endpoint_id == first.endpoint_id
    assert second.received[0].endpoint_id == second.endpoint_id
