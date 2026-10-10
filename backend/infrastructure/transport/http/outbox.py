"""Small in-memory work outbox for the first outbound-only transport."""

from collections import deque
from threading import RLock
from typing import Optional, Tuple

from ....domain.endpoint import EndpointId
from ....protocol.agent import AgentMessageEnvelope, AgentMessageType, MessageDirection, message_direction


class PendingWorkQueue:
    """FIFO queue partitioned by endpoint identity.

    Leasing removes work from the pending queue but retains it in-memory as
    in-flight. This deliberately does not claim durable delivery or retries.
    """

    def __init__(self):
        self._pending = {}
        self._leased = {}
        self._message_ids = set()
        self._lock = RLock()

    def enqueue(self, envelope: AgentMessageEnvelope) -> None:
        if envelope.endpoint_id is None:
            raise ValueError("work envelope requires endpoint_id")
        if envelope.message_type is not AgentMessageType.ASSESSMENT_DISPATCH or message_direction(envelope.message_type) is not MessageDirection.CONTROL_TO_AGENT:
            raise ValueError("HTTP work outbox accepts assessment.dispatch messages only")
        with self._lock:
            key = (envelope.endpoint_id, str(envelope.message_id))
            if key in self._message_ids:
                raise ValueError("work message is already queued or leased")
            self._message_ids.add(key)
            queue = self._pending.setdefault(envelope.endpoint_id, deque())
            queue.append(envelope)

    def lease(self, endpoint_id: EndpointId) -> Optional[AgentMessageEnvelope]:
        endpoint_id = _endpoint(endpoint_id)
        with self._lock:
            queue = self._pending.get(endpoint_id)
            if not queue:
                return None
            envelope = queue.popleft()
            self._leased[(endpoint_id, str(envelope.message_id))] = envelope
            if not queue:
                self._pending.pop(endpoint_id, None)
            return envelope

    def pending(self, endpoint_id: EndpointId) -> Tuple[AgentMessageEnvelope, ...]:
        endpoint_id = _endpoint(endpoint_id)
        with self._lock:
            return tuple(self._pending.get(endpoint_id, ()))

    def leased(self, endpoint_id: EndpointId) -> Tuple[AgentMessageEnvelope, ...]:
        endpoint_id = _endpoint(endpoint_id)
        with self._lock:
            return tuple(
                envelope for (owner, _), envelope in self._leased.items() if owner == endpoint_id
            )

    def acknowledge(self, endpoint_id: EndpointId, message_id) -> bool:
        key = (_endpoint(endpoint_id), str(message_id))
        with self._lock:
            return self._leased.pop(key, None) is not None


class HttpControlPlaneTransport:
    """Dispatcher-facing transport that queues control-to-agent envelopes."""

    def __init__(self, outbox: Optional[PendingWorkQueue] = None):
        self.outbox = outbox or PendingWorkQueue()

    def send_control_to_agent(self, envelope: AgentMessageEnvelope) -> None:
        self.outbox.enqueue(envelope)


def _endpoint(value) -> EndpointId:
    return value if isinstance(value, EndpointId) else EndpointId(value)
