from datetime import datetime, timezone

import pytest

from backend.agent.outbox import DurableResultSender
from backend.infrastructure.transport.http.client import HttpTransportError
from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType, CorrelationId
from backend.domain.endpoint import EndpointId


class FakeFiles:
    def verify_directory(self, path):
        assert path.is_dir()

    def verify_protected_file(self, path):
        assert path.is_file()

    def atomic_write_protected(self, path, data):
        path.write_bytes(data)


class FakeProtector:
    def protect(self, raw):
        return b"protected:" + raw

    def unprotect(self, raw):
        assert raw.startswith(b"protected:")
        return raw[len(b"protected:"):]


class FlakyTransport:
    def __init__(self):
        self.sent = []
        self.fail = True

    def send(self, envelope):
        if self.fail:
            raise HttpTransportError("network_error", "offline")
        self.sent.append(envelope)


def test_result_is_durable_before_network_and_retried(tmp_path):
    transport = FlakyTransport()
    sender = DurableResultSender(transport, tmp_path, protector=FakeProtector(), files=FakeFiles())
    message = AgentMessageEnvelope(
        AgentMessageType.ASSESSMENT_RESULT, {}, endpoint_id=EndpointId.new(),
        timestamp=datetime.now(timezone.utc), correlation_id=CorrelationId(),
    )
    with pytest.raises(HttpTransportError):
        sender.send(message)
    pending = list(tmp_path.glob("*.msg"))
    assert len(pending) == 1
    assert pending[0].read_bytes().startswith(b"protected:")
    transport.fail = False
    sender.flush()
    assert transport.sent[0].message_id == message.message_id
    assert list(tmp_path.glob("*.msg")) == []


def test_non_result_progress_failure_is_transient(tmp_path):
    transport = FlakyTransport()
    sender = DurableResultSender(transport, tmp_path, protector=FakeProtector(), files=FakeFiles())
    progress = AgentMessageEnvelope(
        AgentMessageType.ASSESSMENT_PROGRESS, {}, endpoint_id=EndpointId.new(),
        timestamp=datetime.now(timezone.utc), correlation_id=CorrelationId(),
    )
    sender.send(progress)
    assert list(tmp_path.glob("*.msg")) == []
