from datetime import datetime, timedelta, timezone

import pytest

from backend.application.ports.agent_work_repository import DuplicateAgentWorkError, WorkLeaseError
from backend.domain.agent_work import AgentWorkItem, AgentWorkStatus, WorkId
from backend.domain.endpoint import EndpointId
from backend.infrastructure.persistence.in_memory_agent_work_repository import InMemoryAgentWorkRepository
from backend.protocol.agent import AgentMessageEnvelope, AgentMessageType, AssessmentDispatch, CorrelationId


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


def _item(endpoint=None, *, work_id=None, message_id=None, expires_at=None):
    endpoint = endpoint or EndpointId.new()
    correlation = CorrelationId()
    dispatch = AssessmentDispatch("assessment-1", endpoint, ("windows.firewall",), NOW, deadline=expires_at)
    envelope_kwargs = {"endpoint_id": endpoint, "timestamp": NOW, "correlation_id": correlation}
    if message_id is not None:
        envelope_kwargs["message_id"] = message_id
    envelope = AgentMessageEnvelope(AgentMessageType.ASSESSMENT_DISPATCH, dispatch.to_dict(), **envelope_kwargs)
    return AgentWorkItem(
        work_id or WorkId.new(), endpoint, dispatch.assessment_id, envelope.message_id,
        correlation, envelope.message_type.value, str(envelope.protocol_version), envelope.to_dict(),
        AgentWorkStatus.PENDING, NOW, NOW, expires_at=expires_at,
    )


def test_work_lifecycle_leases_acknowledges_and_completes_without_exposing_token():
    endpoint = EndpointId.new()
    repository = InMemoryAgentWorkRepository()
    item = _item(endpoint)
    repository.add(item)

    leased = repository.lease_next(endpoint, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3,
                                   retry_delay=timedelta())
    assert leased is not None
    assert leased.item.status is AgentWorkStatus.LEASED
    assert leased.item.attempt_count == 1
    assert leased.lease_token not in repr(leased)
    assert leased.lease_token not in repr(leased.item)

    acknowledged = repository.acknowledge(item.work_id, endpoint, leased.lease_token,
                                          assessment_id=item.assessment_id, correlation_id=item.correlation_id,
                                          now=NOW + timedelta(seconds=1))
    assert acknowledged.status is AgentWorkStatus.ACKNOWLEDGED
    completed = repository.complete(endpoint, item.assessment_id, item.correlation_id,
                                    now=NOW + timedelta(seconds=2))
    assert completed.status is AgentWorkStatus.COMPLETED
    assert repository.lease_next(endpoint, now=NOW + timedelta(seconds=3),
                                 lease_duration=timedelta(minutes=1), max_attempts=3, retry_delay=timedelta()) is None


def test_work_is_endpoint_partitioned_and_duplicate_protocol_messages_are_rejected():
    endpoint_a, endpoint_b = EndpointId.new(), EndpointId.new()
    repository = InMemoryAgentWorkRepository()
    item = _item(endpoint_a)
    repository.add(item)
    assert repository.list_for_endpoint(endpoint_b) == ()
    with pytest.raises(DuplicateAgentWorkError):
        repository.add(_item(endpoint_b, message_id=item.message_id))
    assert repository.lease_next(endpoint_b, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3,
                                 retry_delay=timedelta()) is None


def test_expired_lease_is_retried_before_ack_and_max_attempts_fail_delivery():
    endpoint = EndpointId.new()
    repository = InMemoryAgentWorkRepository()
    item = _item(endpoint)
    repository.add(item)
    first = repository.lease_next(endpoint, now=NOW, lease_duration=timedelta(seconds=1), max_attempts=2,
                                  retry_delay=timedelta())
    assert first is not None
    changed = repository.release_expired_leases(now=NOW + timedelta(seconds=2), max_attempts=2, retry_delay=timedelta())
    assert changed[0].status is AgentWorkStatus.PENDING
    second = repository.lease_next(endpoint, now=NOW + timedelta(seconds=2), lease_duration=timedelta(seconds=1),
                                   max_attempts=2, retry_delay=timedelta())
    assert second is not None and second.item.attempt_count == 2
    changed = repository.release_expired_leases(now=NOW + timedelta(seconds=4), max_attempts=2, retry_delay=timedelta())
    assert changed[0].status is AgentWorkStatus.FAILED


def test_work_expiration_prevents_delivery_and_wrong_lease_or_duplicate_ack_is_rejected():
    endpoint = EndpointId.new()
    repository = InMemoryAgentWorkRepository()
    item = _item(endpoint, expires_at=NOW + timedelta(seconds=1))
    repository.add(item)
    assert repository.lease_next(endpoint, now=NOW + timedelta(seconds=2), lease_duration=timedelta(minutes=1),
                                 max_attempts=3, retry_delay=timedelta()) is None
    assert repository.get(item.work_id).status is AgentWorkStatus.EXPIRED

    item2 = _item(endpoint)
    repository.add(item2)
    leased = repository.lease_next(endpoint, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3,
                                   retry_delay=timedelta())
    with pytest.raises(WorkLeaseError):
        repository.acknowledge(item2.work_id, endpoint, "wrong", assessment_id=item2.assessment_id,
                               correlation_id=item2.correlation_id, now=NOW)
    repository.acknowledge(item2.work_id, endpoint, leased.lease_token, assessment_id=item2.assessment_id,
                           correlation_id=item2.correlation_id, now=NOW)
    with pytest.raises(WorkLeaseError):
        repository.acknowledge(item2.work_id, endpoint, leased.lease_token, assessment_id=item2.assessment_id,
                               correlation_id=item2.correlation_id, now=NOW)
