from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event
from types import SimpleNamespace

import pytest

from backend.application.control_plane import (
    CancellationOutcome, RemoteAssessmentCancellationService, RemoteAssessmentReconciler,
    AgentSessionRegistry, ControlPlaneAgentHandlers, RemoteAssessmentDispatcher,
    RemoteAssessment, RemoteAssessmentRegistry, RemoteAssessmentState,
)
from backend.application.ports.agent_work_repository import WorkLeaseError
from backend.application.ports.remote_assessment_repository import RemoteAssessmentConflictError
from backend.core.database.database import DatabaseManager
from backend.domain.agent_work import AgentWorkStatus
from backend.domain.assessment import AssessmentStatus
from backend.domain.endpoint import EndpointId
from backend.domain.endpoint import Endpoint, EndpointStatus, PlatformInfo
from backend.application.endpoint.registry import EndpointRegistry
from backend.infrastructure.transport.http import HttpControlPlaneTransport
from backend.infrastructure.persistence.in_memory_agent_work_repository import InMemoryAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from backend.protocol.agent import AssessmentAcknowledgment, AssessmentProgress, AssessmentResultPayload
from backend.application.control_plane.assessment_dispatch import DuplicateTerminalResultError
from tests.unit.test_agent_work_repository import _item


NOW = datetime(2026, 8, 23, 14, 0, tzinfo=timezone.utc)


class _Endpoints:
    def __init__(self, endpoint): self.endpoint = endpoint
    def exists(self, endpoint_id): return str(endpoint_id) == str(self.endpoint.endpoint_id)
    def get(self, endpoint_id): return self.endpoint if str(endpoint_id) == str(self.endpoint.endpoint_id) else None
    def add(self, endpoint): self.endpoint = endpoint


def _manager(tmp_path):
    config = tmp_path / "remote_assessments.yaml"
    database = tmp_path / "remote_assessments.db"
    config.write_text("database:\n  type: sqlite\n  sqlite_path: '" + database.as_posix() + "'\n", encoding="utf-8")
    manager = DatabaseManager(str(config))
    manager.initialize_sync_engine(); manager.create_tables()
    return manager, config


def _assessment(item, state=RemoteAssessmentState.QUEUED):
    return RemoteAssessment(item.assessment_id, item.endpoint_id, item.correlation_id, ("windows.firewall",),
                             NOW, state, queued_at=NOW, expires_at=NOW + timedelta(minutes=10))


def test_remote_assessment_and_work_max_attempt_failure_survive_restart(tmp_path):
    manager, config = _manager(tmp_path)
    work = _item()
    assessments = SQLAlchemyRemoteAssessmentRepository(manager)
    work_repository = SQLAlchemyAgentWorkRepository(manager)
    assessments.add(_assessment(work)); work_repository.add(work)

    work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(seconds=1), max_attempts=2, retry_delay=timedelta())
    work_repository.release_expired_leases(now=NOW + timedelta(seconds=2), max_attempts=2, retry_delay=timedelta())
    work_repository.lease_next(work.endpoint_id, now=NOW + timedelta(seconds=2), lease_duration=timedelta(seconds=1), max_attempts=2, retry_delay=timedelta())
    work_repository.release_expired_leases(now=NOW + timedelta(seconds=4), max_attempts=2, retry_delay=timedelta())
    assert work_repository.get(work.work_id).status is AgentWorkStatus.FAILED

    reconciler = RemoteAssessmentReconciler(assessments, work_repository)
    result = reconciler.reconcile(work.assessment_id, now=NOW + timedelta(seconds=5))
    assert result.state is RemoteAssessmentState.DELIVERY_FAILED
    assert assessments.get(work.assessment_id).failure_code == "WORK_MAX_ATTEMPTS"
    manager.close()

    reloaded = DatabaseManager(str(config)); reloaded.initialize_sync_engine()
    restored = SQLAlchemyRemoteAssessmentRepository(reloaded).get(work.assessment_id)
    assert restored.state is RemoteAssessmentState.DELIVERY_FAILED
    assert restored.assessment_id == work.assessment_id
    assert restored.correlation_id == work.correlation_id
    reloaded.close()


def test_remote_assessment_progress_and_structured_result_round_trip(tmp_path):
    manager, config = _manager(tmp_path)
    work = _item(); repository = SQLAlchemyRemoteAssessmentRepository(manager)
    assessment = _assessment(work)
    repository.add(assessment)
    progress = AssessmentProgress(work.assessment_id, "running", ("windows.firewall",), 1, None, NOW, work.correlation_id)
    running = replace(assessment, state=RemoteAssessmentState.RUNNING, progress=progress, started_at=NOW)
    repository.update(running)
    result = AssessmentResultPayload(work.assessment_id, str(work.endpoint_id), AssessmentStatus.COMPLETED, NOW, NOW, (), (), None)
    repository.update(replace(running, state=RemoteAssessmentState.COMPLETED, result=result, completed_at=NOW))
    manager.close()
    reloaded = DatabaseManager(str(config)); reloaded.initialize_sync_engine()
    restored = SQLAlchemyRemoteAssessmentRepository(reloaded).get(work.assessment_id)
    assert restored.state is RemoteAssessmentState.COMPLETED
    assert restored.progress.completed_scanners == ("windows.firewall",)
    assert restored.result.status is AssessmentStatus.COMPLETED
    reloaded.close()


def test_reconciliation_is_idempotent_for_pending_leased_acknowledged_and_retryable_work():
    work = _item(); work_repository = InMemoryAgentWorkRepository(); assessments = RemoteAssessmentRegistry()
    assessments.add(_assessment(work)); work_repository.add(work)
    reconciler = RemoteAssessmentReconciler(assessments, work_repository)
    first = reconciler.reconcile(work.assessment_id, now=NOW)
    second = reconciler.reconcile(work.assessment_id, now=NOW)
    assert first.state is RemoteAssessmentState.QUEUED
    assert second.changed is False
    leased = work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3, retry_delay=timedelta())
    leased_result = reconciler.reconcile(work.assessment_id, now=NOW)
    assert leased_result.state is RemoteAssessmentState.DISPATCHED
    work_repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token,
                                assessment_id=work.assessment_id, correlation_id=work.correlation_id, now=NOW)
    ack_result = reconciler.reconcile(work.assessment_id, now=NOW)
    assert ack_result.state is RemoteAssessmentState.RUNNING
    assert reconciler.reconcile(work.assessment_id, now=NOW).changed is False


def test_execution_timeout_fails_work_and_rejects_late_clean_result():
    work = _item()
    work_repository = InMemoryAgentWorkRepository()
    assessments = RemoteAssessmentRegistry()
    initial = _assessment(work)
    assessments.add(initial)
    work_repository.add(work)
    leased = work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1),
                                        max_attempts=3, retry_delay=timedelta())
    work_repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token,
                                assessment_id=work.assessment_id, correlation_id=work.correlation_id, now=NOW)
    assessments.update(replace(initial, state=RemoteAssessmentState.RUNNING, started_at=NOW, acknowledged_at=NOW))
    reconciler = RemoteAssessmentReconciler(assessments, work_repository, execution_timeout=timedelta(seconds=5))

    timeout = reconciler.reconcile(work.assessment_id, now=NOW + timedelta(seconds=6))
    assert timeout.state is RemoteAssessmentState.FAILED
    assert timeout.execution_timeout_detected is True
    assert assessments.get(work.assessment_id).failure_code == "EXECUTION_TIMEOUT"
    assert assessments.get(work.assessment_id).execution_timeout_detected_at == NOW + timedelta(seconds=6)
    assert work_repository.get(work.work_id).status is AgentWorkStatus.FAILED
    assert reconciler.reconcile(work.assessment_id, now=NOW + timedelta(seconds=7)).changed is False

    late_result = AssessmentResultPayload(work.assessment_id, str(work.endpoint_id), AssessmentStatus.COMPLETED,
                                          NOW, NOW + timedelta(seconds=7), (), (), None)
    handlers = ControlPlaneAgentHandlers(AgentSessionRegistry(), assessments, work_repository)
    with pytest.raises(DuplicateTerminalResultError):
        handlers.result(SimpleNamespace(endpoint_id=work.endpoint_id), late_result,
                        SimpleNamespace(correlation_id=work.correlation_id))
    assert assessments.get(work.assessment_id).state is RemoteAssessmentState.FAILED
    assert assessments.get(work.assessment_id).result is None
    assert work_repository.get(work.work_id).status is AgentWorkStatus.FAILED


def test_execution_timeout_invalidates_unacknowledged_lease_without_redelivery():
    work = _item()
    work_repository = InMemoryAgentWorkRepository()
    assessments = RemoteAssessmentRegistry()
    initial = _assessment(work)
    assessments.add(initial)
    work_repository.add(work)
    leased = work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(seconds=1),
                                        max_attempts=3, retry_delay=timedelta())
    assessments.update(replace(initial, state=RemoteAssessmentState.RUNNING, started_at=NOW))
    timeout = RemoteAssessmentReconciler(assessments, work_repository,
                                         execution_timeout=timedelta(seconds=5)).reconcile(
                                             work.assessment_id, now=NOW + timedelta(seconds=6))
    assert timeout.state is RemoteAssessmentState.FAILED
    assert work_repository.get(work.work_id).status is AgentWorkStatus.CANCELLED
    assert work_repository.lease_next(work.endpoint_id, now=NOW + timedelta(seconds=7),
                                      lease_duration=timedelta(seconds=1), max_attempts=3,
                                      retry_delay=timedelta()) is None
    with pytest.raises(WorkLeaseError):
        work_repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token,
                                    assessment_id=work.assessment_id, correlation_id=work.correlation_id,
                                    now=NOW + timedelta(seconds=7))


def test_running_assessment_without_work_still_times_out():
    work = _item()
    assessments = RemoteAssessmentRegistry()
    assessments.add(replace(_assessment(work), state=RemoteAssessmentState.RUNNING,
                            started_at=NOW, acknowledged_at=NOW))
    result = RemoteAssessmentReconciler(assessments, InMemoryAgentWorkRepository(),
                                        execution_timeout=timedelta(seconds=5)).reconcile(
                                            work.assessment_id, now=NOW + timedelta(seconds=6))
    assert result.state is RemoteAssessmentState.FAILED
    assert assessments.get(work.assessment_id).failure_code == "EXECUTION_TIMEOUT"


def test_execution_timeout_and_failed_work_survive_sql_restart(tmp_path):
    manager, config = _manager(tmp_path)
    work = _item()
    assessments = SQLAlchemyRemoteAssessmentRepository(manager)
    work_repository = SQLAlchemyAgentWorkRepository(manager)
    initial = _assessment(work)
    assessments.add(initial)
    work_repository.add(work)
    leased = work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1),
                                        max_attempts=3, retry_delay=timedelta())
    work_repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token,
                                assessment_id=work.assessment_id, correlation_id=work.correlation_id, now=NOW)
    assessments.update(replace(initial, state=RemoteAssessmentState.RUNNING, started_at=NOW, acknowledged_at=NOW))
    result = RemoteAssessmentReconciler(assessments, work_repository,
                                        execution_timeout=timedelta(seconds=5)).reconcile(
                                            work.assessment_id, now=NOW + timedelta(seconds=6))
    assert result.state is RemoteAssessmentState.FAILED
    manager.close()
    reloaded = DatabaseManager(str(config))
    reloaded.initialize_sync_engine()
    assert SQLAlchemyRemoteAssessmentRepository(reloaded).get(work.assessment_id).failure_code == "EXECUTION_TIMEOUT"
    assert SQLAlchemyAgentWorkRepository(reloaded).get(work.work_id).status is AgentWorkStatus.FAILED
    reloaded.close()


def test_expired_work_reconciles_to_expired_but_retryable_lease_does_not_terminally_fail():
    work = _item(expires_at=NOW + timedelta(seconds=1)); work_repository = InMemoryAgentWorkRepository(); assessments = RemoteAssessmentRegistry()
    assessments.add(_assessment(work)); work_repository.add(work)
    assert work_repository.lease_next(work.endpoint_id, now=NOW + timedelta(seconds=2), lease_duration=timedelta(minutes=1), max_attempts=3, retry_delay=timedelta()) is None
    result = RemoteAssessmentReconciler(assessments, work_repository).reconcile(work.assessment_id, now=NOW + timedelta(seconds=2))
    assert result.state is RemoteAssessmentState.EXPIRED


def test_cancellation_before_ack_cancels_work_and_rejects_stale_ack():
    work = _item(); work_repository = InMemoryAgentWorkRepository(); assessments = RemoteAssessmentRegistry()
    assessments.add(_assessment(work)); work_repository.add(work)
    service = RemoteAssessmentCancellationService(assessments, work_repository)
    outcome = service.cancel(work.assessment_id, endpoint_id=work.endpoint_id, now=NOW)
    assert outcome.outcome is CancellationOutcome.CANCELLED
    assert assessments.get(work.assessment_id).state is RemoteAssessmentState.CANCELLED
    assert work_repository.get(work.work_id).status is AgentWorkStatus.CANCELLED
    assert work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3, retry_delay=timedelta()) is None
    with pytest.raises(WorkLeaseError):
        work_repository.acknowledge(work.work_id, work.endpoint_id, "stale", assessment_id=work.assessment_id,
                                     correlation_id=work.correlation_id, now=NOW)


def test_leased_pre_ack_cancellation_invalidates_lease_and_wrong_endpoint_cannot_cancel():
    work = _item(); work_repository = InMemoryAgentWorkRepository(); assessments = RemoteAssessmentRegistry()
    assessments.add(_assessment(work)); work_repository.add(work)
    leased = work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3, retry_delay=timedelta())
    service = RemoteAssessmentCancellationService(assessments, work_repository)
    assert service.cancel(work.assessment_id, endpoint_id=EndpointId.new(), now=NOW).outcome is CancellationOutcome.NOT_FOUND
    assert service.cancel(work.assessment_id, now=NOW).outcome is CancellationOutcome.CANCELLED
    with pytest.raises(WorkLeaseError):
        work_repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token, assessment_id=work.assessment_id,
                                     correlation_id=work.correlation_id, now=NOW)


def test_acknowledged_cancellation_is_only_a_request_and_terminal_results_remain_valid():
    work = _item(); work_repository = InMemoryAgentWorkRepository(); assessments = RemoteAssessmentRegistry()
    assessment = _assessment(work); assessments.add(assessment); work_repository.add(work)
    leased = work_repository.lease_next(work.endpoint_id, now=NOW, lease_duration=timedelta(minutes=1), max_attempts=3, retry_delay=timedelta())
    work_repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token,
                                assessment_id=work.assessment_id, correlation_id=work.correlation_id, now=NOW)
    assessments.update(replace(assessment, state=RemoteAssessmentState.RUNNING, acknowledged_at=NOW, started_at=NOW))
    service = RemoteAssessmentCancellationService(assessments, work_repository)
    assert service.cancel(work.assessment_id, now=NOW).outcome is CancellationOutcome.CANCEL_REQUESTED
    assert assessments.get(work.assessment_id).state is RemoteAssessmentState.CANCEL_REQUESTED
    assert service.cancel(work.assessment_id, now=NOW).outcome is CancellationOutcome.CANCEL_REQUESTED


def test_terminal_cancellation_is_idempotent_and_does_not_mutate_history():
    work = _item(); assessments = RemoteAssessmentRegistry(); work_repository = InMemoryAgentWorkRepository()
    assessments.add(_assessment(work, RemoteAssessmentState.COMPLETED));
    result = RemoteAssessmentCancellationService(assessments, work_repository).cancel(work.assessment_id, now=NOW)
    assert result.outcome is CancellationOutcome.ALREADY_TERMINAL
    assert assessments.get(work.assessment_id).state is RemoteAssessmentState.COMPLETED


def test_durable_dispatch_queues_registered_offline_endpoint_without_session():
    endpoint = Endpoint(EndpointId.new(), "offline-host", PlatformInfo("Windows"),
                        status=EndpointStatus.ACTIVE, created_at=NOW)
    endpoint_registry = EndpointRegistry(_Endpoints(endpoint))
    assessments = RemoteAssessmentRegistry(); work_repository = InMemoryAgentWorkRepository()
    dispatcher = RemoteAssessmentDispatcher(endpoint_registry, AgentSessionRegistry(), HttpControlPlaneTransport(), assessments,
                                             work_repository=work_repository, work_ttl=timedelta(minutes=5))
    assessment = dispatcher.dispatch(endpoint.endpoint_id, ("windows.firewall",), requested_at=NOW)
    assert assessment.state is RemoteAssessmentState.QUEUED
    assert work_repository.list_for_endpoint(endpoint.endpoint_id)[0].status is AgentWorkStatus.PENDING


def test_concurrent_sql_terminal_assessment_update_preserves_first_terminal_state(tmp_path, monkeypatch):
    import backend.infrastructure.persistence.sqlalchemy_remote_assessment_repository as module

    manager, _ = _manager(tmp_path)
    work = _item()
    repository = SQLAlchemyRemoteAssessmentRepository(manager)
    original = _assessment(work)
    repository.add(original)
    completed = replace(original, state=RemoteAssessmentState.COMPLETED, completed_at=NOW)
    timed_out = replace(original, state=RemoteAssessmentState.FAILED, failed_at=NOW,
                        failure_code="EXECUTION_TIMEOUT")
    first_writing, release_first = Event(), Event()
    original_copy = module._copy

    def pause_first_write(record, assessment):
        if assessment.state is RemoteAssessmentState.COMPLETED:
            first_writing.set()
            assert release_first.wait(5)
        return original_copy(record, assessment)

    monkeypatch.setattr(module, "_copy", pause_first_write)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            winner = pool.submit(repository.update, completed)
            assert first_writing.wait(5)
            loser = pool.submit(repository.update, timed_out)
            release_first.set()
            assert winner.result(timeout=10).state is RemoteAssessmentState.COMPLETED
            with pytest.raises(RemoteAssessmentConflictError):
                loser.result(timeout=10)
        assert repository.get(work.assessment_id).state is RemoteAssessmentState.COMPLETED
    finally:
        release_first.set()
        manager.close()


def test_concurrent_sql_ack_blocks_cancel_and_expiry_redelivery(tmp_path, monkeypatch):
    import backend.infrastructure.persistence.sqlalchemy_agent_work_repository as module

    manager, _ = _manager(tmp_path)
    work = _item()
    repository = SQLAlchemyAgentWorkRepository(manager)
    repository.add(work)
    leased = repository.lease_next(work.endpoint_id, now=NOW,
                                   lease_duration=timedelta(seconds=1), max_attempts=3,
                                   retry_delay=timedelta())
    validated, release_ack = Event(), Event()
    original_check = module._active_lease

    def pause_after_validation(*args):
        valid = original_check(*args)
        if valid:
            validated.set()
            assert release_ack.wait(5)
        return valid

    monkeypatch.setattr(module, "_active_lease", pause_after_validation)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            ack = pool.submit(repository.acknowledge, work.work_id, work.endpoint_id,
                              leased.lease_token, assessment_id=work.assessment_id,
                              correlation_id=work.correlation_id, now=NOW)
            assert validated.wait(5)
            cancel = pool.submit(repository.cancel, work.work_id, work.endpoint_id, now=NOW)
            release_ack.set()
            assert ack.result(timeout=10).status is AgentWorkStatus.ACKNOWLEDGED
            with pytest.raises(WorkLeaseError):
                cancel.result(timeout=10)
        assert repository.release_expired_leases(now=NOW + timedelta(seconds=2), max_attempts=3,
                                                 retry_delay=timedelta()) == ()
        assert repository.get(work.work_id).status is AgentWorkStatus.ACKNOWLEDGED
        assert repository.lease_next(work.endpoint_id, now=NOW + timedelta(seconds=2),
                                     lease_duration=timedelta(seconds=1), max_attempts=3,
                                     retry_delay=timedelta()) is None
    finally:
        release_ack.set()
        manager.close()


def test_sql_requeued_work_rejects_stale_progress_result_and_backdated_ack(tmp_path):
    manager, _ = _manager(tmp_path)
    work = _item()
    assessments = SQLAlchemyRemoteAssessmentRepository(manager)
    repository = SQLAlchemyAgentWorkRepository(manager)
    assessments.add(_assessment(work))
    repository.add(work)
    first = repository.lease_next(work.endpoint_id, now=NOW,
                                  lease_duration=timedelta(seconds=1), max_attempts=3,
                                  retry_delay=timedelta())
    handlers = ControlPlaneAgentHandlers(AgentSessionRegistry(), assessments, repository)
    old_ack = AssessmentAcknowledgment(work.assessment_id, str(work.work_id), first.lease_token, NOW)
    with pytest.raises(WorkLeaseError):
        handlers.acknowledge(SimpleNamespace(endpoint_id=work.endpoint_id), old_ack,
                             SimpleNamespace(correlation_id=work.correlation_id))
    repository.release_expired_leases(now=NOW + timedelta(seconds=2), max_attempts=3,
                                      retry_delay=timedelta())
    assert repository.get(work.work_id).status is AgentWorkStatus.PENDING
    with pytest.raises(WorkLeaseError):
        repository.mark_progress(work.endpoint_id, work.assessment_id, work.correlation_id,
                                 now=NOW + timedelta(seconds=2))
    with pytest.raises(WorkLeaseError):
        repository.complete(work.endpoint_id, work.assessment_id, work.correlation_id,
                            now=NOW + timedelta(seconds=2))
    assert assessments.get(work.assessment_id).state is RemoteAssessmentState.QUEUED
    manager.close()


def test_sql_ack_uses_server_receipt_clock_not_agent_future_timestamp(tmp_path):
    manager, _ = _manager(tmp_path)
    work = _item()
    assessments = SQLAlchemyRemoteAssessmentRepository(manager)
    repository = SQLAlchemyAgentWorkRepository(manager)
    assessments.add(_assessment(work))
    repository.add(work)
    before_receipt = datetime.now(timezone.utc)
    leased = repository.lease_next(work.endpoint_id, now=before_receipt,
                                   lease_duration=timedelta(minutes=1), max_attempts=3,
                                   retry_delay=timedelta())
    handlers = ControlPlaneAgentHandlers(AgentSessionRegistry(), assessments, repository)
    claimed_future = before_receipt + timedelta(days=365)
    handlers.acknowledge(SimpleNamespace(endpoint_id=work.endpoint_id),
                         AssessmentAcknowledgment(work.assessment_id, str(work.work_id),
                                                  leased.lease_token, claimed_future),
                         SimpleNamespace(correlation_id=work.correlation_id))
    after_receipt = datetime.now(timezone.utc)
    persisted = assessments.get(work.assessment_id)
    assert before_receipt <= persisted.started_at <= after_receipt
    assert before_receipt <= repository.get(work.work_id).acknowledged_at <= after_receipt
    manager.close()


def test_sql_result_and_timeout_commit_consistent_terminal_pair(tmp_path, monkeypatch):
    import backend.infrastructure.persistence.sqlalchemy_agent_work_repository as module

    manager, _ = _manager(tmp_path)
    work = _item()
    assessments = SQLAlchemyRemoteAssessmentRepository(manager)
    repository = SQLAlchemyAgentWorkRepository(manager)
    initial = _assessment(work)
    assessments.add(initial)
    repository.add(work)
    leased = repository.lease_next(work.endpoint_id, now=NOW,
                                   lease_duration=timedelta(minutes=1), max_attempts=3,
                                   retry_delay=timedelta())
    repository.acknowledge(work.work_id, work.endpoint_id, leased.lease_token,
                           assessment_id=work.assessment_id, correlation_id=work.correlation_id, now=NOW)
    assessments.update(replace(initial, state=RemoteAssessmentState.RUNNING,
                               started_at=NOW, acknowledged_at=NOW))
    handlers = ControlPlaneAgentHandlers(AgentSessionRegistry(), assessments, repository)
    reconciler = RemoteAssessmentReconciler(assessments, repository,
                                            execution_timeout=timedelta(seconds=5))
    result = AssessmentResultPayload(work.assessment_id, str(work.endpoint_id), AssessmentStatus.COMPLETED,
                                     NOW, NOW + timedelta(seconds=4), (), (), None)
    in_result_transaction, release_result, timeout_started = Event(), Event(), Event()
    original_copy = module._copy
    original_finish = reconciler._finish_timed_out_work

    def pause_before_assessment_write(record, updated):
        in_result_transaction.set()
        assert release_result.wait(5)
        return original_copy(record, updated)

    def notice_timeout(*args):
        timeout_started.set()
        return original_finish(*args)

    monkeypatch.setattr(module, "_copy", pause_before_assessment_write)
    monkeypatch.setattr(reconciler, "_finish_timed_out_work", notice_timeout)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            accepted = pool.submit(handlers.result, SimpleNamespace(endpoint_id=work.endpoint_id),
                                   result, SimpleNamespace(correlation_id=work.correlation_id))
            assert in_result_transaction.wait(5)
            timeout = pool.submit(reconciler.reconcile, work.assessment_id,
                                  now=NOW + timedelta(seconds=6))
            assert timeout_started.wait(5)
            release_result.set()
            accepted.result(timeout=10)
            timeout.result(timeout=10)
        persisted = assessments.get(work.assessment_id)
        assert persisted.state is RemoteAssessmentState.COMPLETED
        assert persisted.result is not None
        assert repository.get(work.work_id).status is AgentWorkStatus.COMPLETED
    finally:
        release_result.set()
        manager.close()
