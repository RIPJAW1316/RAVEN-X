"""SQLAlchemy persistence for durable assessment-dispatch delivery."""

from dataclasses import replace
from datetime import timezone, timedelta
import hashlib
import json
import secrets

from sqlalchemy import select, update, or_
from sqlalchemy.exc import IntegrityError

from ...application.ports.agent_work_repository import DuplicateAgentWorkError, WorkLeaseError
from ...core.database.models import AgentWorkItemRecord, RemoteAssessmentRecord, EndpointRecord
from ...domain.agent_work import AgentWorkItem, AgentWorkStatus, LeasedAgentWork, WorkId
from ...domain.endpoint import EndpointId, EndpointStatus
from ...protocol.agent import CorrelationId, MessageId
from ...application.control_plane.assessment_dispatch import DuplicateTerminalResultError, RemoteAssessmentState
from .sqlalchemy_remote_assessment_repository import _assessment, _copy
from .write_transaction import begin_serialized_write


class SQLAlchemyAgentWorkRepository:
    def __init__(self, database_manager, *, endpoint_repository=None, assessment_repository=None):
        self._database_manager = database_manager
        self.endpoint_repository = endpoint_repository
        self.assessment_repository = assessment_repository

    def add(self, item):
        try:
            json.dumps(dict(item.envelope), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as error:
            raise ValueError("work envelope must be JSON serializable") from error
        try:
            with self._database_manager.get_db() as session:
                begin_serialized_write(session)
                self._validate_ownership(item, session)
                session.add(_record(item))
                session.flush()
        except IntegrityError as error:
            raise DuplicateAgentWorkError("work_id or protocol message_id already exists") from error

    def _validate_ownership(self, item, session):
        if self.endpoint_repository is not None:
            if getattr(self.endpoint_repository, "_database_manager", None) is self._database_manager:
                endpoint = session.execute(select(EndpointRecord).where(
                    EndpointRecord.endpoint_id == str(item.endpoint_id),
                ).with_for_update()).scalar_one_or_none()
                endpoint_owner = endpoint.organization_id if endpoint is not None else None
                endpoint_status = endpoint.status if endpoint is not None else None
            else:
                endpoint = self.endpoint_repository.get(item.endpoint_id)
                endpoint_owner = str(endpoint.organization_id) if endpoint is not None and endpoint.organization_id else None
                endpoint_status = endpoint.status.value if endpoint is not None else None
            if endpoint is None or endpoint_owner != (str(item.organization_id) if item.organization_id else None):
                raise ValueError("work endpoint organization mismatch")
            if endpoint_status != EndpointStatus.ACTIVE.value:
                raise ValueError("endpoint is not approved for work")
        if item.organization_id is None:
            return
        if self.assessment_repository is not None:
            if getattr(self.assessment_repository, "_database_manager", None) is self._database_manager:
                assessment = session.execute(select(RemoteAssessmentRecord).where(
                    RemoteAssessmentRecord.assessment_id == item.assessment_id,
                ).with_for_update()).scalar_one_or_none()
                assessment_owner = assessment.organization_id if assessment is not None else None
                assessment_endpoint = assessment.endpoint_id if assessment is not None else None
            else:
                assessment = self.assessment_repository.get(item.assessment_id)
                assessment_owner = str(assessment.organization_id) if assessment is not None and assessment.organization_id else None
                assessment_endpoint = str(assessment.endpoint_id) if assessment is not None else None
            if (assessment is None or assessment_owner != str(item.organization_id)
                    or assessment_endpoint != str(item.endpoint_id)):
                raise ValueError("work assessment organization mismatch")

    def get(self, work_id):
        with self._database_manager.get_db() as session:
            record = session.get(AgentWorkItemRecord, str(work_id))
            return _item(record) if record else None

    def list_for_endpoint(self, endpoint_id):
        with self._database_manager.get_db() as session:
            records = session.execute(select(AgentWorkItemRecord).where(
                AgentWorkItemRecord.endpoint_id == str(_endpoint(endpoint_id))
            ).order_by(AgentWorkItemRecord.available_at, AgentWorkItemRecord.created_at)).scalars()
            return tuple(_item(record) for record in records)

    def list_for_endpoint_and_organization(self, endpoint_id, organization_id):
        with self._database_manager.get_db() as session:
            records = session.execute(select(AgentWorkItemRecord).where(
                AgentWorkItemRecord.endpoint_id == str(_endpoint(endpoint_id)),
                AgentWorkItemRecord.organization_id == str(_organization_id(organization_id)),
            ).order_by(AgentWorkItemRecord.available_at, AgentWorkItemRecord.created_at)).scalars()
            return tuple(_item(record) for record in records)

    def lease_next(self, endpoint_id, *, now, lease_duration, max_attempts, retry_delay):
        _validate_delivery_policy(lease_duration, max_attempts, retry_delay)
        self.release_expired_leases(now=now, max_attempts=max_attempts, retry_delay=retry_delay)
        endpoint_id = _endpoint(endpoint_id)
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            endpoint_owner = None
            if self.endpoint_repository is not None:
                if getattr(self.endpoint_repository, "_database_manager", None) is self._database_manager:
                    endpoint = session.execute(select(EndpointRecord).where(
                        EndpointRecord.endpoint_id == str(endpoint_id),
                    ).with_for_update()).scalar_one_or_none()
                    endpoint_status = endpoint.status if endpoint is not None else None
                    endpoint_owner = endpoint.organization_id if endpoint is not None else None
                else:
                    endpoint = self.endpoint_repository.get(endpoint_id)
                    endpoint_status = endpoint.status.value if endpoint is not None else None
                    endpoint_owner = str(endpoint.organization_id) if endpoint is not None and endpoint.organization_id else None
                if endpoint is None or endpoint_status != EndpointStatus.ACTIVE.value:
                    return None
            records = session.execute(select(AgentWorkItemRecord).where(
                AgentWorkItemRecord.endpoint_id == str(endpoint_id),
                AgentWorkItemRecord.organization_id.is_(None) if self.endpoint_repository is not None and endpoint_owner is None else AgentWorkItemRecord.organization_id == str(endpoint_owner) if self.endpoint_repository is not None else True,
                AgentWorkItemRecord.status == AgentWorkStatus.PENDING.value,
                AgentWorkItemRecord.available_at <= _store(now),
                or_(AgentWorkItemRecord.expires_at.is_(None), AgentWorkItemRecord.expires_at > _store(now)),
            ).order_by(AgentWorkItemRecord.available_at, AgentWorkItemRecord.created_at).with_for_update()).scalars()
            # The conditional update is the claim: a concurrent poller can only
            # lease a row if it is still pending when its transaction writes.
            for candidate in records:
                token = secrets.token_urlsafe(32)
                result = session.execute(update(AgentWorkItemRecord).where(
                    AgentWorkItemRecord.work_id == candidate.work_id,
                    AgentWorkItemRecord.status == AgentWorkStatus.PENDING.value,
                    AgentWorkItemRecord.available_at <= _store(now),
                    or_(AgentWorkItemRecord.expires_at.is_(None), AgentWorkItemRecord.expires_at > _store(now)),
                ).values(status=AgentWorkStatus.LEASED.value, leased_at=_store(now),
                         lease_expires_at=_store(now + lease_duration), lease_token_hash=_hash(token),
                         attempt_count=AgentWorkItemRecord.attempt_count + 1))
                if result.rowcount == 1:
                    session.flush()
                    record = session.get(AgentWorkItemRecord, candidate.work_id)
                    return LeasedAgentWork(_item(record), token)
            return None

    def acknowledge(self, work_id, endpoint_id, lease_token, *, assessment_id, correlation_id, now):
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = session.execute(select(AgentWorkItemRecord).where(
                AgentWorkItemRecord.work_id == str(work_id),
            ).with_for_update()).scalar_one_or_none()
            if not _active_lease(record, endpoint_id, lease_token, assessment_id, correlation_id, now):
                raise WorkLeaseError("work acknowledgment does not match an active lease")
            record.status = AgentWorkStatus.ACKNOWLEDGED.value
            record.acknowledged_at = _store(now)
            return _item(record)

    def mark_progress(self, endpoint_id, assessment_id, correlation_id, *, now):
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = _find(session, endpoint_id, assessment_id, correlation_id)
            if record is None:
                raise WorkLeaseError("progress has no linked work")
            if record.status == AgentWorkStatus.LEASED.value and record.lease_expires_at and _load(record.lease_expires_at) > now:
                record.status = AgentWorkStatus.ACKNOWLEDGED.value
                record.acknowledged_at = _store(now)
            elif record.status != AgentWorkStatus.ACKNOWLEDGED.value:
                raise WorkLeaseError("progress does not match active or acknowledged work")
            return _item(record)

    def complete(self, endpoint_id, assessment_id, correlation_id, *, now, failed=False, error=None):
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = _find(session, endpoint_id, assessment_id, correlation_id)
            if record is None:
                raise WorkLeaseError("result has no linked work")
            if record.status == AgentWorkStatus.LEASED.value:
                if not record.lease_expires_at or _load(record.lease_expires_at) <= now:
                    raise WorkLeaseError("result does not match an active lease")
            elif record.status != AgentWorkStatus.ACKNOWLEDGED.value:
                raise WorkLeaseError("result does not match active or acknowledged work")
            record.status = AgentWorkStatus.FAILED.value if failed else AgentWorkStatus.COMPLETED.value
            record.completed_at = _store(now)
            record.last_error = error
            return _item(record)

    def complete_with_assessment(self, assessment_repository, endpoint_id, assessment_id, correlation_id,
                                 *, now, payload):
        """Commit accepted work and its result in one transaction.

        A separate work commit would let the timeout worker observe COMPLETED
        work alongside a RUNNING assessment and record a false timeout.
        """
        if self._database_manager is not assessment_repository._database_manager:
            raise ValueError("work and assessment repositories must share a database manager")
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            # Keep the same lock order as work creation/delivery: endpoint,
            # work, then assessment.  PostgreSQL row locks need this order to
            # avoid a result/timeout cycle while SQLite uses one writer lock.
            endpoint = None
            if self.endpoint_repository is not None:
                endpoint = session.execute(select(EndpointRecord).where(
                    EndpointRecord.endpoint_id == str(_endpoint(endpoint_id)),
                ).with_for_update()).scalar_one_or_none()
                if endpoint is None or endpoint.status != EndpointStatus.ACTIVE.value:
                    raise WorkLeaseError("endpoint is not approved for assessment work")
            work_record = _find(session, endpoint_id, assessment_id, correlation_id)
            if work_record is None:
                raise WorkLeaseError("linked work no longer exists")
            assessment_record = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.assessment_id == assessment_id,
            ).with_for_update()).scalar_one_or_none()
            if assessment_record is None:
                raise WorkLeaseError("assessment no longer exists")
            assessment = _assessment(assessment_record)
            if assessment.endpoint_id != _endpoint(endpoint_id) or str(assessment.correlation_id) != str(correlation_id):
                raise WorkLeaseError("assessment ownership mismatch")
            if assessment.terminal:
                raise DuplicateTerminalResultError(assessment_id)
            if assessment.state is RemoteAssessmentState.CANCELLED:
                raise WorkLeaseError("cancelled assessment cannot receive a result")
            if endpoint is not None and assessment.organization_id is not None and endpoint.organization_id != str(assessment.organization_id):
                raise WorkLeaseError("endpoint tenant ownership mismatch")
            if work_record.organization_id != (str(assessment.organization_id) if assessment.organization_id else None):
                raise WorkLeaseError("work tenant ownership mismatch")
            if work_record.status == AgentWorkStatus.LEASED.value:
                if not work_record.lease_expires_at or _load(work_record.lease_expires_at) <= now:
                    raise WorkLeaseError("result does not match an active lease")
            elif work_record.status != AgentWorkStatus.ACKNOWLEDGED.value:
                raise WorkLeaseError("result does not match active or acknowledged work")
            failed = payload.status.value != "completed"
            work_record.status = AgentWorkStatus.FAILED.value if failed else AgentWorkStatus.COMPLETED.value
            work_record.completed_at = _store(now)
            work_record.last_error = payload.error
            cancellation_metadata = assessment.state is RemoteAssessmentState.CANCEL_REQUESTED
            updated = replace(
                assessment, state=RemoteAssessmentState.FAILED if failed else RemoteAssessmentState.COMPLETED,
                result=payload, error=payload.error,
                completed_at=None if failed else now,
                failed_at=now if failed else None,
                failure_code=(assessment.failure_code if cancellation_metadata else
                              "RESULT_EXECUTION_FAILED" if failed else None),
                failure_reason=(assessment.failure_reason if cancellation_metadata else
                                payload.error if failed else None),
            )
            _copy(assessment_record, updated)
            session.flush()
            return _item(work_record), _assessment(assessment_record)

    def cancel(self, work_id, endpoint_id, *, now):
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = session.execute(select(AgentWorkItemRecord).where(
                AgentWorkItemRecord.work_id == str(work_id),
            ).with_for_update()).scalar_one_or_none()
            if record is None or record.endpoint_id != str(_endpoint(endpoint_id)):
                raise WorkLeaseError("work cancellation ownership mismatch")
            if record.status not in (AgentWorkStatus.PENDING.value, AgentWorkStatus.LEASED.value):
                raise WorkLeaseError("only pre-acknowledgment work can be cancelled")
            record.status = AgentWorkStatus.CANCELLED.value
            record.completed_at = _store(now)
            record.leased_at = record.lease_expires_at = record.lease_token_hash = None
            record.last_error = "cancelled before acknowledgment"
            return _item(record)

    def release_expired_leases(self, *, now, max_attempts, retry_delay):
        _validate_delivery_policy(timedelta(seconds=1), max_attempts, retry_delay)
        changed = []
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            records = session.execute(select(AgentWorkItemRecord).where(
                AgentWorkItemRecord.status.in_((AgentWorkStatus.PENDING.value, AgentWorkStatus.LEASED.value))
            ).with_for_update()).scalars()
            for record in records:
                if record.status == AgentWorkStatus.PENDING.value and record.expires_at and _load(record.expires_at) <= now:
                    record.status, record.completed_at, record.last_error = AgentWorkStatus.EXPIRED.value, _store(now), "work expired before delivery"
                elif record.status == AgentWorkStatus.LEASED.value and record.lease_expires_at and _load(record.lease_expires_at) <= now:
                    if record.attempt_count >= max_attempts:
                        record.status, record.completed_at, record.last_error = AgentWorkStatus.FAILED.value, _store(now), "max delivery attempts exhausted"
                    else:
                        record.status, record.available_at = AgentWorkStatus.PENDING.value, _store(now + retry_delay)
                        record.leased_at = record.lease_expires_at = record.lease_token_hash = None
                        record.last_error = "lease expired before acknowledgment"
                else:
                    continue
                changed.append(_item(record))
            return tuple(changed)


def _record(item):
    return AgentWorkItemRecord(work_id=str(item.work_id), endpoint_id=str(item.endpoint_id),
        organization_id=str(item.organization_id) if item.organization_id else None, assessment_id=item.assessment_id,
        message_id=str(item.message_id), correlation_id=str(item.correlation_id), message_type=item.message_type,
        protocol_version=item.protocol_version, envelope_json=dict(item.envelope), status=item.status.value,
        created_at=_store(item.created_at), available_at=_store(item.available_at),
        expires_at=_store(item.expires_at) if item.expires_at else None, leased_at=_store(item.leased_at) if item.leased_at else None,
        lease_expires_at=_store(item.lease_expires_at) if item.lease_expires_at else None, lease_token_hash=item.lease_token_hash,
        attempt_count=item.attempt_count, acknowledged_at=_store(item.acknowledged_at) if item.acknowledged_at else None,
        completed_at=_store(item.completed_at) if item.completed_at else None, last_error=item.last_error)


def _item(record):
    return AgentWorkItem(WorkId(record.work_id), EndpointId(record.endpoint_id), record.assessment_id,
        MessageId(record.message_id), CorrelationId(record.correlation_id), record.message_type, record.protocol_version,
        dict(record.envelope_json), AgentWorkStatus(record.status), _load(record.created_at), _load(record.available_at),
        _load(record.expires_at) if record.expires_at else None, _load(record.leased_at) if record.leased_at else None,
        _load(record.lease_expires_at) if record.lease_expires_at else None, record.lease_token_hash, record.attempt_count,
        _load(record.acknowledged_at) if record.acknowledged_at else None, _load(record.completed_at) if record.completed_at else None,
        record.last_error, record.organization_id)


def _find(session, endpoint_id, assessment_id, correlation_id):
    return session.execute(select(AgentWorkItemRecord).where(AgentWorkItemRecord.endpoint_id == str(_endpoint(endpoint_id)),
        AgentWorkItemRecord.assessment_id == assessment_id, AgentWorkItemRecord.correlation_id == str(correlation_id)
    ).with_for_update()).scalar_one_or_none()


def _active_lease(record, endpoint_id, token, assessment_id, correlation_id, now):
    return bool(record and record.endpoint_id == str(_endpoint(endpoint_id)) and record.assessment_id == assessment_id
        and record.correlation_id == str(correlation_id) and record.status == AgentWorkStatus.LEASED.value
        and record.lease_expires_at and _load(record.lease_expires_at) > now and record.lease_token_hash == _hash(token))


def _endpoint(value): return value if isinstance(value, EndpointId) else EndpointId(value)
def _organization_id(value):
    module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
    return module.OrganizationId.parse(value)
def _hash(value): return hashlib.sha256(value.encode("utf-8")).hexdigest()
def _store(value): return value.astimezone(timezone.utc).replace(tzinfo=None)
def _load(value): return value.replace(tzinfo=timezone.utc)


def _validate_delivery_policy(lease_duration, max_attempts, retry_delay):
    if lease_duration <= timedelta(0) or retry_delay < timedelta(0) or max_attempts < 1:
        raise ValueError("lease duration, retry delay, and max attempts are invalid")
