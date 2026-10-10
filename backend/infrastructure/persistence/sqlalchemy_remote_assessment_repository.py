"""SQLAlchemy adapter for durable remote assessment workflow state."""

from datetime import datetime, timezone
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ...application.control_plane.assessment_dispatch import (
    RemoteAssessment, RemoteAssessmentState, _TERMINAL_ASSESSMENT_STATES,
)
from ...application.ports.remote_assessment_repository import (
    DuplicateRemoteAssessmentError, RemoteAssessmentConflictError,
)
from ...core.database.models import RemoteAssessmentRecord
from ...domain.endpoint import EndpointId
from ...protocol.agent import AssessmentProgress, AssessmentResultPayload, CorrelationId
from .write_transaction import begin_serialized_write


class SQLAlchemyRemoteAssessmentRepository:
    def __init__(self, database_manager):
        self._database_manager = database_manager

    def add(self, assessment):
        try:
            with self._database_manager.get_db() as session:
                session.add(_record(assessment))
                session.flush()
        except IntegrityError as error:
            raise DuplicateRemoteAssessmentError("assessment_id or correlation_id already exists") from error

    def get(self, assessment_id):
        with self._database_manager.get_db() as session:
            record = session.get(RemoteAssessmentRecord, assessment_id)
            return _assessment(record) if record else None

    def exists(self, assessment_id):
        return self.get(assessment_id) is not None

    def update(self, assessment):
        with self._database_manager.get_db() as session:
            begin_serialized_write(session)
            record = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.assessment_id == assessment.assessment_id,
            ).with_for_update()).scalar_one_or_none()
            if record is None:
                raise KeyError(assessment.assessment_id)
            existing = _assessment(record)
            if existing.terminal and existing != assessment:
                raise RemoteAssessmentConflictError("terminal assessment cannot be changed")
            if existing.organization_id != assessment.organization_id:
                raise RemoteAssessmentConflictError("assessment organization ownership is immutable")
            _copy(record, assessment)
            session.flush()
            return _assessment(record)

    def list(self):
        with self._database_manager.get_db() as session:
            records = session.execute(select(RemoteAssessmentRecord).order_by(RemoteAssessmentRecord.requested_at)).scalars()
            return tuple(_assessment(record) for record in records)

    def list_non_terminal(self):
        terminal = tuple(state.value for state in _TERMINAL_ASSESSMENT_STATES)
        with self._database_manager.get_db() as session:
            records = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.status.not_in(terminal)
            ).order_by(RemoteAssessmentRecord.requested_at)).scalars()
            return tuple(_assessment(record) for record in records)

    def get_for_organization(self, assessment_id, organization_id):
        with self._database_manager.get_db() as session:
            record = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.assessment_id == assessment_id,
                RemoteAssessmentRecord.organization_id == str(_organization_id(organization_id)),
            )).scalar_one_or_none()
            return _assessment(record) if record else None

    def list_for_organization(self, organization_id):
        with self._database_manager.get_db() as session:
            records = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.organization_id == str(_organization_id(organization_id))
            ).order_by(RemoteAssessmentRecord.requested_at)).scalars()
            return tuple(_assessment(record) for record in records)

    def exists_for_organization(self, assessment_id, organization_id):
        return self.get_for_organization(assessment_id, organization_id) is not None

    def list_for_organization_bounded(self, organization_id, *, endpoint_ids, limit):
        """Bound rows in SQL; report callers reject overflow instead of truncating history."""
        if not 1 <= limit <= 2001 or len(endpoint_ids) > 500:
            raise ValueError("invalid assessment report query bound")
        if not endpoint_ids:
            return ()
        with self._database_manager.get_db() as session:
            records = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.organization_id == str(_organization_id(organization_id)),
                RemoteAssessmentRecord.endpoint_id.in_(tuple(str(value) for value in endpoint_ids)),
            ).order_by(RemoteAssessmentRecord.requested_at.desc(), RemoteAssessmentRecord.assessment_id)
              .limit(limit)).scalars()
            return tuple(_assessment(record) for record in records)

    def list_for_endpoint_and_organization(self, endpoint_id, organization_id):
        with self._database_manager.get_db() as session:
            records = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.organization_id == str(_organization_id(organization_id)),
                RemoteAssessmentRecord.endpoint_id == str(endpoint_id if isinstance(endpoint_id, EndpointId) else EndpointId(endpoint_id)),
            ).order_by(RemoteAssessmentRecord.requested_at)).scalars()
            return tuple(_assessment(record) for record in records)

    def list_for_schedule(self, schedule_id):
        with self._database_manager.get_db() as session:
            records = session.execute(select(RemoteAssessmentRecord).where(
                RemoteAssessmentRecord.schedule_id == str(schedule_id)
            ).order_by(RemoteAssessmentRecord.requested_at)).scalars()
            return tuple(_assessment(record) for record in records)


def _record(assessment):
    record = RemoteAssessmentRecord(assessment_id=assessment.assessment_id)
    _copy(record, assessment)
    return record


def _copy(record, assessment):
    record.organization_id = str(assessment.organization_id) if assessment.organization_id else None
    record.schedule_id = assessment.schedule_id
    record.endpoint_id = str(assessment.endpoint_id)
    record.correlation_id = str(assessment.correlation_id)
    record.scanner_ids = list(assessment.scanner_ids)
    record.status = assessment.state.value
    record.requested_at = _store(assessment.requested_at)
    for name in ("queued_at", "dispatched_at", "acknowledged_at", "started_at", "completed_at", "failed_at",
                 "cancel_requested_at", "cancelled_at", "expires_at", "execution_timeout_detected_at"):
        setattr(record, name, _store(getattr(assessment, name)) if getattr(assessment, name) else None)
    record.progress_json = _json_value(assessment.progress)
    record.result_json = _json_value(assessment.result)
    record.error = assessment.error
    record.failure_code = assessment.failure_code
    record.failure_reason = assessment.failure_reason


def _assessment(record):
    return RemoteAssessment(
        record.assessment_id, EndpointId(record.endpoint_id), CorrelationId(record.correlation_id), tuple(record.scanner_ids),
        _load(record.requested_at), RemoteAssessmentState(record.status), _progress(record.progress_json),
        _result(record.result_json), record.error,
        _optional(record.queued_at), _optional(record.dispatched_at), _optional(record.acknowledged_at),
        _optional(record.started_at), _optional(record.completed_at), _optional(record.failed_at),
        _optional(record.cancel_requested_at), _optional(record.cancelled_at), _optional(record.expires_at),
        record.failure_code, record.failure_reason, _optional(record.execution_timeout_detected_at), record.organization_id, record.schedule_id,
    )


def _json_value(value):
    if value is None:
        return None
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    if isinstance(value, Mapping):
        return dict(value)
    raise ValueError("remote assessment progress/result must be JSON-safe structured data")


def _progress(value):
    if not value:
        return None
    return AssessmentProgress(value["assessment_id"], value["status"], tuple(value.get("completed_scanners", ())),
                              value["total_scanners"], value.get("current_scanner_id"),
                              datetime.fromisoformat(value["timestamp"]), value.get("correlation_id"))


def _result(value):
    if not value:
        return None
    return AssessmentResultPayload(value["assessment_id"], value["endpoint_id"], value["status"],
                                   datetime.fromisoformat(value["started_at"]),
                                   datetime.fromisoformat(value["finished_at"]) if value.get("finished_at") else None,
                                   tuple(value.get("findings", ())), tuple(value.get("scanner_results", ())), value.get("error"))


def _store(value): return value.astimezone(timezone.utc).replace(tzinfo=None)
def _load(value): return value.replace(tzinfo=timezone.utc)
def _optional(value): return _load(value) if value else None
def _organization_id(value):
    module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
    return module.OrganizationId.parse(value)
