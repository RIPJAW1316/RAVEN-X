"""Deterministic in-memory implementation of durable-work semantics for tests."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from threading import RLock

from ...application.ports.agent_work_repository import DuplicateAgentWorkError, WorkLeaseError
from ...domain.agent_work import AgentWorkItem, AgentWorkStatus, LeasedAgentWork, WorkId
from ...domain.endpoint import EndpointId


class InMemoryAgentWorkRepository:
    def __init__(self, *, endpoint_repository=None, assessment_repository=None):
        self._items = {}
        self._message_ids = set()
        self._lock = RLock()
        self.endpoint_repository = endpoint_repository
        self.assessment_repository = assessment_repository

    def add(self, item):
        with self._lock:
            self._validate_ownership(item)
            try:
                json.dumps(dict(item.envelope), sort_keys=True, separators=(",", ":"))
            except (TypeError, ValueError) as error:
                raise ValueError("work envelope must be JSON serializable") from error
            if str(item.work_id) in self._items or str(item.message_id) in self._message_ids:
                raise DuplicateAgentWorkError("work_id or protocol message_id already exists")
            self._items[str(item.work_id)] = item
            self._message_ids.add(str(item.message_id))

    def _validate_ownership(self, item):
        if item.organization_id is None:
            return
        if self.endpoint_repository is not None:
            endpoint = self.endpoint_repository.get(item.endpoint_id)
            if endpoint is None or endpoint.organization_id != item.organization_id:
                raise ValueError("work endpoint organization mismatch")
        if self.assessment_repository is not None:
            assessment = self.assessment_repository.get(item.assessment_id)
            if assessment is None or assessment.organization_id != item.organization_id or assessment.endpoint_id != item.endpoint_id:
                raise ValueError("work assessment organization mismatch")

    def get(self, work_id):
        with self._lock:
            return self._items.get(str(work_id))

    def list_for_endpoint(self, endpoint_id):
        with self._lock:
            return tuple(item for item in self._items.values() if item.endpoint_id == _endpoint(endpoint_id))

    def list_for_endpoint_and_organization(self, endpoint_id, organization_id):
        module = __import__("backend.domain.organization", fromlist=["OrganizationId"])
        oid = module.OrganizationId.parse(organization_id)
        return tuple(item for item in self.list_for_endpoint(endpoint_id) if item.organization_id == oid)

    def lease_next(self, endpoint_id, *, now, lease_duration, max_attempts, retry_delay):
        _validate_delivery_policy(lease_duration, max_attempts, retry_delay)
        with self._lock:
            self.release_expired_leases(now=now, max_attempts=max_attempts, retry_delay=retry_delay)
            endpoint_id = _endpoint(endpoint_id)
            endpoint_record = self.endpoint_repository.get(endpoint_id) if self.endpoint_repository else None
            if self.endpoint_repository is not None and endpoint_record is None:
                return None
            endpoint_owner = endpoint_record.organization_id if endpoint_record is not None else None
            candidates = sorted(
                (item for item in self._items.values()
                 if item.endpoint_id == endpoint_id and item.status is AgentWorkStatus.PENDING and item.available_at <= now
                 and (item.expires_at is None or now < item.expires_at)
                 and (self.endpoint_repository is None or item.organization_id == endpoint_owner)),
                key=lambda item: (item.available_at, item.created_at, str(item.work_id)),
            )
            if not candidates:
                return None
            item = candidates[0]
            token = secrets.token_urlsafe(32)
            leased = replace(item, status=AgentWorkStatus.LEASED, leased_at=now,
                             lease_expires_at=now + lease_duration, lease_token_hash=_hash(token),
                             attempt_count=item.attempt_count + 1)
            self._items[str(item.work_id)] = leased
            return LeasedAgentWork(leased, token)

    def acknowledge(self, work_id, endpoint_id, lease_token, *, assessment_id, correlation_id, now):
        with self._lock:
            item = self._require(work_id)
            if (item.endpoint_id != _endpoint(endpoint_id) or item.assessment_id != assessment_id
                    or str(item.correlation_id) != str(correlation_id) or item.status is not AgentWorkStatus.LEASED
                    or item.lease_expires_at is None or now >= item.lease_expires_at
                    or item.lease_token_hash != _hash(lease_token)):
                raise WorkLeaseError("work acknowledgment does not match an active lease")
            updated = replace(item, status=AgentWorkStatus.ACKNOWLEDGED, acknowledged_at=now)
            self._items[str(item.work_id)] = updated
            return updated

    def mark_progress(self, endpoint_id, assessment_id, correlation_id, *, now):
        with self._lock:
            item = self._find(endpoint_id, assessment_id, correlation_id)
            if item is None:
                raise WorkLeaseError("progress has no linked work")
            if item.status is AgentWorkStatus.LEASED and item.lease_expires_at is not None and now < item.lease_expires_at:
                updated = replace(item, status=AgentWorkStatus.ACKNOWLEDGED, acknowledged_at=now)
                self._items[str(item.work_id)] = updated
                return updated
            if item.status is not AgentWorkStatus.ACKNOWLEDGED:
                raise WorkLeaseError("progress does not match active or acknowledged work")
            return item

    def complete(self, endpoint_id, assessment_id, correlation_id, *, now, failed=False, error=None):
        with self._lock:
            item = self._find(endpoint_id, assessment_id, correlation_id)
            if item is None:
                raise WorkLeaseError("result has no linked work")
            if item.status is AgentWorkStatus.LEASED:
                if item.lease_expires_at is None or now >= item.lease_expires_at:
                    raise WorkLeaseError("result does not match an active lease")
            elif item.status is not AgentWorkStatus.ACKNOWLEDGED:
                raise WorkLeaseError("result does not match active or acknowledged work")
            updated = replace(item, status=AgentWorkStatus.FAILED if failed else AgentWorkStatus.COMPLETED,
                             completed_at=now, last_error=error)
            self._items[str(item.work_id)] = updated
            return updated

    def cancel(self, work_id, endpoint_id, *, now):
        with self._lock:
            item = self._require(work_id)
            if item.endpoint_id != _endpoint(endpoint_id):
                raise WorkLeaseError("work cancellation ownership mismatch")
            if item.status not in (AgentWorkStatus.PENDING, AgentWorkStatus.LEASED):
                raise WorkLeaseError("only pre-acknowledgment work can be cancelled")
            updated = replace(item, status=AgentWorkStatus.CANCELLED, completed_at=now,
                              leased_at=None, lease_expires_at=None, lease_token_hash=None,
                              last_error="cancelled before acknowledgment")
            self._items[str(item.work_id)] = updated
            return updated

    def release_expired_leases(self, *, now, max_attempts, retry_delay):
        _validate_delivery_policy(timedelta(seconds=1), max_attempts, retry_delay)
        with self._lock:
            changed = []
            for item in tuple(self._items.values()):
                if item.status is AgentWorkStatus.PENDING and item.expires_at is not None and now >= item.expires_at:
                    updated = replace(item, status=AgentWorkStatus.EXPIRED, completed_at=now, last_error="work expired before delivery")
                elif item.status is AgentWorkStatus.LEASED and item.lease_expires_at is not None and now >= item.lease_expires_at:
                    if item.attempt_count >= max_attempts:
                        updated = replace(item, status=AgentWorkStatus.FAILED, completed_at=now, last_error="max delivery attempts exhausted")
                    else:
                        updated = replace(item, status=AgentWorkStatus.PENDING, available_at=now + retry_delay,
                                          leased_at=None, lease_expires_at=None, lease_token_hash=None,
                                          last_error="lease expired before acknowledgment")
                else:
                    continue
                self._items[str(item.work_id)] = updated
                changed.append(updated)
            return tuple(changed)

    def _require(self, work_id):
        item = self.get(work_id)
        if item is None:
            raise WorkLeaseError("work item not found")
        return item

    def _find(self, endpoint_id, assessment_id, correlation_id):
        endpoint_id = _endpoint(endpoint_id)
        return next((item for item in self._items.values() if item.endpoint_id == endpoint_id
                     and item.assessment_id == assessment_id and str(item.correlation_id) == str(correlation_id)), None)


def _endpoint(value):
    return value if isinstance(value, EndpointId) else EndpointId(value)


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_delivery_policy(lease_duration, max_attempts, retry_delay):
    if lease_duration <= timedelta(0) or retry_delay < timedelta(0) or max_attempts < 1:
        raise ValueError("lease duration, retry delay, and max attempts are invalid")
