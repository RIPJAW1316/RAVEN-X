"""Explicit, bounded compliance snapshot retention (no background worker)."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ...domain.compliance_snapshot import ComplianceSnapshotRetentionPolicy, ComplianceSnapshotRetentionCandidate, ComplianceRetentionReason
from ...domain.security import SecurityAuditEvent, SecurityAuditOutcome, SecurityPrincipal

class ComplianceSnapshotRetentionRunner:
    def __init__(self, repository, policy=None, *, now_fn=None, audit_sink=None, metrics=None, logger=None):
        self.repository = repository
        self.policy = policy or ComplianceSnapshotRetentionPolicy()
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.audit_sink, self.metrics, self.logger = audit_sink, metrics, logger

    def evaluate_retention(self, organization_id=None):
        orgs = [organization_id] if organization_id is not None else self._organizations()
        cutoff = self.now_fn() - timedelta(days=self.policy.max_age_days)
        candidates = []
        for org in orgs:
            snapshots = list(self.repository.list_for_organization(org, limit=10000, offset=0))
            groups = defaultdict(list)
            for snapshot in snapshots:
                groups[(snapshot.framework_id, snapshot.framework_version)].append(snapshot)
            for values in groups.values():
                values.sort(key=lambda x: (x.created_at, str(x.snapshot_id)), reverse=True)
                for index, snapshot in enumerate(values):
                    if index < self.policy.minimum_snapshots_to_keep:
                        continue
                    reason = None
                    if index >= self.policy.max_snapshots_per_framework:
                        reason = ComplianceRetentionReason.COUNT_EXCEEDED
                    elif snapshot.created_at < cutoff:
                        reason = ComplianceRetentionReason.AGE_EXCEEDED
                    if reason:
                        candidates.append(ComplianceSnapshotRetentionCandidate(str(snapshot.snapshot_id), str(snapshot.organization_id), snapshot.framework_id, snapshot.framework_version, snapshot.created_at, reason))
        return tuple(sorted(candidates, key=lambda x: (x.created_at, x.snapshot_id)))

    def run_once(self, *, organization_id=None, dry_run=False):
        started = self.now_fn()
        if self.logger: self.logger.info("compliance.snapshot.retention.started", extra={"dry_run":dry_run})
        candidates = self.evaluate_retention(organization_id)
        if dry_run:
            if self.logger: self.logger.info("compliance.snapshot.retention.completed", extra={"dry_run":True,"candidate_count":len(candidates)})
            return {"dry_run": True, "candidates": candidates, "deleted_count": 0}
        deleted = 0; failures = 0
        for candidate in candidates:
            try:
                if self.repository.delete_for_retention(candidate.organization_id, candidate.snapshot_id): deleted += 1
            except Exception:
                failures += 1
                if self.logger: self.logger.exception("compliance.snapshot.retention.delete_failed")
        if self.metrics:
            self.metrics.increment("compliance_retention_runs_total")
            self.metrics.increment("compliance_retention_deleted_snapshots_total", deleted)
            if failures: self.metrics.increment("compliance_retention_failures_total", failures)
        if self.audit_sink:
            self.audit_sink.append(SecurityAuditEvent(event_type="compliance.snapshot.retention", principal=SecurityPrincipal.system(), outcome=SecurityAuditOutcome.FAILED if failures else SecurityAuditOutcome.SUCCESS, organization_id=str(organization_id) if organization_id else None, metadata={"deleted_count":deleted,"candidate_count":len(candidates),"failure_count":failures,"duration_ms":int((self.now_fn()-started).total_seconds()*1000)}))
        if self.logger: self.logger.info("compliance.snapshot.retention.completed", extra={"dry_run":False,"candidate_count":len(candidates),"deleted_count":deleted,"failure_count":failures})
        return {"dry_run": False, "candidates": candidates, "deleted_count": deleted, "failure_count": failures}

    def _organizations(self):
        if hasattr(self.repository, "list_organizations"):
            return self.repository.list_organizations()
        items = getattr(self.repository, "items", {})
        return tuple(sorted({str(x.organization_id) for x in items.values()}))
