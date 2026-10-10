"""Immutable historical compliance snapshot contracts."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4, UUID
import hashlib, json
from .compliance import ComplianceStatus

class ComplianceSnapshotStatus(str, Enum): COMPLETE="complete"; PARTIAL="partial"; FAILED="failed"
class ComplianceSnapshotIntegrityStatus(str, Enum): VALID="valid"; INVALID="invalid"; UNAVAILABLE="unavailable"

@dataclass(frozen=True)
class ComplianceSnapshotId:
    value: str
    def __post_init__(self):
        try: object.__setattr__(self,"value",str(UUID(str(self.value))))
        except (TypeError,ValueError,AttributeError) as e: raise ValueError("snapshot ID must be a valid UUID") from e
    @classmethod
    def new(cls): return cls(str(uuid4()))
    def __str__(self): return self.value

@dataclass(frozen=True)
class ComplianceEndpointSnapshot:
    endpoint_id: str; hostname: str; platform: str; lifecycle_status: str; evaluation_count: int
    def to_dict(self): return {"endpoint_id":self.endpoint_id,"hostname":self.hostname,"platform":self.platform,"lifecycle_status":self.lifecycle_status,"evaluation_count":self.evaluation_count}

@dataclass(frozen=True)
class ComplianceControlSnapshot:
    endpoint_id: str; control_id: str; control_title: str; capability: str; status: ComplianceStatus; reason_code: str; evaluated_at: datetime; source_assessment_id: str|None=None; evidence_age_seconds: float|None=None; coverage_status: str|None=None
    def __post_init__(self): object.__setattr__(self,"status",ComplianceStatus(self.status))
    def to_dict(self): return {"endpoint_id":self.endpoint_id,"control_id":self.control_id,"control_title":self.control_title,"capability":self.capability,"status":self.status.value,"reason":self.reason_code,"evaluated_at":self.evaluated_at.astimezone(timezone.utc).isoformat(),"source_assessment_id":self.source_assessment_id,"evidence_age_seconds":self.evidence_age_seconds,"coverage_status":self.coverage_status}

@dataclass(frozen=True)
class ComplianceSnapshot:
    snapshot_id: ComplianceSnapshotId; organization_id: str; framework_id: str; framework_version: str; created_at: datetime; status: ComplianceSnapshotStatus; evaluation_complete: bool; endpoints_examined: int; endpoint_count: int; control_evaluation_count: int; compliant_count: int; non_compliant_count: int; unknown_count: int; not_applicable_count: int; source_scope_type: str="organization"; source_scope_reference_id: str|None=None; endpoints: tuple[ComplianceEndpointSnapshot,...]=(); controls: tuple[ComplianceControlSnapshot,...]=(); snapshot_digest_sha256: str|None=None
    def __post_init__(self): object.__setattr__(self,"snapshot_id",self.snapshot_id if isinstance(self.snapshot_id,ComplianceSnapshotId) else ComplianceSnapshotId(self.snapshot_id)); object.__setattr__(self,"status",ComplianceSnapshotStatus(self.status))
    def summary(self): return {"snapshot_id":str(self.snapshot_id),"organization_id":self.organization_id,"framework_id":self.framework_id,"framework_version":self.framework_version,"created_at":self.created_at.astimezone(timezone.utc).isoformat(),"status":self.status.value,"evaluation_complete":self.evaluation_complete,"source_scope_type":self.source_scope_type,"source_scope_reference_id":self.source_scope_reference_id,"endpoint_count":self.endpoint_count,"compliant":self.compliant_count,"non_compliant":self.non_compliant_count,"unknown":self.unknown_count,"not_applicable":self.not_applicable_count,"snapshot_digest_sha256":self.snapshot_digest_sha256}
    def to_dict(self): return {**self.summary(),"endpoints_examined":self.endpoints_examined,"control_evaluation_count":self.control_evaluation_count,"endpoints":[x.to_dict() for x in self.endpoints],"controls":[x.to_dict() for x in self.controls]}

def canonical_snapshot_bytes(snapshot: ComplianceSnapshot) -> bytes:
    """Stable semantic serialization; digest is deliberately excluded."""
    value = snapshot.to_dict().copy(); value.pop("snapshot_digest_sha256", None)
    value["endpoints"] = sorted(value["endpoints"], key=lambda x: (x["endpoint_id"], x["hostname"], x["platform"]))
    value["controls"] = sorted(value["controls"], key=lambda x: (x["endpoint_id"], x["control_id"], x["evaluated_at"]))
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def compute_snapshot_digest(snapshot: ComplianceSnapshot) -> str:
    return hashlib.sha256(canonical_snapshot_bytes(snapshot)).hexdigest()

def snapshot_with_digest(snapshot: ComplianceSnapshot) -> ComplianceSnapshot:
    return replace(snapshot, snapshot_digest_sha256=compute_snapshot_digest(snapshot))

def verify_snapshot_integrity(snapshot: ComplianceSnapshot) -> ComplianceSnapshotIntegrityStatus:
    if not snapshot.snapshot_digest_sha256: return ComplianceSnapshotIntegrityStatus.UNAVAILABLE
    return ComplianceSnapshotIntegrityStatus.VALID if snapshot.snapshot_digest_sha256 == compute_snapshot_digest(snapshot) else ComplianceSnapshotIntegrityStatus.INVALID

@dataclass(frozen=True)
class ComplianceSnapshotDelta:
    previous_snapshot_id: str|None; current_snapshot_id: str; comparison_compatible: bool; compliant_delta: int=0; non_compliant_delta: int=0; unknown_delta: int=0; not_applicable_delta: int=0; endpoint_count_delta: int=0; endpoints_added_count: int=0; endpoints_removed_count: int=0; control_deltas: tuple[dict,...]=()
    def to_dict(self): return {"previous_snapshot_id":self.previous_snapshot_id,"current_snapshot_id":self.current_snapshot_id,"comparison_compatible":self.comparison_compatible,"compliant_delta":self.compliant_delta,"non_compliant_delta":self.non_compliant_delta,"unknown_delta":self.unknown_delta,"not_applicable_delta":self.not_applicable_delta,"endpoint_count_delta":self.endpoint_count_delta,"endpoints_added_count":self.endpoints_added_count,"endpoints_removed_count":self.endpoints_removed_count,"control_deltas":list(self.control_deltas)}

class ComplianceRetentionReason(str, Enum):
    AGE_EXCEEDED = "age_exceeded"
    COUNT_EXCEEDED = "count_exceeded"

@dataclass(frozen=True)
class ComplianceSnapshotRetentionPolicy:
    max_age_days: int = 365
    max_snapshots_per_framework: int = 1000
    minimum_snapshots_to_keep: int = 10

    def __post_init__(self):
        if self.max_age_days < 0 or self.max_snapshots_per_framework < 1 or self.minimum_snapshots_to_keep < 1:
            raise ValueError("retention policy values must be positive")
        if self.minimum_snapshots_to_keep > self.max_snapshots_per_framework:
            raise ValueError("minimum snapshots cannot exceed maximum snapshots")

@dataclass(frozen=True)
class ComplianceSnapshotRetentionCandidate:
    snapshot_id: str
    organization_id: str
    framework_id: str
    framework_version: str
    created_at: datetime
    reason: ComplianceRetentionReason
    def to_dict(self):
        return {"snapshot_id": self.snapshot_id, "organization_id": self.organization_id,
                "framework_id": self.framework_id, "framework_version": self.framework_version,
                "created_at": self.created_at.astimezone(timezone.utc).isoformat(), "reason": self.reason.value}

@dataclass(frozen=True)
class ComplianceTimelinePoint:
    snapshot_id: str; created_at: datetime; framework_version: str; endpoint_count: int
    control_evaluation_count: int; compliant: int; non_compliant: int; unknown: int; not_applicable: int; evaluation_complete: bool
    def to_dict(self):
        return {"snapshot_id": self.snapshot_id, "created_at": self.created_at.astimezone(timezone.utc).isoformat(),
                "framework_version": self.framework_version, "endpoint_count": self.endpoint_count,
                "control_evaluation_count": self.control_evaluation_count, "compliant": self.compliant,
                "non_compliant": self.non_compliant, "unknown": self.unknown, "not_applicable": self.not_applicable,
                "evaluation_complete": self.evaluation_complete}

@dataclass(frozen=True)
class ComplianceControlTrendPoint:
    snapshot_id: str; created_at: datetime; framework_version: str; control_id: str
    compliant: int; non_compliant: int; unknown: int; not_applicable: int; endpoint_count: int
    def to_dict(self): return {"snapshot_id":self.snapshot_id,"created_at":self.created_at.astimezone(timezone.utc).isoformat(),"framework_version":self.framework_version,"control_id":self.control_id,"compliant":self.compliant,"non_compliant":self.non_compliant,"unknown":self.unknown,"not_applicable":self.not_applicable,"endpoint_count":self.endpoint_count}

@dataclass(frozen=True)
class ComplianceEndpointHistoryPoint:
    snapshot_id: str; snapshot_created_at: datetime; endpoint_id: str; hostname: str; platform: str
    lifecycle_status: str; compliant: int; non_compliant: int; unknown: int; not_applicable: int
    def to_dict(self): return {"snapshot_id":self.snapshot_id,"snapshot_created_at":self.snapshot_created_at.astimezone(timezone.utc).isoformat(),"endpoint_id":self.endpoint_id,"hostname":self.hostname,"platform":self.platform,"lifecycle_status":self.lifecycle_status,"compliant":self.compliant,"non_compliant":self.non_compliant,"unknown":self.unknown,"not_applicable":self.not_applicable}
