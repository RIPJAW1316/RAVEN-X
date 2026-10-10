# backend/core/database/models.py
from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

def _uuid(): return str(uuid.uuid4())

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String(50))  # full, quick, targeted
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    system_info = Column(JSON)
    risk_score = Column(Float)
    risk_level = Column(String(20))
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    status = Column(String(20))  # running, completed, failed
    
    vulnerabilities = relationship('Vulnerability', back_populates='scan', cascade='all, delete-orphan')
    fixes = relationship('Fix', back_populates='scan', cascade='all, delete-orphan')

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'))
    severity = Column(String(20))
    category = Column(String(50))
    title = Column(String(255))
    details = Column(Text)
    component = Column(String(100))
    remediation = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Defense-grade fields
    cvss_score = Column(Float, nullable=True)          # CVSS v3.1 base score
    powershell_command = Column(Text, nullable=True)   # Auto-remediation command
    compliance_tags = Column(JSON, nullable=True)      # {framework: [control_ids]}

    # Pattern learning
    signature = Column(String(255), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    occurrence_count = Column(Integer, default=1)
    
    scan = relationship('Scan', back_populates='vulnerabilities')
    fixes = relationship('Fix', back_populates='vulnerability')

class Fix(Base):
    __tablename__ = 'fixes'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'))
    vulnerability_id = Column(String(36), ForeignKey('vulnerabilities.id'))
    fix_type = Column(String(50))  # automated, manual, script
    status = Column(String(20))  # pending, success, failed, manual
    applied_at = Column(DateTime, nullable=True)
    execution_time = Column(Float, nullable=True)
    command_executed = Column(Text, nullable=True)
    output = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # For learning from fixes
    success_rate = Column(Float, nullable=True)
    rollback_performed = Column(Boolean, default=False)
    
    scan = relationship('Scan', back_populates='fixes')
    vulnerability = relationship('Vulnerability', back_populates='fixes')

class ThreatPattern(Base):
    """Learned threat patterns from scans and incidents"""
    __tablename__ = 'threat_patterns'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    pattern_type = Column(String(50))  # malware, config, behavior, network
    pattern_signature = Column(String(255), unique=True)
    pattern_data = Column(JSON)  # Flexible storage for pattern details
    severity = Column(String(20))
    confidence_score = Column(Float)  # 0.0 to 1.0
    times_detected = Column(Integer, default=1)
    first_detected = Column(DateTime, default=datetime.utcnow)
    last_detected = Column(DateTime, default=datetime.utcnow)
    false_positive_count = Column(Integer, default=0)
    true_positive_count = Column(Integer, default=0)
    
    # Learning metadata
    source = Column(String(50))  # internal_scan, user_feedback, external_intel
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MalwareSample(Base):
    """Stored malware samples for analysis and learning"""
    __tablename__ = 'malware_samples'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_hash_md5 = Column(String(32), unique=True)
    file_hash_sha256 = Column(String(64), unique=True)
    file_path = Column(String(500))
    file_size = Column(Integer)
    file_type = Column(String(50))
    
    # Detection metadata
    detected_at = Column(DateTime, default=datetime.utcnow)
    detection_method = Column(String(50))  # signature, heuristic, ml, behavior
    severity = Column(String(20))
    
    # Analysis results
    yara_matches = Column(JSON, nullable=True)
    behavioral_indicators = Column(JSON, nullable=True)
    ml_prediction = Column(JSON, nullable=True)
    static_analysis = Column(JSON, nullable=True)
    
    # Quarantine info
    quarantined = Column(Boolean, default=False)
    quarantine_path = Column(String(500), nullable=True)
    
    # Learning data
    user_verified = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)

class AIAnalysis(Base):
    """AI analysis results for historical tracking"""
    __tablename__ = 'ai_analyses'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'))
    model_name = Column(String(100))
    prompt_tokens = Column(Integer)
    completion_tokens = Column(Integer)
    analysis_text = Column(Text)
    recommendations = Column(JSON)
    priority_fixes = Column(JSON)
    compliance_mapping = Column(JSON, nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    execution_time = Column(Float)

class SystemBaseline(Base):
    """Baseline system configurations for anomaly detection"""
    __tablename__ = 'system_baselines'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String(255))
    baseline_type = Column(String(50))  # services, ports, processes, files, registry
    baseline_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class UserFeedback(Base):
    """User feedback for improving AI and detection"""
    __tablename__ = 'user_feedback'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id = Column(String(36), ForeignKey('vulnerabilities.id'), nullable=True)
    fix_id = Column(String(36), ForeignKey('fixes.id'), nullable=True)
    feedback_type = Column(String(50))  # false_positive, true_positive, fix_worked, fix_failed
    rating = Column(Integer, nullable=True)  # 1-5
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Tamper-proof audit log entries (mirrors the flat JSONL chain file)"""
    __tablename__ = 'audit_logs'

    id = Column(String(36), primary_key=True, default=_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String(50))
    description = Column(String(255))
    actor = Column(String(100), default='system')
    severity = Column(String(20), default='info')
    details = Column(JSON, nullable=True)
    prev_hash = Column(String(64))
    entry_hash = Column(String(64), unique=True)


class ComplianceSnapshot(Base):
    """Point-in-time compliance scores per scan"""
    __tablename__ = 'compliance_snapshots'

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey('scans.id'))
    framework = Column(String(50))           # CIS, NIST, ISO 27001, PCI-DSS, SMLDI 2025, CERT-In
    score = Column(Float)                    # 0.0 – 100.0
    total_controls = Column(Integer)
    passed = Column(Integer)
    failed = Column(Integer)
    failed_controls = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class EndpointRecord(Base):
    """Durable adapter record for the pure endpoint identity domain."""
    __tablename__ = 'endpoints'

    endpoint_id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=True, index=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(100), nullable=False)
    platform_version = Column(String(255), nullable=True)
    architecture = Column(String(100), nullable=True)
    status = Column(String(20), nullable=False)
    agent_version = Column(String(100), nullable=True)
    protocol_version = Column(String(100), nullable=True)
    agent_installed_at = Column(DateTime, nullable=True)
    capabilities = Column(JSON, nullable=False, default=list)
    capability_observations = Column(JSON, nullable=False, default=list)
    endpoint_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)


class EndpointPresenceRecord(Base):
    """Current liveness snapshot; deliberately no heartbeat history rows."""
    __tablename__ = 'endpoint_presence'

    endpoint_id = Column(String(36), ForeignKey('endpoints.endpoint_id'), primary_key=True)
    organization_id = Column(String(36), nullable=True, index=True)
    state = Column(String(20), nullable=False, default='unknown')
    last_seen_at = Column(DateTime, nullable=True)
    last_heartbeat_at = Column(DateTime, nullable=True)
    connected_since = Column(DateTime, nullable=True)
    stale_since = Column(DateTime, nullable=True)
    offline_since = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class EnrollmentRecord(Base):
    """Bootstrap authorization; only a one-way token verifier is stored."""
    __tablename__ = 'endpoint_enrollments'

    enrollment_id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=True, index=True)
    token_verifier = Column(String(512), nullable=False)
    status = Column(String(20), nullable=False)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    consumed_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    enrollment_metadata = Column(JSON, nullable=False, default=dict)


class EndpointCredentialRecord(Base):
    """Credential metadata and verifier; raw credential material is never stored."""
    __tablename__ = 'endpoint_credentials'

    credential_id = Column(String(36), primary_key=True)
    endpoint_id = Column(String(36), ForeignKey('endpoints.endpoint_id'), nullable=False, index=True)
    credential_kind = Column(String(30), nullable=False)
    verifier = Column(String(512), nullable=False)
    status = Column(String(20), nullable=False)
    issued_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    rotated_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(255), nullable=True)
    credential_metadata = Column(JSON, nullable=False, default=dict)


class AgentMessageReplayRecord(Base):
    """Minimal durable replay claim; payloads are intentionally not stored."""
    __tablename__ = 'agent_message_replay'

    message_id = Column(String(36), primary_key=True)
    endpoint_id = Column(String(36), nullable=False, index=True)
    first_seen_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)


class AgentWorkItemRecord(Base):
    """Additive durable assessment-dispatch delivery record; credentials are never stored."""
    __tablename__ = 'agent_work_items'

    work_id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=True, index=True)
    endpoint_id = Column(String(36), ForeignKey('endpoints.endpoint_id'), nullable=False, index=True)
    assessment_id = Column(String(64), nullable=False, index=True)
    message_id = Column(String(36), nullable=False, unique=True)
    correlation_id = Column(String(36), nullable=False, index=True)
    message_type = Column(String(80), nullable=False)
    protocol_version = Column(String(20), nullable=False)
    envelope_json = Column(JSON, nullable=False)
    status = Column(String(20), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    available_at = Column(DateTime, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    leased_at = Column(DateTime, nullable=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    lease_token_hash = Column(String(64), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    acknowledged_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)


class RemoteAssessmentRecord(Base):
    """Durable control-plane assessment workflow, separate from delivery work."""
    __tablename__ = 'remote_assessments'

    assessment_id = Column(String(64), primary_key=True)
    schedule_id = Column(String(36), nullable=True, index=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=True, index=True)
    endpoint_id = Column(String(36), ForeignKey('endpoints.endpoint_id'), nullable=False, index=True)
    correlation_id = Column(String(36), nullable=False, unique=True, index=True)
    scanner_ids = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, index=True)
    requested_at = Column(DateTime, nullable=False)
    queued_at = Column(DateTime, nullable=True)
    dispatched_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    failed_at = Column(DateTime, nullable=True)
    cancel_requested_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    progress_json = Column(JSON, nullable=True)
    result_json = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    failure_code = Column(String(80), nullable=True)
    failure_reason = Column(Text, nullable=True)
    execution_timeout_detected_at = Column(DateTime, nullable=True)


class AssessmentScheduleRecord(Base):
    __tablename__ = 'assessment_schedules'
    schedule_id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    status = Column(String(20), nullable=False, index=True)
    recurrence_json = Column(JSON, nullable=False)
    target_endpoint_ids = Column(JSON, nullable=False)
    scanner_ids = Column(JSON, nullable=False)
    next_run_at = Column(DateTime, nullable=False, index=True)
    last_run_at = Column(DateTime, nullable=True)
    created_by = Column(String(36), nullable=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    overlap_policy = Column(String(40), nullable=False, default="skip_if_active")
    schedule_metadata = Column(JSON, nullable=False, default=dict)
    target_type = Column(String(40), nullable=True)
    target_reference_id = Column(String(36), nullable=True)


class AssessmentScheduleRunRecord(Base):
    __tablename__ = 'assessment_schedule_runs'
    run_id = Column(String(36), primary_key=True)
    schedule_id = Column(String(36), ForeignKey('assessment_schedules.schedule_id'), nullable=False, index=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=False, index=True)
    scheduled_for = Column(DateTime, nullable=False, index=True)
    started_at = Column(DateTime, nullable=False)
    status = Column(String(20), nullable=False, index=True)
    assessment_ids = Column(JSON, nullable=False, default=list)
    target_outcomes = Column(JSON, nullable=False, default=dict)
    reason = Column(Text, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    resolved_endpoint_ids = Column(JSON, nullable=False, default=list)
    targets_resolved_at = Column(DateTime, nullable=True)
    target_type = Column(String(40), nullable=True)
    target_reference_id = Column(String(36), nullable=True)
    scope_criteria_snapshot = Column(JSON, nullable=False, default=dict)
    resolution_reason = Column(String(100), nullable=True)
    __table_args__ = (UniqueConstraint('schedule_id', 'scheduled_for', name='uq_assessment_schedule_run_occurrence'),)

class EndpointGroupRecord(Base):
    __tablename__ = 'endpoint_groups'
    group_id=Column(String(36),primary_key=True); organization_id=Column(String(36),ForeignKey('organizations.organization_id'),nullable=False,index=True)
    name=Column(String(200),nullable=False); description=Column(Text,nullable=False,default=''); status=Column(String(20),nullable=False,index=True)
    created_by=Column(String(36)); created_at=Column(DateTime,nullable=False); updated_at=Column(DateTime,nullable=False)

class EndpointGroupMembershipRecord(Base):
    __tablename__='endpoint_group_memberships'
    group_id=Column(String(36),ForeignKey('endpoint_groups.group_id'),primary_key=True); endpoint_id=Column(String(36),ForeignKey('endpoints.endpoint_id'),primary_key=True,index=True)
    organization_id=Column(String(36),ForeignKey('organizations.organization_id'),nullable=False,index=True); added_at=Column(DateTime,nullable=False); added_by=Column(String(36))

class SavedFleetScopeRecord(Base):
    __tablename__='saved_fleet_scopes'
    scope_id=Column(String(36),primary_key=True); organization_id=Column(String(36),ForeignKey('organizations.organization_id'),nullable=False,index=True)
    name=Column(String(200),nullable=False); description=Column(Text,nullable=False,default=''); status=Column(String(20),nullable=False,index=True)
    query_version=Column(Integer,nullable=False,default=1); criteria_json=Column(JSON,nullable=False); created_by=Column(String(36)); created_at=Column(DateTime,nullable=False); updated_at=Column(DateTime,nullable=False)

class ComplianceSnapshotRecord(Base):
    __tablename__ = 'compliance_posture_snapshots'
    snapshot_id=Column(String(36),primary_key=True); organization_id=Column(String(36),nullable=False,index=True)
    framework_id=Column(String(120),nullable=False,index=True); framework_version=Column(String(40),nullable=False)
    created_at=Column(DateTime,nullable=False,index=True); created_by=Column(String(255),nullable=True)
    status=Column(String(20),nullable=False); evaluation_complete=Column(Boolean,nullable=False,default=True)
    endpoints_examined=Column(Integer,nullable=False); endpoint_count=Column(Integer,nullable=False)
    control_evaluation_count=Column(Integer,nullable=False); compliant_count=Column(Integer,nullable=False)
    non_compliant_count=Column(Integer,nullable=False); unknown_count=Column(Integer,nullable=False); not_applicable_count=Column(Integer,nullable=False)
    source_scope_type=Column(String(40),nullable=False,default='organization'); source_scope_reference_id=Column(String(36),nullable=True)
    snapshot_digest_sha256=Column(String(64),nullable=True)

class ComplianceSnapshotEndpointRecord(Base):
    __tablename__ = 'compliance_posture_snapshot_endpoints'
    snapshot_id=Column(String(36),ForeignKey('compliance_posture_snapshots.snapshot_id'),primary_key=True)
    endpoint_id=Column(String(36),primary_key=True); hostname=Column(String(255),nullable=False)
    platform=Column(String(100),nullable=False); lifecycle_status=Column(String(30),nullable=False); evaluation_count=Column(Integer,nullable=False)

class ComplianceSnapshotControlRecord(Base):
    __tablename__ = 'compliance_posture_snapshot_controls'
    snapshot_id=Column(String(36),ForeignKey('compliance_posture_snapshots.snapshot_id'),primary_key=True)
    endpoint_id=Column(String(36),primary_key=True); control_id=Column(String(120),primary_key=True)
    control_title=Column(String(255),nullable=False); capability=Column(String(30),nullable=False)
    status=Column(String(30),nullable=False); reason_code=Column(String(60),nullable=False); evaluated_at=Column(DateTime,nullable=False)
    source_assessment_id=Column(String(64),nullable=True); evidence_age_seconds=Column(Float,nullable=True); coverage_status=Column(String(30),nullable=True)


class SecurityAuditEventRecord(Base):
    """Append-only structured security history; sensitive values are redacted before persistence."""
    __tablename__ = 'security_audit_events'

    event_id = Column(String(36), primary_key=True)
    event_type = Column(String(100), nullable=False, index=True)
    occurred_at = Column(DateTime, nullable=False, index=True)
    principal_type = Column(String(30), nullable=False, index=True)
    principal_id = Column(String(255), nullable=False, index=True)
    principal_metadata = Column(JSON, nullable=False, default=dict)
    action = Column(String(100), nullable=True, index=True)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True, index=True)
    resource_metadata = Column(JSON, nullable=True)
    outcome = Column(String(20), nullable=False, index=True)
    reason_code = Column(String(100), nullable=True)
    correlation_id = Column(String(36), nullable=True, index=True)
    endpoint_id = Column(String(36), nullable=True, index=True)
    assessment_id = Column(String(64), nullable=True, index=True)
    work_id = Column(String(36), nullable=True, index=True)
    message_id = Column(String(36), nullable=True, index=True)
    # Tenancy is a first-class indexed column, not a JSON lookup: the audit feed
    # filters on it and an unindexed scan of an append-only log does not scale.
    # NULL means an unattributed/system event and is never returned to a tenant.
    organization_id = Column(String(36), nullable=True, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    event_metadata = Column(JSON, nullable=False, default=dict)


class UserRecord(Base):
    __tablename__ = 'users'
    user_id = Column(String(36), primary_key=True)
    email = Column(String(320), nullable=False, unique=True, index=True)
    display_name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    last_authenticated_at = Column(DateTime, nullable=True)
    user_metadata = Column(JSON, nullable=False, default=dict)


class UserCredentialRecord(Base):
    __tablename__ = 'user_credentials'
    credential_id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.user_id'), nullable=False, unique=True, index=True)
    credential_kind = Column(String(30), nullable=False)
    verifier = Column(String(512), nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)


class HumanSessionRecord(Base):
    __tablename__ = 'human_sessions'
    session_id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.user_id'), nullable=False, index=True)
    token_verifier = Column(String(512), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    authentication_method = Column(String(30), nullable=False)


class OrganizationRecord(Base):
    __tablename__ = 'organizations'
    organization_id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    organization_metadata = Column(JSON, nullable=False, default=dict)


class OrganizationMembershipRecord(Base):
    __tablename__ = 'organization_memberships'
    __table_args__ = (UniqueConstraint('user_id', 'organization_id', name='uq_organization_membership_user_org'),)
    membership_id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.user_id'), nullable=False, index=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=False, index=True)
    status = Column(String(20), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    membership_metadata = Column(JSON, nullable=False, default=dict)


class RoleRecord(Base):
    __tablename__ = 'roles'
    __table_args__ = (UniqueConstraint('organization_id', 'name', name='uq_role_organization_name'),)
    role_id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default='')
    permissions_json = Column(JSON, nullable=False, default=list)
    status = Column(String(20), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    role_metadata = Column(JSON, nullable=False, default=dict)


class RoleBindingRecord(Base):
    __tablename__ = 'role_bindings'
    __table_args__ = (UniqueConstraint('membership_id', 'role_id', name='uq_role_binding_membership_role'),)
    role_binding_id = Column(String(36), primary_key=True)
    organization_id = Column(String(36), ForeignKey('organizations.organization_id'), nullable=False, index=True)
    membership_id = Column(String(36), ForeignKey('organization_memberships.membership_id'), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey('roles.role_id'), nullable=False, index=True)
    status = Column(String(20), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    binding_metadata = Column(JSON, nullable=False, default=dict)
