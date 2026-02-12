# backend/core/database/models.py
from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Boolean, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

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
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'))
    severity = Column(String(20))
    category = Column(String(50))
    title = Column(String(255))
    details = Column(Text)
    component = Column(String(100))
    remediation = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # For pattern learning
    signature = Column(String(255), nullable=True)  # Hash/signature of the issue
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