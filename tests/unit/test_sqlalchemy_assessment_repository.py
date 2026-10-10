"""Isolated SQLite tests for the local assessment repository adapter."""

from datetime import datetime

from sqlalchemy import select

from backend.core.database.database import DatabaseManager
from backend.core.database.models import Vulnerability
from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, Finding, FindingSeverity
from backend.infrastructure.persistence.sqlalchemy_assessment_repository import SQLAlchemyAssessmentRepository


def _manager(tmp_path):
    config_path = tmp_path / "repository.yaml"
    database_path = tmp_path / "repository.db"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  sqlite_path: '{database_path.as_posix()}'\n",
        encoding="utf-8",
    )
    manager = DatabaseManager(str(config_path))
    manager.initialize_sync_engine()
    manager.create_tables()
    return manager


def _target():
    return AssessmentTarget("local:test", "test-host", "Windows")


def _result(assessment_id, status=AssessmentStatus.COMPLETED):
    now = datetime.utcnow()
    if status is AssessmentStatus.FAILED:
        return AssessmentResult(assessment_id, _target(), status, now, now, error="scanner failed")
    finding = Finding(
        "finding-1",
        FindingSeverity.HIGH,
        "Firewall",
        "Windows Firewall Disabled",
        "The public profile is disabled.",
        "Windows Defender Firewall",
        "Enable the firewall.",
        legacy_metadata={"powershell_command": "Set-NetFirewallProfile -Enabled True"},
    )
    return AssessmentResult(assessment_id, _target(), status, now, now, findings=(finding,))


def test_repository_creates_completes_and_retrieves_assessment(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyAssessmentRepository(manager)
    assessment_id = "assessment-1"
    repository.create_assessment(assessment_id, "full", _target(), datetime.utcnow())
    repository.persist_completed(_result(assessment_id))

    persisted = repository.get(assessment_id)
    assert persisted.status == "completed"
    assert persisted.total_findings == 1

    with manager.get_db() as session:
        vulnerability = session.execute(select(Vulnerability).where(Vulnerability.scan_id == assessment_id)).scalar_one()
        assert vulnerability.powershell_command == "Set-NetFirewallProfile -Enabled True"

    manager.close()


def test_repository_marks_failure_and_preserves_error(tmp_path):
    manager = _manager(tmp_path)
    repository = SQLAlchemyAssessmentRepository(manager)
    assessment_id = "assessment-failed"
    repository.create_assessment(assessment_id, "full", _target(), datetime.utcnow())
    repository.mark_failed(assessment_id, datetime.utcnow(), "scanner failed")

    persisted = repository.get(assessment_id)
    assert persisted.status == "failed"
    assert persisted.error == "scanner failed"

    manager.close()
