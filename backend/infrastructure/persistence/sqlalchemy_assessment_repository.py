"""SQLAlchemy implementation of the small local-assessment repository port."""

from datetime import datetime
from typing import Optional

from ...application.ports.assessment_repository import PersistedAssessment
from ...core.database.database import DatabaseManager
from ...core.database.models import Scan
from ...domain.assessment import AssessmentResult, AssessmentTarget
from .mappers import apply_completed_result, scan_from_target, vulnerability_from_finding


class SQLAlchemyAssessmentRepository:
    def __init__(self, database_manager: DatabaseManager):
        self._database_manager = database_manager

    def create_assessment(
        self,
        assessment_id: str,
        scan_type: str,
        target: AssessmentTarget,
        started_at: datetime,
    ) -> None:
        with self._database_manager.get_db() as session:
            session.add(scan_from_target(assessment_id, scan_type, target, started_at))

    def persist_completed(self, result: AssessmentResult) -> None:
        with self._database_manager.get_db() as session:
            scan = session.get(Scan, result.assessment_id)
            if scan is None:
                raise KeyError(f"Assessment {result.assessment_id} was not created")
            if scan.status != "running":
                raise ValueError(f"Assessment {result.assessment_id} is not running")

            for finding in result.findings:
                session.add(vulnerability_from_finding(result.assessment_id, finding))
            apply_completed_result(scan, result)

    def mark_failed(self, assessment_id: str, finished_at: datetime, error: str) -> None:
        with self._database_manager.get_db() as session:
            scan = session.get(Scan, assessment_id)
            if scan is None:
                raise KeyError(f"Assessment {assessment_id} was not created")
            scan.status = "failed"
            scan.end_time = finished_at
            scan.duration_seconds = (finished_at - scan.start_time).total_seconds()

            system_info = dict(scan.system_info or {})
            system_info["assessment_error"] = error
            scan.system_info = system_info

    def get(self, assessment_id: str) -> Optional[PersistedAssessment]:
        with self._database_manager.get_db() as session:
            scan = session.get(Scan, assessment_id)
            if scan is None:
                return None
            return PersistedAssessment(
                assessment_id=scan.id,
                scan_type=scan.scan_type,
                status=scan.status,
                started_at=scan.start_time,
                finished_at=scan.end_time,
                total_findings=scan.total_vulnerabilities or 0,
                error=(scan.system_info or {}).get("assessment_error"),
            )
