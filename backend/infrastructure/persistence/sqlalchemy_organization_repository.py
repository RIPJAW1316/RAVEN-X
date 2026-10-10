from datetime import timezone
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from ...application.ports.organization_repository import DuplicateOrganizationError
from ...core.database.models import OrganizationRecord
from ...domain.organization import Organization, OrganizationId, OrganizationStatus

def _store(value): return value.astimezone(timezone.utc).replace(tzinfo=None)
def _load(value): return value.replace(tzinfo=timezone.utc)
def _domain(record):
    if record is None: return None
    return Organization(OrganizationId(record.organization_id),record.name,OrganizationStatus(record.status),_load(record.created_at),_load(record.updated_at),record.organization_metadata or {})

class SQLAlchemyOrganizationRepository:
    def __init__(self,database_manager): self._database_manager=database_manager
    def add(self,organization):
        try:
            with self._database_manager.get_db() as s:
                s.add(OrganizationRecord(organization_id=str(organization.organization_id),name=organization.name,status=organization.status.value,created_at=_store(organization.created_at),updated_at=_store(organization.updated_at),organization_metadata=dict(organization.metadata))); s.flush()
        except IntegrityError as error: raise DuplicateOrganizationError("organization already exists") from error
    def get(self,organization_id):
        with self._database_manager.get_db() as s: return _domain(s.get(OrganizationRecord,str(OrganizationId.parse(organization_id))))
    def list(self,status=None):
        with self._database_manager.get_db() as s:
            q=select(OrganizationRecord).order_by(OrganizationRecord.created_at,OrganizationRecord.organization_id)
            if status is not None: q=q.where(OrganizationRecord.status==OrganizationStatus(status).value)
            return tuple(_domain(x) for x in s.execute(q).scalars())
    def update(self,organization):
        with self._database_manager.get_db() as s:
            r=s.get(OrganizationRecord,str(organization.organization_id))
            if r is None: raise KeyError("organization does not exist")
            r.name=organization.name; r.status=organization.status.value; r.updated_at=_store(organization.updated_at); r.organization_metadata=dict(organization.metadata)
    def exists(self,organization_id):
        with self._database_manager.get_db() as s: return s.get(OrganizationRecord,str(OrganizationId.parse(organization_id))) is not None
