from datetime import timezone
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from ...application.ports.membership_repository import DuplicateMembershipError
from ...core.database.models import OrganizationMembershipRecord
from ...domain.organization import MembershipId, MembershipStatus, OrganizationId, OrganizationMembership
from ...domain.user import UserId

def _store(value): return value.astimezone(timezone.utc).replace(tzinfo=None)
def _load(value): return value.replace(tzinfo=timezone.utc)
def _domain(record):
    if record is None: return None
    return OrganizationMembership(MembershipId(record.membership_id),UserId.parse(record.user_id),OrganizationId(record.organization_id),MembershipStatus(record.status),_load(record.created_at),_load(record.updated_at),record.membership_metadata or {})

class SQLAlchemyOrganizationMembershipRepository:
    def __init__(self,database_manager): self._database_manager=database_manager
    def add(self,membership):
        try:
            with self._database_manager.get_db() as s:
                existing=s.execute(select(OrganizationMembershipRecord.membership_id).where(OrganizationMembershipRecord.user_id==str(membership.user_id),OrganizationMembershipRecord.organization_id==str(membership.organization_id))).first()
                if existing: raise DuplicateMembershipError("membership already exists")
                s.add(OrganizationMembershipRecord(membership_id=str(membership.membership_id),user_id=str(membership.user_id),organization_id=str(membership.organization_id),status=membership.status.value,created_at=_store(membership.created_at),updated_at=_store(membership.updated_at),membership_metadata=dict(membership.metadata))); s.flush()
        except IntegrityError as error: raise DuplicateMembershipError("membership already exists") from error
    def get(self,membership_id):
        with self._database_manager.get_db() as s: return _domain(s.get(OrganizationMembershipRecord,str(MembershipId.parse(membership_id))))
    def get_for_user_and_organization(self,user_id,organization_id):
        with self._database_manager.get_db() as s: return _domain(s.execute(select(OrganizationMembershipRecord).where(OrganizationMembershipRecord.user_id==str(UserId.parse(user_id)),OrganizationMembershipRecord.organization_id==str(OrganizationId.parse(organization_id)))).scalar_one_or_none())
    def list_for_user(self,user_id): return self._list(OrganizationMembershipRecord.user_id==str(UserId.parse(user_id)))
    def list_for_organization(self,organization_id): return self._list(OrganizationMembershipRecord.organization_id==str(OrganizationId.parse(organization_id)))
    def _list(self,criterion):
        with self._database_manager.get_db() as s: return tuple(_domain(x) for x in s.execute(select(OrganizationMembershipRecord).where(criterion).order_by(OrganizationMembershipRecord.created_at,OrganizationMembershipRecord.membership_id)).scalars())
    def update(self,membership):
        with self._database_manager.get_db() as s:
            r=s.get(OrganizationMembershipRecord,str(membership.membership_id))
            if r is None: raise KeyError("membership does not exist")
            r.status=membership.status.value; r.updated_at=_store(membership.updated_at); r.membership_metadata=dict(membership.metadata)
    def exists(self,membership_id):
        with self._database_manager.get_db() as s: return s.get(OrganizationMembershipRecord,str(MembershipId.parse(membership_id))) is not None

SQLAlchemyMembershipRepository = SQLAlchemyOrganizationMembershipRepository
