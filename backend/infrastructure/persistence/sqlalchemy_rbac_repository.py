from datetime import timezone
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from ...application.ports.rbac_repository import DuplicateRoleBindingError, DuplicateRoleError
from ...core.database.models import RoleBindingRecord, RoleRecord
from ...domain.organization import MembershipId, OrganizationId
from ...domain.rbac import Permission, Role, RoleBinding, RoleBindingId, RoleBindingStatus, RoleId, RoleStatus

def _store(value): return value.astimezone(timezone.utc).replace(tzinfo=None)
def _load(value): return value.replace(tzinfo=timezone.utc)
def _role(record):
    if record is None:return None
    return Role(RoleId(record.role_id),OrganizationId(record.organization_id),record.name,record.description or "",frozenset(Permission(x) for x in (record.permissions_json or [])),RoleStatus(record.status),_load(record.created_at),_load(record.updated_at),record.role_metadata or {})
def _binding(record):
    if record is None:return None
    return RoleBinding(RoleBindingId(record.role_binding_id),OrganizationId(record.organization_id),MembershipId(record.membership_id),RoleId(record.role_id),RoleBindingStatus(record.status),_load(record.created_at),_load(record.updated_at),record.binding_metadata or {})

class SQLAlchemyRoleRepository:
    def __init__(self,database_manager): self._database_manager=database_manager
    def add(self,role):
        try:
            with self._database_manager.get_db() as s:
                duplicate=s.execute(select(RoleRecord.role_id).where(RoleRecord.organization_id==str(role.organization_id),func.lower(RoleRecord.name)==role.name.casefold())).first()
                if duplicate: raise DuplicateRoleError("role name already exists in organization")
                s.add(RoleRecord(role_id=str(role.role_id),organization_id=str(role.organization_id),name=role.name,description=role.description,permissions_json=sorted(str(x) for x in role.permissions),status=role.status.value,created_at=_store(role.created_at),updated_at=_store(role.updated_at),role_metadata=dict(role.metadata))); s.flush()
        except IntegrityError as error: raise DuplicateRoleError("role already exists") from error
    def get(self,role_id):
        with self._database_manager.get_db() as s:return _role(s.get(RoleRecord,str(RoleId.parse(role_id))))
    def list_for_organization(self,organization_id):
        with self._database_manager.get_db() as s:return tuple(_role(x) for x in s.execute(select(RoleRecord).where(RoleRecord.organization_id==str(OrganizationId.parse(organization_id))).order_by(RoleRecord.created_at,RoleRecord.role_id)).scalars())
    def update(self,role):
        with self._database_manager.get_db() as s:
            r=s.get(RoleRecord,str(role.role_id))
            if r is None:raise KeyError("role does not exist")
            duplicate=s.execute(select(RoleRecord.role_id).where(RoleRecord.organization_id==str(role.organization_id),func.lower(RoleRecord.name)==role.name.casefold(),RoleRecord.role_id!=str(role.role_id))).first()
            if duplicate: raise DuplicateRoleError("role name already exists in organization")
            r.name=role.name;r.description=role.description;r.permissions_json=sorted(str(x) for x in role.permissions);r.status=role.status.value;r.updated_at=_store(role.updated_at);r.role_metadata=dict(role.metadata);s.flush()
    def exists(self,role_id):
        with self._database_manager.get_db() as s:return s.get(RoleRecord,str(RoleId.parse(role_id))) is not None

class SQLAlchemyRoleBindingRepository:
    def __init__(self,database_manager): self._database_manager=database_manager
    def add(self,binding):
        try:
            with self._database_manager.get_db() as s:
                s.add(RoleBindingRecord(role_binding_id=str(binding.role_binding_id),organization_id=str(binding.organization_id),membership_id=str(binding.membership_id),role_id=str(binding.role_id),status=binding.status.value,created_at=_store(binding.created_at),updated_at=_store(binding.updated_at),binding_metadata=dict(binding.metadata)));s.flush()
        except IntegrityError as error: raise DuplicateRoleBindingError("role binding already exists") from error
    def get(self,binding_id):
        with self._database_manager.get_db() as s:return _binding(s.get(RoleBindingRecord,str(RoleBindingId.parse(binding_id))))
    def list_for_membership(self,membership_id): return self._list(RoleBindingRecord.membership_id==str(MembershipId.parse(membership_id)))
    def list_for_role(self,role_id): return self._list(RoleBindingRecord.role_id==str(RoleId.parse(role_id)))
    def _list(self,criterion):
        with self._database_manager.get_db() as s:return tuple(_binding(x) for x in s.execute(select(RoleBindingRecord).where(criterion).order_by(RoleBindingRecord.created_at,RoleBindingRecord.role_binding_id)).scalars())
    def update(self,binding):
        with self._database_manager.get_db() as s:
            r=s.get(RoleBindingRecord,str(binding.role_binding_id))
            if r is None:raise KeyError("role binding does not exist")
            r.status=binding.status.value;r.updated_at=_store(binding.updated_at);r.binding_metadata=dict(binding.metadata)
    def exists(self,binding_id):
        with self._database_manager.get_db() as s:return s.get(RoleBindingRecord,str(RoleBindingId.parse(binding_id))) is not None

SQLAlchemyRBACRoleRepository=SQLAlchemyRoleRepository
SQLAlchemyRBACRoleBindingRepository=SQLAlchemyRoleBindingRepository
