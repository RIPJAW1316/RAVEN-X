from copy import deepcopy
from ...domain.organization import MembershipId, OrganizationId
from ...domain.rbac import Role, RoleBinding, RoleBindingId, RoleId
from ...application.ports.rbac_repository import DuplicateRoleBindingError, DuplicateRoleError

class InMemoryRoleRepository:
    def __init__(self): self._items={}
    def add(self,role):
        if any(x.organization_id==role.organization_id and x.name.casefold()==role.name.casefold() for x in self._items.values()): raise DuplicateRoleError("role name already exists in organization")
        key=RoleId.parse(role.role_id)
        if key in self._items: raise DuplicateRoleError("role already exists")
        self._items[key]=deepcopy(role)
    def get(self,role_id): return deepcopy(self._items.get(RoleId.parse(role_id)))
    def list_for_organization(self,organization_id):
        oid=OrganizationId.parse(organization_id); return tuple(deepcopy(x) for x in sorted(self._items.values(),key=lambda x:(x.created_at,str(x.role_id))) if x.organization_id==oid)
    def update(self,role):
        key=RoleId.parse(role.role_id)
        if key not in self._items: raise KeyError("role does not exist")
        if any(x.role_id!=key and x.organization_id==role.organization_id and x.name.casefold()==role.name.casefold() for x in self._items.values()): raise DuplicateRoleError("role name already exists in organization")
        self._items[key]=deepcopy(role)
    def exists(self,role_id): return RoleId.parse(role_id) in self._items

class InMemoryRoleBindingRepository:
    def __init__(self): self._items={}
    def add(self,binding):
        if any(x.membership_id==binding.membership_id and x.role_id==binding.role_id for x in self._items.values()): raise DuplicateRoleBindingError("role binding already exists")
        key=RoleBindingId.parse(binding.role_binding_id)
        if key in self._items: raise DuplicateRoleBindingError("role binding already exists")
        self._items[key]=deepcopy(binding)
    def get(self,binding_id): return deepcopy(self._items.get(RoleBindingId.parse(binding_id)))
    def list_for_membership(self,membership_id):
        mid=MembershipId.parse(membership_id); return tuple(deepcopy(x) for x in sorted(self._items.values(),key=lambda x:(x.created_at,str(x.role_binding_id))) if x.membership_id==mid)
    def list_for_role(self,role_id):
        rid=RoleId.parse(role_id); return tuple(deepcopy(x) for x in sorted(self._items.values(),key=lambda x:(x.created_at,str(x.role_binding_id))) if x.role_id==rid)
    def update(self,binding):
        key=RoleBindingId.parse(binding.role_binding_id)
        if key not in self._items: raise KeyError("role binding does not exist")
        self._items[key]=deepcopy(binding)
    def exists(self,binding_id): return RoleBindingId.parse(binding_id) in self._items

InMemoryRBACRoleRepository=InMemoryRoleRepository
InMemoryRBACRoleBindingRepository=InMemoryRoleBindingRepository
