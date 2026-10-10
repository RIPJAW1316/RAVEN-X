from copy import deepcopy
from ...domain.organization import MembershipId, OrganizationId, OrganizationMembership
from ...domain.user import UserId
from ...application.ports.membership_repository import DuplicateMembershipError
class InMemoryOrganizationMembershipRepository:
    def __init__(self): self._items={}
    def add(self,membership):
        if self.get_for_user_and_organization(membership.user_id,membership.organization_id) is not None: raise DuplicateMembershipError("membership already exists")
        key=MembershipId.parse(membership.membership_id)
        if key in self._items: raise DuplicateMembershipError("membership already exists")
        self._items[key]=deepcopy(membership)
    def get(self,membership_id): return deepcopy(self._items.get(MembershipId.parse(membership_id)))
    def get_for_user_and_organization(self,user_id,organization_id):
        uid=UserId.parse(user_id); oid=OrganizationId.parse(organization_id)
        return next((deepcopy(x) for x in self._items.values() if x.user_id==uid and x.organization_id==oid),None)
    def list_for_user(self,user_id):
        uid=UserId.parse(user_id); return tuple(deepcopy(x) for x in sorted(self._items.values(),key=lambda x:(x.created_at,str(x.membership_id))) if x.user_id==uid)
    def list_for_organization(self,organization_id):
        oid=OrganizationId.parse(organization_id); return tuple(deepcopy(x) for x in sorted(self._items.values(),key=lambda x:(x.created_at,str(x.membership_id))) if x.organization_id==oid)
    def update(self,membership):
        key=MembershipId.parse(membership.membership_id)
        if key not in self._items: raise KeyError("membership does not exist")
        self._items[key]=deepcopy(membership)
    def exists(self,membership_id): return MembershipId.parse(membership_id) in self._items

InMemoryMembershipRepository = InMemoryOrganizationMembershipRepository
