from copy import deepcopy
from ...domain.group_scope import EndpointGroup, SavedFleetScope, EndpointGroupSummary
class InMemoryEndpointGroupRepository:
    def __init__(self): self.groups={}; self.members={}
    def add(self,g):
        if str(g.group_id) in self.groups: raise ValueError("group already exists")
        if any(x.organization_id==g.organization_id and x.name.casefold()==g.name.casefold() and x.status.value=="active" for x in self.groups.values()): raise ValueError("group name already exists")
        self.groups[str(g.group_id)]=deepcopy(g); self.members[str(g.group_id)]=set()
    def get(self,i): return deepcopy(self.groups.get(str(i)))
    def update(self,g): self.groups[str(g.group_id)]=deepcopy(g)
    def list_for_organization(self,o): return tuple(EndpointGroupSummary(g,len(self.members.get(str(g.group_id),()))) for g in self.groups.values() if str(g.organization_id)==str(o))
    def add_members(self,g,endpoint_ids,added_by=None,organization_id=None):
        self.members.setdefault(str(g),set()).update(str(x) for x in endpoint_ids)
    def remove_members(self,g,endpoint_ids): self.members.setdefault(str(g),set()).difference_update(str(x) for x in endpoint_ids)
    def list_members(self,g,limit=50,offset=0): return tuple(sorted(self.members.get(str(g),())))[offset:offset+limit]
    def contains(self,g,e): return str(e) in self.members.get(str(g),set())
    def count(self,g): return len(self.members.get(str(g),set()))

class InMemorySavedFleetScopeRepository:
    def __init__(self): self.items={}
    def add(self,s): self.items[str(s.scope_id)]=deepcopy(s)
    def get(self,i): return deepcopy(self.items.get(str(i)))
    def update(self,s): self.items[str(s.scope_id)]=deepcopy(s)
    def list_for_organization(self,o): return tuple(x for x in self.items.values() if str(x.organization_id)==str(o))
