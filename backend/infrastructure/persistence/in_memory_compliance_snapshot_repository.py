from copy import deepcopy
class InMemoryComplianceSnapshotRepository:
    def __init__(self): self.items={}
    def add(self,snapshot):
        if str(snapshot.snapshot_id) in self.items: raise ValueError("snapshot already exists")
        self.items[str(snapshot.snapshot_id)]=deepcopy(snapshot)
    def get_for_organization(self,snapshot_id,organization_id):
        value=self.items.get(str(snapshot_id)); return deepcopy(value) if value and str(value.organization_id)==str(organization_id) else None
    def list_for_organization(self,organization_id,framework_id=None,limit=50,offset=0):
        values=[x for x in self.items.values() if str(x.organization_id)==str(organization_id) and (framework_id is None or x.framework_id==str(framework_id))]
        values.sort(key=lambda x:(x.created_at,str(x.snapshot_id)),reverse=True); return tuple(deepcopy(values[offset:offset+limit]))
    def get_previous(self,snapshot):
        values=self.list_for_organization(snapshot.organization_id,snapshot.framework_id,limit=100000)
        return next((x for x in values if x.created_at < snapshot.created_at),None)
    def delete_for_retention(self, organization_id, snapshot_id):
        value = self.items.get(str(snapshot_id))
        if value is None or str(value.organization_id) != str(organization_id):
            return False
        del self.items[str(snapshot_id)]
        return True
    def list_organizations(self):
        return tuple(sorted({str(x.organization_id) for x in self.items.values()}))
