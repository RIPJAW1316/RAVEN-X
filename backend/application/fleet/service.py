from ...domain.fleet import FleetQuery, FleetPage
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource

class TenantFleetQueryService:
    def __init__(self, endpoint_repository, authorizer, *, presence_repository=None, metrics=None):
        self.endpoints=endpoint_repository; self.authorizer=authorizer; self.presence=presence_repository; self.metrics=metrics
    def query(self, principal, context, query: FleetQuery):
        if principal.principal_type.value != "human" or context is None: raise PermissionError("human organization context required")
        decision=self.authorizer.authorize(AuthorizationRequest(principal, AuthorizationAction.ENDPOINT_READ, AuthorizationResource("endpoint", None, {"organization_id":str(context.organization_id)}), organization_context=context))
        if not decision.allowed: raise PermissionError(decision.reason_code)
        page=self.endpoints.query_for_organization(context.organization_id, query, presence_repository=self.presence)
        if self.metrics is not None: self.metrics.increment("fleet_query.requests")
        return page
