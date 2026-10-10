"""Organization-scoped remote assessment application boundary."""
from typing import Optional

from ...domain.endpoint import EndpointId
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, SecurityPrincipal
from ..organization.context import OrganizationContext


class TenantAssessmentService:
    """Human assessment operations rooted at a tenant-owned endpoint."""
    def __init__(self, endpoint_repository, assessments, dispatcher, authorizer, *, cancellation_service=None):
        self.endpoint_repository = endpoint_repository
        self.assessments = assessments
        self.dispatcher = dispatcher
        self.authorizer = authorizer
        self.cancellation_service = cancellation_service

    def create_assessment(self, principal: SecurityPrincipal, context: OrganizationContext,
                          endpoint_id: EndpointId, scanner_ids, *, requested_at=None):
        self._context(principal, context)
        endpoint = self.endpoint_repository.get_for_organization(endpoint_id, context.organization_id)
        if endpoint is None:
            raise KeyError("endpoint not found")
        self._require(principal, context, AuthorizationAction.ASSESSMENT_CREATE, None)
        return self.dispatcher.dispatch(endpoint.endpoint_id, tuple(scanner_ids), requested_at=requested_at,
                                         principal=principal, organization_context=context)

    def get_assessment(self, principal: SecurityPrincipal, context: OrganizationContext, assessment_id: str):
        self._context(principal, context)
        assessment = self.assessments.get_for_organization(assessment_id, context.organization_id)
        if assessment is None:
            raise KeyError("assessment not found")
        self._require(principal, context, AuthorizationAction.ASSESSMENT_READ, assessment_id)
        return assessment

    def list_assessments(self, principal: SecurityPrincipal, context: OrganizationContext):
        self._context(principal, context)
        self._require(principal, context, AuthorizationAction.ASSESSMENT_READ, None)
        return self.assessments.list_for_organization(context.organization_id)

    def get_result(self, principal: SecurityPrincipal, context: OrganizationContext, assessment_id: str):
        return self.get_assessment(principal, context, assessment_id).result

    def cancel(self, principal: SecurityPrincipal, context: OrganizationContext, assessment_id: str, *, now=None):
        self._context(principal, context)
        assessment = self.assessments.get_for_organization(assessment_id, context.organization_id)
        if assessment is None:
            raise KeyError("assessment not found")
        self._require(principal, context, AuthorizationAction.ASSESSMENT_CANCEL, assessment_id)
        if self.cancellation_service is None:
            raise RuntimeError("assessment cancellation is not configured")
        return self.cancellation_service.cancel(assessment_id, endpoint_id=assessment.endpoint_id, now=now,
                                                 principal=principal, organization_context=context)

    def create_scheduled_assessment(self, endpoint_id, scanner_ids, organization_id, *, requested_at=None, schedule_id=None):
        """Internal SYSTEM path used only by the bounded schedule runner."""
        return self.dispatcher.dispatch(endpoint_id, tuple(scanner_ids), requested_at=requested_at,
                                         principal=SecurityPrincipal.system(), organization_context=None, schedule_id=schedule_id)

    @staticmethod
    def _context(principal, context):
        if principal.principal_type.value != "human":
            raise PermissionError("human principal required")
        if not isinstance(context, OrganizationContext):
            raise PermissionError("organization context required")

    def _require(self, principal, context, action, assessment_id):
        resource = AuthorizationResource("assessment", assessment_id,
                                         {"organization_id": str(context.organization_id)})
        decision = self.authorizer.authorize(AuthorizationRequest(principal, action, resource,
                                                                   organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
