"""Tenant-scoped organization and membership administration boundary."""
from ...domain.organization import MembershipId, OrganizationId
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource
from ...domain.user import UserId
from .context import OrganizationContext


class TenantOrganizationAdministrationService:
    """Small HUMAN-only facade over existing organization domain services.

    Routes use this facade instead of repositories, preserving explicit tenant
    scope and current RBAC evaluation for every operation.
    """
    def __init__(self, organization_service, membership_service, organization_repository,
                 membership_repository, authorizer):
        self.organizations = organization_service
        self.memberships = membership_service
        self.organization_repository = organization_repository
        self.membership_repository = membership_repository
        self.authorizer = authorizer

    def get_organization(self, principal, context):
        self._context(principal, context)
        self._require(principal, context, AuthorizationAction.ORGANIZATION_READ, "organization", str(context.organization_id))
        organization = self.organization_repository.get(context.organization_id)
        if organization is None:
            raise KeyError("organization not found")
        return organization

    def update_organization(self, principal, context, *, name=None, metadata=None):
        self._context(principal, context)
        self._require(principal, context, AuthorizationAction.ORGANIZATION_UPDATE, "organization", str(context.organization_id))
        return self.organizations.update(context.organization_id, name=name, metadata=metadata, principal=principal)

    def list_memberships(self, principal, context):
        self._context(principal, context)
        self._require(principal, context, AuthorizationAction.MEMBERSHIP_READ, "membership", None)
        return self.membership_repository.list_for_organization(context.organization_id)

    def create_membership(self, principal, context, user_id):
        self._context(principal, context)
        self._require(principal, context, AuthorizationAction.MEMBERSHIP_CREATE, "organization", str(context.organization_id))
        return self.memberships.create(UserId.parse(user_id), context.organization_id, principal=principal)

    def suspend_membership(self, principal, context, membership_id):
        membership = self._scoped_membership(principal, context, membership_id)
        self._require(principal, context, AuthorizationAction.MEMBERSHIP_SUSPEND, "membership", str(membership.membership_id))
        return self.memberships.suspend(membership.membership_id, principal=principal)

    def revoke_membership(self, principal, context, membership_id):
        membership = self._scoped_membership(principal, context, membership_id)
        self._require(principal, context, AuthorizationAction.MEMBERSHIP_REVOKE, "membership", str(membership.membership_id))
        return self.memberships.revoke(membership.membership_id, principal=principal)

    def _scoped_membership(self, principal, context, membership_id):
        self._context(principal, context)
        try:
            parsed_id = MembershipId.parse(membership_id)
        except (TypeError, ValueError):
            raise KeyError("membership not found")
        membership = self.membership_repository.get(parsed_id)
        if membership is None or membership.organization_id != context.organization_id:
            raise KeyError("membership not found")
        return membership

    @staticmethod
    def _context(principal, context):
        if principal.principal_type.value != "human" or not isinstance(context, OrganizationContext):
            raise PermissionError("human organization context required")

    def _require(self, principal, context, action, resource_type, resource_id):
        resource = AuthorizationResource(resource_type, resource_id, {"organization_id": str(context.organization_id)})
        decision = self.authorizer.authorize(AuthorizationRequest(principal, action, resource, organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
