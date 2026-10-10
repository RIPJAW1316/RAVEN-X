from dataclasses import dataclass
from ...domain.organization import MembershipStatus, OrganizationId, OrganizationStatus
from ...domain.rbac import RoleBindingStatus, RoleStatus
from ...domain.security import AuthorizationDecision, AuthorizationRequest, AuthorizationResource, PrincipalType, SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal
from ...application.ports.control_plane_authorization import ConservativeControlPlaneAuthorizer
from .audit_policy import AuthorizationAuditPolicy, DEFAULT_AUTHORIZATION_AUDIT_POLICY

class EffectivePermissionResolver:
    def __init__(self,membership_repository,role_binding_repository,role_repository):self.membership_repository=membership_repository;self.role_binding_repository=role_binding_repository;self.role_repository=role_repository
    def permissions_for(self,membership_id,organization_id):
        permissions=set();bindings=self.role_binding_repository.list_for_membership(membership_id)
        for binding in bindings:
            if binding.status is not RoleBindingStatus.ACTIVE or binding.organization_id!=organization_id:continue
            role=self.role_repository.get(binding.role_id)
            if role is not None and role.status is RoleStatus.ACTIVE and role.organization_id==organization_id:permissions.update(str(x) for x in role.permissions)
        return frozenset(permissions)
    resolve = permissions_for
    effective_permissions = permissions_for

class OrganizationRbacAuthorizer:
    def __init__(self,*,membership_repository,role_binding_repository,role_repository,organization_repository,endpoint_repository=None,base_authorizer=None,audit_sink=None,audit_policy=None,telemetry=None):
        self.membership_repository=membership_repository;self.role_binding_repository=role_binding_repository;self.role_repository=role_repository;self.organization_repository=organization_repository;self.endpoint_repository=endpoint_repository;self.base_authorizer=base_authorizer or ConservativeControlPlaneAuthorizer();self.audit_sink=audit_sink;self.audit_policy=audit_policy or DEFAULT_AUTHORIZATION_AUDIT_POLICY;self.telemetry=telemetry;self.permissions=EffectivePermissionResolver(membership_repository,role_binding_repository,role_repository)
    def authorize(self,request):
        if request.principal.principal_type is not PrincipalType.HUMAN:return self.base_authorizer.authorize(request)
        context=request.organization_context
        # Denials before this point carry no attribution: the organization the
        # caller *claims* is unverified, and attributing an event to it would
        # let an unauthenticated caller inject records into another tenant's
        # audit feed.  Attribution is added only once membership and
        # organization have been read back and validated from the repositories.
        if not context:return self._deny(request,"organization_context_required")
        try:user_id=str(context["user_id"]);organization_id=OrganizationId.parse(context["organization_id"]);membership_id=str(context["membership_id"])
        except (KeyError,TypeError,ValueError):return self._deny(request,"invalid_organization_context")
        if request.principal.principal_id!=user_id:return self._deny(request,"principal_context_mismatch")
        membership=self.membership_repository.get(membership_id);organization=self.organization_repository.get(organization_id)
        if membership is None or str(membership.user_id)!=user_id or membership.organization_id!=organization_id:return self._deny(request,"membership_context_mismatch")
        # Membership is now server-verified against the repository, so the
        # organization is safe to attribute on subsequent denials.
        verified=_Attribution(user_id,str(organization_id),membership_id)
        if membership.status is not MembershipStatus.ACTIVE:return self._deny(request,"membership_inactive",verified)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:return self._deny(request,"organization_inactive",verified)
        scoped=self._resource_scope(request.resource, str(organization_id))
        if scoped is not None and scoped!=str(organization_id):return self._deny(request,"resource_organization_mismatch",verified)
        action_value=request.action.value if hasattr(request.action,"value") else str(request.action)
        if action_value not in self.permissions.permissions_for(membership_id,organization_id):return self._deny(request,"permission_not_granted",verified)
        decision=AuthorizationDecision(True)
        # A successful permission check is an implementation detail, not an
        # audit record: the operation that follows writes its own event.  It is
        # still counted, because volume and rate are exactly the questions
        # telemetry should answer.  See audit_policy.AuthorizationAuditPolicy
        # and docs/architecture/security-observability.md.
        self._telemetry(True, action_value, None, str(organization_id))
        if self.audit_sink and self.audit_policy.should_record_success(action_value):
            self.audit_sink.append(SecurityAuditEvent(event_type=SecurityAuditEventType.AUTHORIZATION_ALLOWED.value,principal=request.principal,action=request.action,resource=request.resource,outcome=SecurityAuditOutcome.SUCCESS,user_id=user_id,organization_id=str(organization_id),membership_id=membership_id))
        return decision
    def _resource_scope(self,resource, context_organization_id=None):
        if resource.resource_type=="endpoint":
            if self.endpoint_repository is not None and resource.resource_id:
                context_org = context_organization_id or resource.metadata.get("organization_id")
                item = self.endpoint_repository.get_for_organization(resource.resource_id, context_org) if context_org else None
                # A scoped miss is intentionally not treated as a metadata-only
                # claim: the caller must not turn an IDOR into an allow decision.
                return str(item.organization_id) if item is not None and item.organization_id is not None else "__unresolved_endpoint__"
            return resource.metadata.get("organization_id")
        if resource.resource_type=="organization":return resource.resource_id
        if resource.resource_type=="membership":
            item=self.membership_repository.get(resource.resource_id) if resource.resource_id else None
            return str(item.organization_id) if item else resource.metadata.get("organization_id")
        if resource.resource_type=="role":
            item=self.role_repository.get(resource.resource_id) if resource.resource_id else None
            return str(item.organization_id) if item else resource.metadata.get("organization_id")
        if resource.resource_type=="role_binding":
            item=self.role_binding_repository.get(resource.resource_id) if resource.resource_id else None
            return str(item.organization_id) if item else resource.metadata.get("organization_id")
        return resource.metadata.get("organization_id")
    def _deny(self,request,reason,attribution=None):
        """Record a denial.  Never suppressed by policy: a denial is evidence a
        control rejected something, and a burst of them indicates probing.

        ``attribution`` is supplied only when the membership and organization
        were verified server-side, so a caller can never cause an event to be
        written into a tenant it does not belong to."""
        decision=AuthorizationDecision(False,reason,reason)
        action_value=request.action.value if hasattr(request.action,"value") else str(request.action)
        self._telemetry(False,action_value,reason,attribution.organization_id if attribution else None)
        if self.audit_sink:
            self.audit_sink.append(SecurityAuditEvent(
                event_type=SecurityAuditEventType.AUTHORIZATION_DENIED.value,
                principal=request.principal,action=request.action,resource=request.resource,
                outcome=SecurityAuditOutcome.DENIED,reason_code=reason,
                user_id=attribution.user_id if attribution else None,
                organization_id=attribution.organization_id if attribution else None,
                membership_id=attribution.membership_id if attribution else None))
        return decision
    def _telemetry(self,allowed,action,reason,organization_id):
        """Count the evaluation.  ``organization_id`` is passed only when it was
        verified server-side, so an unverified caller cannot attribute its own
        traffic to another tenant's telemetry."""
        if self.telemetry is None: return
        try:
            self.telemetry.record_authorization(organization_id=organization_id,allowed=allowed,action=action,reason_code=reason)
        except Exception:
            # Telemetry must never be able to fail an authorization decision.
            pass


@dataclass(frozen=True)
class _Attribution:
    """Server-verified identity for an audit record.  Never built from caller
    input alone; only from repository reads that already matched."""
    user_id: str
    organization_id: str
    membership_id: str
