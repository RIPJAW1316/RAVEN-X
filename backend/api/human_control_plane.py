"""Small human-facing control-plane HTTP boundary.

The router is deliberately composed from application services.  It does not
perform global endpoint/assessment lookups and it never shares authentication
with the machine-agent router.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import re
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..application.identity.service import AuthenticationFailure
from ..application.organization.context import OrganizationContextError
from ..domain.enrollment import EnrollmentStatus
from ..domain.endpoint import EndpointId
from ..domain.security import SecurityPrincipal
from ..domain.security import SecurityAuditEvent, SecurityAuditEventType, SecurityAuditOutcome


@dataclass(frozen=True)
class HumanRequestContext:
    principal: SecurityPrincipal
    session: object
    organization_context: Optional[object] = None


@dataclass(frozen=True)
class HumanControlPlaneDependencies:
    authentication_service: object
    session_authenticator: object
    user_repository: object
    context_resolver: object
    endpoint_service: object
    assessment_service: object
    organization_repository: object = None
    membership_repository: object = None
    organization_admin_service: object = None
    login_rate_limiter: object = None
    audit_sink: object = None
    metrics: object = None
    presence_service: object = None
    fleet_presence_service: object = None
    security_overview_service: object = None
    assessment_detail_service: object = None
    finding_recurrence_service: object = None
    finding_coverage_service: object = None
    schedule_service: object = None
    fleet_query_service: object = None
    endpoint_group_service: object = None
    fleet_scope_service: object = None
    schedule_run_repository: object = None
    compliance_service: object = None
    compliance_snapshot_service: object = None
    audit_query_service: object = None
    security_observability_service: object = None
    enrollment_service: object = None


def create_human_control_plane_router(dependencies: HumanControlPlaneDependencies) -> APIRouter:
    """Create the human auth and tenant-safe routers from explicit services."""
    router = APIRouter()

    def authenticate_human(authorization: Optional[str] = Header(default=None)) -> HumanRequestContext:
        token = _bearer_token(authorization)
        try:
            principal = dependencies.session_authenticator.authenticate_bearer(token)
        except (AuthenticationFailure, ValueError, KeyError):
            # Deliberately identical response for missing, unknown, expired,
            # revoked, and user-disabled sessions.
            raise _http_error(401, "INVALID_SESSION", "human authentication failed")
        session = dependencies.user_repository.get_session_for_token(token)
        if session is None:  # defensive: avoid returning a principal without its session
            raise _http_error(401, "INVALID_SESSION", "human authentication failed")
        return HumanRequestContext(principal, session)

    def organization_context(organization_id: str, human: HumanRequestContext = Depends(authenticate_human)) -> HumanRequestContext:
        try:
            context = dependencies.context_resolver.resolve(human.principal, organization_id)
        except (OrganizationContextError, ValueError, KeyError):
            # Do not disclose whether an organization exists or whether the
            # caller lacks membership.
            raise _http_error(403, "ORGANIZATION_ACCESS_DENIED", "organization context is unavailable")
        return HumanRequestContext(human.principal, human.session, context)

    @router.post("/auth/login", tags=["Human Authentication"])
    async def login(request: Request):
        body = await _json_body(request)
        email, password = body.get("email"), body.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            raise _http_error(422, "INVALID_REQUEST", "email and password are required")
        limiter = dependencies.login_rate_limiter
        rate_key = _login_rate_key(request, email)
        if limiter is not None:
            decision = limiter.check(rate_key)
            if not decision.allowed:
                _metric(dependencies.metrics, "http.login.rate_limited")
                _audit_rate_limit(dependencies.audit_sink, request, rate_key)
                error = _http_error(429, "RATE_LIMITED", "too many login attempts")
                error.headers = {"Retry-After": str(decision.retry_after)}
                raise error
        try:
            result = dependencies.authentication_service.authenticate(email, password)
        except (AuthenticationFailure, ValueError):
            _metric(dependencies.metrics, "http.login.failure")
            raise _http_error(401, "INVALID_CREDENTIALS", "invalid credentials")
        if limiter is not None:
            limiter.reset(rate_key)
        _metric(dependencies.metrics, "http.login.success")
        return {"session_token": result.session_token, "expires_at": result.session.expires_at.astimezone(timezone.utc).isoformat()}

    @router.post("/auth/logout", tags=["Human Authentication"])
    async def logout(human: HumanRequestContext = Depends(authenticate_human)):
        try:
            dependencies.session_authenticator.revoke_session(human.session.session_id, principal=human.principal)
        except (AuthenticationFailure, KeyError, ValueError):
            raise _http_error(401, "INVALID_SESSION", "human authentication failed")
        return {"status": "revoked"}

    @router.get("/auth/me", tags=["Human Authentication"])
    async def me(human: HumanRequestContext = Depends(authenticate_human)):
        user = dependencies.user_repository.get_user(human.principal.principal_id)
        if user is None:
            raise _http_error(401, "INVALID_SESSION", "human authentication failed")
        return {"user_id": str(user.user_id), "email": user.email, "display_name": user.display_name, "status": user.status.value}

    @router.get("/auth/organizations", tags=["Human Authentication"])
    async def selectable_organizations(human: HumanRequestContext = Depends(authenticate_human)):
        if dependencies.membership_repository is None or dependencies.organization_repository is None:
            raise _http_error(503, "CONTROL_PLANE_UNAVAILABLE", "organization discovery is unavailable")
        result = []
        for membership in dependencies.membership_repository.list_for_user(human.principal.principal_id):
            organization = dependencies.organization_repository.get(membership.organization_id)
            if organization is not None and membership.status.value == "active" and organization.status.value == "active":
                result.append({"organization_id": str(organization.organization_id), "name": organization.name,
                               "membership_id": str(membership.membership_id)})
        return result

    @router.get("/organizations/{organization_id}", tags=["Organization Administration"])
    async def get_organization(context: HumanRequestContext = Depends(organization_context)):
        try:
            return _organization_response(dependencies.organization_admin_service.get_organization(context.principal, context.organization_context))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/memberships", tags=["Organization Administration"])
    async def list_memberships(context: HumanRequestContext = Depends(organization_context)):
        try:
            return [_membership_response(item) for item in dependencies.organization_admin_service.list_memberships(context.principal, context.organization_context)]
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/memberships", tags=["Organization Administration"])
    async def create_membership(request: Request, context: HumanRequestContext = Depends(organization_context)):
        body = await _json_body(request)
        if set(body) != {"user_id"} or not isinstance(body.get("user_id"), str):
            raise _http_error(422, "INVALID_REQUEST", "user_id is required")
        try:
            return _membership_response(dependencies.organization_admin_service.create_membership(context.principal, context.organization_context, body["user_id"]))
        except KeyError:
            # The caller may manage this organization but must not use this
            # endpoint as a global user-discovery API.
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError:
            raise _http_error(409, "CONFLICT", "membership already exists or is invalid")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/memberships/{membership_id}/suspend", tags=["Organization Administration"])
    async def suspend_membership(membership_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            return _membership_response(dependencies.organization_admin_service.suspend_membership(context.principal, context.organization_context, membership_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError:
            raise _http_error(409, "CONFLICT", "membership lifecycle conflict")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/memberships/{membership_id}/revoke", tags=["Organization Administration"])
    async def revoke_membership(membership_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            return _membership_response(dependencies.organization_admin_service.revoke_membership(context.principal, context.organization_context, membership_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError:
            raise _http_error(409, "CONFLICT", "membership lifecycle conflict")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/endpoints", tags=["Tenant Endpoints"])
    async def list_endpoints(context: HumanRequestContext = Depends(organization_context)):
        try:
            return [_json_safe(endpoint) for endpoint in dependencies.endpoint_service.list(context.principal, context.organization_context)]
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/endpoints/{endpoint_id}/approve", tags=["Tenant Endpoints"])
    async def approve_endpoint(endpoint_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            return _json_safe(dependencies.endpoint_service.approve(
                context.principal, context.organization_context, EndpointId(endpoint_id), datetime.now(timezone.utc)))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError:
            raise _http_error(409, "CONFLICT", "endpoint lifecycle conflict")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/endpoints/{endpoint_id}/revoke", tags=["Tenant Endpoints"])
    async def revoke_endpoint(endpoint_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            return _json_safe(dependencies.endpoint_service.revoke(
                context.principal, context.organization_context, EndpointId(endpoint_id), datetime.now(timezone.utc)))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError:
            raise _http_error(409, "CONFLICT", "endpoint lifecycle conflict")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/enrollment-tokens", tags=["Agent Enrollment"])
    async def list_enrollment_tokens(context: HumanRequestContext = Depends(organization_context)):
        if dependencies.enrollment_service is None:
            raise _http_error(503, "ENROLLMENT_UNAVAILABLE", "enrollment is unavailable")
        try:
            return [_enrollment_descriptor(item) for item in
                    dependencies.enrollment_service.list(context.principal, context.organization_context)]
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/enrollment-tokens", tags=["Agent Enrollment"])
    async def create_enrollment_token(request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.enrollment_service is None:
            raise _http_error(503, "ENROLLMENT_UNAVAILABLE", "enrollment is unavailable")
        body = await _json_body(request)
        if set(body) - {"ttl_minutes", "label", "max_uses"} or type(body.get("max_uses", 1)) is not int or body.get("max_uses", 1) != 1:
            raise _http_error(422, "INVALID_REQUEST", "invalid enrollment token options")
        try:
            authorization, secret = dependencies.enrollment_service.create(
                context.principal, context.organization_context,
                ttl_minutes=body.get("ttl_minutes", 60), label=body.get("label", ""))
        except ValueError:
            raise _http_error(422, "INVALID_REQUEST", "invalid enrollment token options")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        response = {**_enrollment_descriptor(authorization), "enrollment_token": secret.value}
        return JSONResponse(response, status_code=201, headers={"Cache-Control": "no-store"})

    @router.post("/organizations/{organization_id}/enrollment-tokens/{enrollment_id}/renew", tags=["Agent Enrollment"])
    async def renew_enrollment_token(enrollment_id: UUID, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.enrollment_service is None:
            raise _http_error(503, "ENROLLMENT_UNAVAILABLE", "enrollment is unavailable")
        try:
            item = dependencies.enrollment_service.renew(
                context.principal, context.organization_context, enrollment_id)
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        except ValueError:
            raise _http_error(409, "ENROLLMENT_NOT_RENEWABLE",
                              "Only recently issued, unused and expired tokens can be renewed.")
        return JSONResponse(_enrollment_descriptor(item), headers={"Cache-Control": "no-store"})

    @router.delete("/organizations/{organization_id}/enrollment-tokens/{enrollment_id}", tags=["Agent Enrollment"])
    async def revoke_enrollment_token(enrollment_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.enrollment_service is None:
            raise _http_error(503, "ENROLLMENT_UNAVAILABLE", "enrollment is unavailable")
        try:
            item = dependencies.enrollment_service.revoke(
                context.principal, context.organization_context, enrollment_id)
            return _enrollment_descriptor(item)
        except (KeyError, ValueError):
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/fleet/endpoints", tags=["Tenant Endpoints"])
    async def query_fleet(request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.fleet_query_service is None: raise _http_error(503, "FLEET_QUERY_UNAVAILABLE", "fleet query is unavailable")
        from ..domain.fleet import FleetQuery
        def vals(name):
            raw=request.query_params.getlist(name); out=[]
            for item in raw:
                out.extend(part.strip() for part in item.split(",") if part.strip())
            return tuple(out)
        try:
            query=FleetQuery(search=request.query_params.get("q", ""), statuses=vals("status"), presence_states=vals("presence"), platforms=vals("platform"), architectures=vals("architecture"), agent_versions=vals("agent_version"), sort_by=request.query_params.get("sort", "created_at"), direction=request.query_params.get("direction", "desc"), limit=int(request.query_params.get("limit", "50")), offset=int(request.query_params.get("offset", "0")))
            return _json_safe(dependencies.fleet_query_service.query(context.principal, context.organization_context, query))
        except ValueError as exc: raise _http_error(422, "INVALID_QUERY", str(exc))
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/endpoint-groups", tags=["Endpoint Groups"])
    async def create_group(request: Request, context: HumanRequestContext = Depends(organization_context)):
        body=await _json_body(request)
        try: return _json_safe(dependencies.endpoint_group_service.create(context.principal,context.organization_context,body.get("name"),body.get("description","")))
        except ValueError as e: raise _http_error(422,"INVALID_REQUEST",str(e))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.get("/organizations/{organization_id}/endpoint-groups", tags=["Endpoint Groups"])
    async def list_groups(context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.endpoint_group_service.list(context.principal,context.organization_context))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.get("/organizations/{organization_id}/endpoint-groups/{group_id}", tags=["Endpoint Groups"])
    async def get_group(group_id: str, context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.endpoint_group_service.get(context.principal,context.organization_context,group_id))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.patch("/organizations/{organization_id}/endpoint-groups/{group_id}", tags=["Endpoint Groups"])
    async def update_group(group_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        body=await _json_body(request)
        try: return _json_safe(dependencies.endpoint_group_service.update(context.principal,context.organization_context,group_id,body.get("name"),body.get("description")))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as e: raise _http_error(422,"INVALID_REQUEST",str(e))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.post("/organizations/{organization_id}/endpoint-groups/{group_id}/members", tags=["Endpoint Groups"])
    async def add_group_members(group_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        body=await _json_body(request)
        try: return _json_safe(dependencies.endpoint_group_service.add_members(context.principal,context.organization_context,group_id,body.get("endpoint_ids")))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as e: raise _http_error(422,"INVALID_REQUEST",str(e))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.post("/organizations/{organization_id}/endpoint-groups/{group_id}/members/remove", tags=["Endpoint Groups"])
    async def remove_group_members(group_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        body=await _json_body(request)
        try: return _json_safe(dependencies.endpoint_group_service.remove_members(context.principal,context.organization_context,group_id,body.get("endpoint_ids")))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.get("/organizations/{organization_id}/endpoint-groups/{group_id}/members", tags=["Endpoint Groups"])
    async def list_group_members(group_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.endpoint_group_service.members(context.principal,context.organization_context,group_id,int(request.query_params.get("limit",50)),int(request.query_params.get("offset",0))))
        except (ValueError,KeyError): raise _http_error(422,"INVALID_REQUEST","invalid pagination or group")
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.post("/organizations/{organization_id}/endpoint-groups/{group_id}/revoke", tags=["Endpoint Groups"])
    async def revoke_group(group_id: str, context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.endpoint_group_service.revoke(context.principal,context.organization_context,group_id))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError: raise _http_error(409,"CONFLICT","group lifecycle conflict")
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")

    @router.post("/organizations/{organization_id}/fleet-scopes", tags=["Fleet Scopes"])
    async def create_scope(request: Request, context: HumanRequestContext = Depends(organization_context)):
        body=await _json_body(request)
        try: return _json_safe(dependencies.fleet_scope_service.create(context.principal,context.organization_context,body.get("name"),body.get("criteria",{}),body.get("description","")))
        except ValueError as e: raise _http_error(422,"INVALID_REQUEST",str(e))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.get("/organizations/{organization_id}/fleet-scopes", tags=["Fleet Scopes"])
    async def list_scopes(context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.fleet_scope_service.list(context.principal,context.organization_context))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.get("/organizations/{organization_id}/fleet-scopes/{scope_id}", tags=["Fleet Scopes"])
    async def get_scope(scope_id: str, context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.fleet_scope_service.get(context.principal,context.organization_context,scope_id))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.patch("/organizations/{organization_id}/fleet-scopes/{scope_id}", tags=["Fleet Scopes"])
    async def update_scope(scope_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        body=await _json_body(request)
        try: return _json_safe(dependencies.fleet_scope_service.update(context.principal,context.organization_context,scope_id, name=body.get("name"),description=body.get("description"),query=body.get("criteria")))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as e: raise _http_error(422,"INVALID_REQUEST",str(e))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.post("/organizations/{organization_id}/fleet-scopes/{scope_id}/revoke", tags=["Fleet Scopes"])
    async def revoke_scope(scope_id: str, context: HumanRequestContext = Depends(organization_context)):
        try: return _json_safe(dependencies.fleet_scope_service.revoke(context.principal,context.organization_context,scope_id))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError: raise _http_error(409,"CONFLICT","scope lifecycle conflict")
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")
    @router.get("/organizations/{organization_id}/fleet-scopes/{scope_id}/endpoints", tags=["Fleet Scopes"])
    async def resolve_scope(scope_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        from ..domain.fleet import FleetQuery
        try:
            q=FleetQuery(limit=int(request.query_params.get("limit",50)),offset=int(request.query_params.get("offset",0)),sort_by=request.query_params.get("sort","created_at"),direction=request.query_params.get("direction","desc"))
            return _json_safe(dependencies.fleet_scope_service.resolve(context.principal,context.organization_context,scope_id,q))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as e: raise _http_error(422,"INVALID_QUERY",str(e))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/endpoints/{endpoint_id}", tags=["Tenant Endpoints"])
    async def get_endpoint(endpoint_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            endpoint = dependencies.endpoint_service.get(context.principal, context.organization_context, EndpointId(endpoint_id))
        except (KeyError, ValueError):
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        return _json_safe(endpoint)

    @router.get("/organizations/{organization_id}/endpoints/{endpoint_id}/presence", tags=["Tenant Endpoints"])
    async def endpoint_presence(endpoint_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.presence_service is None:
            raise _http_error(503, "PRESENCE_UNAVAILABLE", "presence is unavailable")
        try:
            return _json_safe(dependencies.presence_service.get(context.principal, context.organization_context, EndpointId(endpoint_id)))
        except (KeyError, ValueError):
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/fleet/presence", tags=["Tenant Endpoints"])
    async def fleet_presence(context: HumanRequestContext = Depends(organization_context)):
        if dependencies.fleet_presence_service is None:
            raise _http_error(503, "PRESENCE_UNAVAILABLE", "presence is unavailable")
        try:
            return _json_safe(dependencies.fleet_presence_service.summary(context.principal, context.organization_context))
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/audit-events", tags=["Tenant Security Reporting"])
    async def audit_events(request: Request, context: HumanRequestContext = Depends(organization_context)):
        """Organization security activity, newest first.

        The organization is taken from the resolved context, never from a query
        parameter, so this route cannot be pointed at another tenant.
        """
        if dependencies.audit_query_service is None:
            raise _http_error(503, "AUDIT_UNAVAILABLE", "security activity is unavailable")
        from ..domain.audit import AuditQuery

        def values(name):
            collected = []
            for item in request.query_params.getlist(name):
                collected.extend(part.strip() for part in item.split(",") if part.strip())
            return tuple(collected)

        def timestamp(name):
            raw = request.query_params.get(name)
            if not raw:
                return None
            # An unencoded "+" in a query string arrives as a space, so an ISO
            # offset like "+00:00" would otherwise fail to parse. Restoring it
            # is unambiguous: ISO-8601 never contains a literal space there.
            candidate = raw.strip().replace("Z", "+00:00")
            candidate = re.sub(r" (\d{2}:\d{2})$", r"+\1", candidate)
            try:
                parsed = datetime.fromisoformat(candidate)
            except ValueError:
                raise _http_error(422, "INVALID_QUERY", f"{name} must be an ISO-8601 timestamp")
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

        def integer(name, default):
            raw = request.query_params.get(name)
            if raw is None or not raw.strip():
                return default
            try:
                return int(raw)
            except ValueError:
                raise _http_error(422, "INVALID_QUERY", f"{name} must be an integer")

        def boolean(name, default=False):
            raw = request.query_params.get(name)
            if raw is None or not raw.strip():
                return default
            normalized = raw.strip().lower()
            if normalized in {"1", "true", "yes"}:
                return True
            if normalized in {"0", "false", "no"}:
                return False
            raise _http_error(422, "INVALID_QUERY", f"{name} must be a boolean")

        try:
            query = AuditQuery(
                event_types=values("event_type"),
                outcomes=values("outcome"),
                severities=values("severity"),
                actor_id=request.query_params.get("actor_id"),
                endpoint_id=request.query_params.get("endpoint_id"),
                occurred_after=timestamp("from"),
                occurred_before=timestamp("to"),
                include_permission_checks=boolean("include_permission_checks"),
                limit=integer("limit", 25),
                offset=integer("offset", 0),
            )
        except ValueError as exc:
            raise _http_error(422, "INVALID_QUERY", str(exc))

        try:
            return _json_safe(dependencies.audit_query_service.query(
                context.principal, context.organization_context, query))
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        except ValueError as exc:
            raise _http_error(422, "INVALID_QUERY", str(exc))

    @router.get("/organizations/{organization_id}/security/metrics", tags=["Tenant Security Reporting"])
    async def security_metrics(request: Request, context: HumanRequestContext = Depends(organization_context)):
        """Windowed security telemetry and any signals it triggered.

        High-volume authorization telemetry lives here rather than in the audit
        trail; see docs/architecture/security-observability.md.
        """
        service = dependencies.security_observability_service
        if service is None:
            raise _http_error(503, "OBSERVABILITY_UNAVAILABLE", "security observability is unavailable")
        raw = request.query_params.get("window_minutes")
        try:
            window = int(raw) if raw and raw.strip() else 15
        except ValueError:
            raise _http_error(422, "INVALID_QUERY", "window_minutes must be an integer")
        try:
            return _json_safe(service.snapshot(context.principal, context.organization_context,
                                               window_minutes=window))
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        except ValueError as exc:
            raise _http_error(422, "INVALID_QUERY", str(exc))

    @router.get("/organizations/{organization_id}/security/overview", tags=["Tenant Security Reporting"])
    async def security_overview(context: HumanRequestContext = Depends(organization_context)):
        if dependencies.security_overview_service is None:
            raise _http_error(503, "REPORTING_UNAVAILABLE", "security overview is unavailable")
        try:
            return _json_safe(dependencies.security_overview_service.overview(
                context.principal, context.organization_context))
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        except (KeyError, ValueError):
            raise _http_error(404, "NOT_FOUND", "resource not found")

    @router.get("/organizations/{organization_id}/compliance/frameworks", tags=["Tenant Compliance"])
    async def compliance_frameworks(context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_service is None: raise _http_error(503, "COMPLIANCE_UNAVAILABLE", "compliance is unavailable")
        try: return [_json_safe(x) for x in dependencies.compliance_service.frameworks(context.principal, context.organization_context)]
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/compliance/frameworks/{framework_id}", tags=["Tenant Compliance"])
    async def compliance_framework(framework_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_service is None: raise _http_error(503, "COMPLIANCE_UNAVAILABLE", "compliance is unavailable")
        try: return _json_safe(dependencies.compliance_service.framework_detail(context.principal, context.organization_context, framework_id))
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/endpoints/{endpoint_id}/compliance/{framework_id}", tags=["Tenant Compliance"])
    async def endpoint_compliance(endpoint_id: str, framework_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_service is None: raise _http_error(503, "COMPLIANCE_UNAVAILABLE", "compliance is unavailable")
        try: return [_json_safe(x) for x in dependencies.compliance_service.evaluate_endpoint(context.principal, context.organization_context, endpoint_id, framework_id)]
        except (KeyError, ValueError): raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/summary", tags=["Tenant Compliance"])
    async def compliance_summary(framework_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_service is None: raise _http_error(503, "COMPLIANCE_UNAVAILABLE", "compliance is unavailable")
        try: return _json_safe(dependencies.compliance_service.summary(context.principal, context.organization_context, framework_id))
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError as exc: raise _http_error(422, "BOUND_EXCEEDED", str(exc))
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/compliance/{framework_id}/snapshots", tags=["Tenant Compliance"])
    async def create_compliance_snapshot(framework_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503, "COMPLIANCE_UNAVAILABLE", "compliance snapshots are unavailable")
        body=await _json_body(request)
        try: return _json_safe(dependencies.compliance_snapshot_service.create(context.principal,context.organization_context,framework_id,scope_type=body.get("scope_type","organization"),scope_reference_id=body.get("scope_reference_id")))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as exc: raise _http_error(422,"INVALID_REQUEST",str(exc))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/snapshots", tags=["Tenant Compliance"])
    async def list_compliance_snapshots(framework_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        try:return _json_safe(dependencies.compliance_snapshot_service.list(context.principal,context.organization_context,framework_id,int(request.query_params.get("limit",50)),int(request.query_params.get("offset",0))))
        except PermissionError:raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/snapshots/{snapshot_id}", tags=["Tenant Compliance"])
    async def get_compliance_snapshot(framework_id: str, snapshot_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        try:return _json_safe(dependencies.compliance_snapshot_service.get(context.principal,context.organization_context,snapshot_id,framework_id))
        except KeyError:raise _http_error(404,"NOT_FOUND","resource not found")
        except PermissionError:raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/snapshots/{snapshot_id}/compare", tags=["Tenant Compliance"])
    async def compare_compliance_snapshot(framework_id: str, snapshot_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        try:return _json_safe(dependencies.compliance_snapshot_service.compare(context.principal,context.organization_context,snapshot_id,request.query_params.get("previous_id")))
        except KeyError:raise _http_error(404,"NOT_FOUND","resource not found")
        except PermissionError:raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/snapshots/{snapshot_id}/export", tags=["Tenant Compliance"])
    async def export_compliance_snapshot(framework_id: str, snapshot_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        from fastapi.responses import Response
        try:
            fmt=request.query_params.get("format","json"); body,content_type=dependencies.compliance_snapshot_service.export(context.principal,context.organization_context,snapshot_id,fmt); safe_fmt = "csv" if fmt.lower()=="csv" else "json"; return Response(body,media_type=content_type,headers={"Content-Disposition":f"attachment; filename=ravenx-compliance-{framework_id}.{safe_fmt}"})
        except KeyError:raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as exc:raise _http_error(422,"INVALID_EXPORT",str(exc))
        except PermissionError:raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/timeline", tags=["Tenant Compliance"])
    async def compliance_timeline(framework_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        try:
            from datetime import datetime, timezone
            def parse(value):
                if not value: return None
                parsed=datetime.fromisoformat(value.replace("Z","+00:00")); return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            values=dependencies.compliance_snapshot_service.timeline(context.principal,context.organization_context,framework_id,version=request.query_params.get("version"),from_dt=parse(request.query_params.get("from")),to_dt=parse(request.query_params.get("to")),limit=int(request.query_params.get("limit",50)))
            return _json_safe(values)
        except ValueError as exc: raise _http_error(422,"INVALID_REQUEST",str(exc))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/compliance/{framework_id}/controls/{control_id}/trend", tags=["Tenant Compliance"])
    async def compliance_control_trend(framework_id: str, control_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        try: return _json_safe(dependencies.compliance_snapshot_service.control_trend(context.principal,context.organization_context,framework_id,control_id,version=request.query_params.get("version"),limit=int(request.query_params.get("limit",50))))
        except KeyError: raise _http_error(404,"NOT_FOUND","resource not found")
        except ValueError as exc: raise _http_error(422,"INVALID_REQUEST",str(exc))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/endpoints/{endpoint_id}/compliance/{framework_id}/history", tags=["Tenant Compliance"])
    async def endpoint_compliance_history(endpoint_id: str, framework_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.compliance_snapshot_service is None: raise _http_error(503,"COMPLIANCE_UNAVAILABLE","compliance snapshots are unavailable")
        try: return _json_safe(dependencies.compliance_snapshot_service.endpoint_history(context.principal,context.organization_context,endpoint_id,framework_id,limit=int(request.query_params.get("limit",50))))
        except ValueError as exc: raise _http_error(422,"INVALID_REQUEST",str(exc))
        except PermissionError: raise _http_error(403,"FORBIDDEN","permission denied")

    @router.get("/organizations/{organization_id}/assessments/{assessment_id}/details", tags=["Tenant Security Reporting"])
    async def assessment_details(assessment_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.assessment_detail_service is None:
            raise _http_error(503, "REPORTING_UNAVAILABLE", "assessment details are unavailable")
        try:
            return _json_safe(dependencies.assessment_detail_service.get_detail(context.principal, context.organization_context, assessment_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/assessments/{assessment_id}/findings/{occurrence_id}", tags=["Tenant Security Reporting"])
    async def finding_details(assessment_id: str, occurrence_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.assessment_detail_service is None:
            raise _http_error(503, "REPORTING_UNAVAILABLE", "finding details are unavailable")
        try:
            return _json_safe(dependencies.assessment_detail_service.get_finding(context.principal, context.organization_context, assessment_id, occurrence_id))
        except (KeyError, ValueError):
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/assessments/{assessment_id}/findings/{occurrence_id}/recurrence", tags=["Tenant Security Reporting"])
    async def finding_recurrence(assessment_id: str, occurrence_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.finding_recurrence_service is None:
            raise _http_error(503, "REPORTING_UNAVAILABLE", "finding recurrence is unavailable")
        try:
            return _json_safe(dependencies.finding_recurrence_service.compare(
                context.principal, context.organization_context, assessment_id, occurrence_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/assessments/{assessment_id}/findings/{occurrence_id}/coverage", tags=["Tenant Security Reporting"])
    async def finding_coverage(assessment_id: str, occurrence_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.finding_coverage_service is None:
            raise _http_error(503, "REPORTING_UNAVAILABLE", "finding coverage is unavailable")
        try:
            return _json_safe(dependencies.finding_coverage_service.history(
                context.principal, context.organization_context, assessment_id, occurrence_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/assessments", tags=["Tenant Assessments"])
    async def create_assessment(request: Request, context: HumanRequestContext = Depends(organization_context)):
        body = await _json_body(request)
        endpoint_id = body.get("endpoint_id")
        scanner_ids = body.get("scanner_ids")
        if not isinstance(endpoint_id, str) or not isinstance(scanner_ids, list) or not scanner_ids or not all(isinstance(item, str) and item.strip() for item in scanner_ids):
            raise _http_error(422, "INVALID_REQUEST", "endpoint_id and scanner_ids are required")
        try:
            assessment = dependencies.assessment_service.create_assessment(
                context.principal, context.organization_context, EndpointId(endpoint_id), tuple(scanner_ids))
        except (KeyError, ValueError):
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        except RuntimeError:
            raise _http_error(409, "INVALID_LIFECYCLE", "assessment cannot be created")
        return _json_safe(assessment)

    @router.post("/organizations/{organization_id}/assessment-schedules", tags=["Tenant Assessment Schedules"])
    async def create_schedule(request: Request, context: HumanRequestContext = Depends(organization_context)):
        body = await _json_body(request)
        service = dependencies.schedule_service
        if service is None: raise _http_error(503, "SCHEDULING_UNAVAILABLE", "assessment scheduling is unavailable")
        try:
            schedule = service.create(context.principal, context.organization_context, body.get("name"), body.get("target_endpoint_ids", body.get("targets")), body.get("scanner_ids"), body.get("recurrence", {}), starts_at=body.get("starts_at"), target=body.get("target"), group_repository=getattr(dependencies.endpoint_group_service,"repo",None), scope_repository=getattr(dependencies.fleet_scope_service,"repo",None))
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError as exc: raise _http_error(422, "INVALID_REQUEST", str(exc))
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")
        return _json_safe(schedule)

    @router.get("/organizations/{organization_id}/assessment-schedules", tags=["Tenant Assessment Schedules"])
    async def list_schedules(context: HumanRequestContext = Depends(organization_context)):
        if dependencies.schedule_service is None: raise _http_error(503, "SCHEDULING_UNAVAILABLE", "assessment scheduling is unavailable")
        try: return [_json_safe(x) for x in dependencies.schedule_service.list(context.principal, context.organization_context)]
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/assessment-schedules/{schedule_id}", tags=["Tenant Assessment Schedules"])
    async def get_schedule(schedule_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.schedule_service is None: raise _http_error(503, "SCHEDULING_UNAVAILABLE", "assessment scheduling is unavailable")
        try: return _json_safe(dependencies.schedule_service.get(context.principal, context.organization_context, schedule_id))
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/assessment-schedules/{schedule_id}/runs", tags=["Tenant Assessment Schedules"])
    async def list_schedule_runs(schedule_id: str, context: HumanRequestContext = Depends(organization_context)):
        if dependencies.schedule_service is None: raise _http_error(503, "SCHEDULING_UNAVAILABLE", "assessment scheduling is unavailable")
        try:
            return [_json_safe(x) for x in dependencies.schedule_service.list_runs(context.principal, context.organization_context, schedule_id, dependencies.schedule_run_repository)]
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.patch("/organizations/{organization_id}/assessment-schedules/{schedule_id}", tags=["Tenant Assessment Schedules"])
    async def update_schedule(schedule_id: str, request: Request, context: HumanRequestContext = Depends(organization_context)):
        body = await _json_body(request)
        if dependencies.schedule_service is None: raise _http_error(503, "SCHEDULING_UNAVAILABLE", "assessment scheduling is unavailable")
        changes = {key: value for key, value in (("name", body.get("name")), ("endpoint_ids", body.get("target_endpoint_ids", body.get("targets"))), ("scanner_ids", body.get("scanner_ids")), ("recurrence", body.get("recurrence")), ("target", body.get("target"))) if value is not None}
        if "target" in changes:
            changes["group_repository"] = getattr(dependencies.endpoint_group_service, "repo", None)
            changes["scope_repository"] = getattr(dependencies.fleet_scope_service, "repo", None)
        try: return _json_safe(dependencies.schedule_service.update(context.principal, context.organization_context, schedule_id, **changes))
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError as exc: raise _http_error(422, "INVALID_REQUEST", str(exc))
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")

    async def _schedule_action(schedule_id, context, action):
        if dependencies.schedule_service is None: raise _http_error(503, "SCHEDULING_UNAVAILABLE", "assessment scheduling is unavailable")
        try: return _json_safe(action(context.principal, context.organization_context, schedule_id))
        except KeyError: raise _http_error(404, "NOT_FOUND", "resource not found")
        except ValueError: raise _http_error(409, "INVALID_LIFECYCLE", "schedule lifecycle conflict")
        except PermissionError: raise _http_error(403, "FORBIDDEN", "permission denied")
    @router.post("/organizations/{organization_id}/assessment-schedules/{schedule_id}/pause", tags=["Tenant Assessment Schedules"])
    async def pause_schedule(schedule_id: str, context: HumanRequestContext = Depends(organization_context)): return await _schedule_action(schedule_id, context, dependencies.schedule_service.pause)
    @router.post("/organizations/{organization_id}/assessment-schedules/{schedule_id}/resume", tags=["Tenant Assessment Schedules"])
    async def resume_schedule(schedule_id: str, context: HumanRequestContext = Depends(organization_context)): return await _schedule_action(schedule_id, context, dependencies.schedule_service.resume)
    @router.post("/organizations/{organization_id}/assessment-schedules/{schedule_id}/revoke", tags=["Tenant Assessment Schedules"])
    async def revoke_schedule(schedule_id: str, context: HumanRequestContext = Depends(organization_context)): return await _schedule_action(schedule_id, context, dependencies.schedule_service.revoke)

    @router.get("/organizations/{organization_id}/assessments", tags=["Tenant Assessments"])
    async def list_assessments(context: HumanRequestContext = Depends(organization_context)):
        try:
            return [_json_safe(item) for item in dependencies.assessment_service.list_assessments(context.principal, context.organization_context)]
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.get("/organizations/{organization_id}/assessments/{assessment_id}", tags=["Tenant Assessments"])
    async def get_assessment(assessment_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            return _json_safe(dependencies.assessment_service.get_assessment(context.principal, context.organization_context, assessment_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")

    @router.post("/organizations/{organization_id}/assessments/{assessment_id}/cancel", tags=["Tenant Assessments"])
    async def cancel_assessment(assessment_id: str, context: HumanRequestContext = Depends(organization_context)):
        try:
            return _json_safe(dependencies.assessment_service.cancel(context.principal, context.organization_context, assessment_id))
        except KeyError:
            raise _http_error(404, "NOT_FOUND", "resource not found")
        except PermissionError:
            raise _http_error(403, "FORBIDDEN", "permission denied")
        except RuntimeError:
            raise _http_error(409, "INVALID_LIFECYCLE", "assessment cannot be cancelled")

    return router


def _bearer_token(value: Optional[str]) -> str:
    if not isinstance(value, str) or not value.startswith("Bearer "):
        raise _http_error(401, "INVALID_SESSION", "human authentication failed")
    token = value[7:].strip()
    if not token or any(ch.isspace() for ch in token):
        raise _http_error(401, "INVALID_SESSION", "human authentication failed")
    return token


async def _json_body(request: Request) -> dict:
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        raise _http_error(415, "UNSUPPORTED_MEDIA_TYPE", "application/json is required")
    try:
        body = await request.json()
    except Exception:
        raise _http_error(400, "MALFORMED_JSON", "request body is not valid JSON")
    if not isinstance(body, dict):
        raise _http_error(422, "INVALID_REQUEST", "request body must be an object")
    return body


def _http_error(code: int, error: str, message: str) -> HTTPException:
    return HTTPException(status_code=code, detail={"code": error, "message": message})


def _login_rate_key(request: Request, email: str) -> str:
    peer = request.client.host if request.client else "unknown"
    identifier = hashlib.sha256(email.strip().casefold().encode("utf-8")).hexdigest()
    return f"{peer}:{identifier}"


def _metric(metrics, name: str) -> None:
    if metrics is not None:
        metrics.increment(name)


def _audit_rate_limit(audit_sink, request: Request, rate_key: str) -> None:
    if audit_sink is None:
        return
    audit_sink.append(SecurityAuditEvent(
        event_type=SecurityAuditEventType.HUMAN_AUTHENTICATION_RATE_LIMITED.value,
        outcome=SecurityAuditOutcome.DENIED,
        reason_code="rate_limit_exceeded",
        metadata={"client_key": hashlib.sha256(rate_key.encode("utf-8")).hexdigest(),
                  "request_id": getattr(getattr(request, "state", None), "request_id", None)},
    ))


def _json_safe(value: Any):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if hasattr(value, "to_dict"):
        return _json_safe(value.to_dict())
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return str(value)


def _enrollment_descriptor(authorization):
    """Public management view; token verifier and raw token never appear here."""
    effective_status = authorization.status
    now = datetime.now(timezone.utc)
    if effective_status is EnrollmentStatus.PENDING and now >= authorization.expires_at:
        effective_status = EnrollmentStatus.EXPIRED
    return {
        "enrollment_id": str(authorization.enrollment_id),
        "organization_id": str(authorization.organization_id),
        "status": effective_status.value,
        "renewable": authorization.can_renew(now),
        "created_at": authorization.created_at.astimezone(timezone.utc).isoformat(),
        "expires_at": authorization.expires_at.astimezone(timezone.utc).isoformat(),
        "label": authorization.metadata.get("label", ""),
    }


def _organization_response(organization):
    return {"organization_id": str(organization.organization_id), "name": organization.name,
            "status": organization.status.value, "created_at": organization.created_at.astimezone(timezone.utc).isoformat(),
            "updated_at": organization.updated_at.astimezone(timezone.utc).isoformat()}


def _membership_response(membership):
    return {"membership_id": str(membership.membership_id), "user_id": str(membership.user_id),
            "status": membership.status.value, "created_at": membership.created_at.astimezone(timezone.utc).isoformat()}


__all__ = ["HumanRequestContext", "HumanControlPlaneDependencies", "create_human_control_plane_router"]
