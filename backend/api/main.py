"""
RAVEN-X Enterprise - FastAPI Backend
The brain surgery begins HERE!
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging
import os
import ipaddress
import re
import time
import uuid
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
import uvicorn
import yaml
from pathlib import Path
from sqlalchemy import text

from ..core.database.database import db_manager, get_async_db_session, resolve_config_path
from ..application.agent.processor import AgentMessageProcessor, CredentialEndpointAuthenticator, TypedMessageRouter
from ..application.control_plane import AgentSessionRegistry, ControlPlaneAgentHandlers
from ..application.control_plane import RemoteAssessmentCancellationService, RemoteAssessmentDispatcher
from ..application.control_plane import RemoteAssessmentReconciler
from ..application.enrollment.service import EnrollmentService
from ..infrastructure.security.verifier_key import bind_control_plane_verifier_key
from ..application.enrollment import TenantEnrollmentService
from ..application.assessment import TenantAssessmentService
from ..application.scheduling import TenantAssessmentScheduleService, AssessmentScheduleRunner, AssessmentScheduleWorker
from ..application.endpoint import TenantEndpointService, PresenceMaintenanceRunner, TenantFleetPresenceService
from ..application.fleet import TenantFleetQueryService
from ..application.fleet.groups import TenantEndpointGroupService, TenantSavedFleetScopeService
from ..application.identity import HumanAuthenticationService, HumanSessionAuthenticator
from ..application.organization import (OrganizationContextResolver, OrganizationMembershipService,
                                        OrganizationService, TenantOrganizationAdministrationService)
from ..application.rbac import AuthorizationAuditPolicy, OrganizationRbacAuthorizer
from ..infrastructure.persistence.sqlalchemy_user_repository import SQLAlchemyUserRepository
from ..infrastructure.persistence.sqlalchemy_organization_repository import SQLAlchemyOrganizationRepository
from ..infrastructure.persistence.sqlalchemy_membership_repository import SQLAlchemyOrganizationMembershipRepository
from ..infrastructure.persistence.sqlalchemy_rbac_repository import SQLAlchemyRoleRepository, SQLAlchemyRoleBindingRepository
from ..infrastructure.persistence.sqlalchemy_enrollment_repository import SQLAlchemyEnrollmentRepository
from ..infrastructure.persistence.sqlalchemy_replay_guard import SQLAlchemyReplayGuard
from ..infrastructure.persistence.sqlalchemy_agent_work_repository import SQLAlchemyAgentWorkRepository
from ..infrastructure.persistence.sqlalchemy_remote_assessment_repository import SQLAlchemyRemoteAssessmentRepository
from ..infrastructure.persistence.sqlalchemy_security_audit_repository import SQLAlchemySecurityAuditRepository
from ..infrastructure.persistence.sqlalchemy_endpoint_repository import SQLAlchemyEndpointRepository
from ..infrastructure.persistence.sqlalchemy_group_scope_repository import SQLAlchemyEndpointGroupRepository, SQLAlchemySavedFleetScopeRepository
from ..infrastructure.persistence.sqlalchemy_schedule_repository import SQLAlchemyAssessmentScheduleRepository, SQLAlchemyAssessmentScheduleRunRepository
from ..domain.scheduling import AssessmentScheduleCalculator
from ..infrastructure.persistence.sqlalchemy_presence_repository import SQLAlchemyEndpointPresenceRepository
from ..application.endpoint.presence_service import EndpointPresenceService, TenantEndpointPresenceService
from ..application.reporting import (TenantSecurityOverviewService, TenantAssessmentDetailService,
                                      TenantFindingRecurrenceService, TenantFindingCoverageService)
from ..application.compliance import TenantComplianceService, ComplianceControlEvaluator, TenantComplianceSnapshotService
from ..application.audit import TenantAuditQueryService
from ..application.observability import TenantSecurityObservabilityService
from ..infrastructure.persistence.sqlalchemy_compliance_snapshot_repository import SQLAlchemyComplianceSnapshotRepository
from ..domain.compliance import ravenx_windows_baseline_registry
from ..domain.presence import PresencePolicy
from ..infrastructure.transport.http import HttpControlPlaneTransport, create_agent_http_router
from ..infrastructure.operational import (ApplicationSettings, InMemoryRateLimiter,
                                          MetricsCollector, SecurityTelemetry)
from .human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from .tenant_insights import TenantInsightsDependencies, create_tenant_insights_router
from ..application.reporting.fleet_report import TenantFleetReportService
from ..application.ai import TenantLocalAnalysisService
from ..infrastructure.ai import LocalAIConfig, LocalOpenAIProvider

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load the same config file as DatabaseManager, even when launched from a
# different working directory or with an explicit deployment config path.
with open(resolve_config_path(), 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

# Legacy scan/AI/reporting/monitoring modules are optional application
# features.  They are composed when their declared dependencies are present;
# their import failures must not prevent the authenticated control-plane and
# agent ingress from starting.  This does not disable a configured feature in
# a healthy runtime, it only makes its dependency boundary explicit.
optional_components = {}
learning_engine = None
behavioral_monitor = None
settings = ApplicationSettings.from_environment(config)
settings.validate_pre_mount()
# Routers are mounted at import time, but settings.validate() only runs in the
# lifespan.  Anything that serves this app without running lifespan (an embedder,
# or TestClient used without a context manager) would otherwise expose the
# unauthenticated legacy routers in production.  Refuse at the mount point too,
# so the dangerous surface can never be built in a production process.
_legacy_routes_requested = settings.enable_legacy_routes
_legacy_routes_enabled = _legacy_routes_requested and settings.environment != "production"
_mounted_legacy_prefixes = set()
metrics = MetricsCollector()
# High-volume authorization/authentication telemetry. Process-local and
# non-durable by design: the audit trail keeps the historical record.
security_telemetry = SecurityTelemetry(metrics=metrics)
login_rate_limiter = InMemoryRateLimiter(settings.login_rate_limit, settings.login_rate_window_seconds)

def _mount_optional_router(module_name, prefix, tag):
    if not _legacy_routes_enabled:
        optional_components[module_name] = (
            "refused: legacy routes are not served in production"
            if _legacy_routes_requested
            else "disabled: set RAVENX_ENABLE_LEGACY_ROUTES=true")
        return
    try:
        module = __import__(module_name, fromlist=["router"])
        app.include_router(module.router, prefix=prefix, tags=[tag])
        _mounted_legacy_prefixes.add(prefix)
        optional_components[module_name] = "available"
    except Exception as error:
        optional_components[module_name] = f"unavailable: {type(error).__name__}"
        logger.warning("Optional component %s is unavailable", module_name)

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    settings.validate()
    # Startup
    logger.info("🚀 RAVEN-X Enterprise API Starting...")

    # Initialize database, then bind the HMAC key before any request is served.
    # A custody failure raises here, so the process never logs ready and never
    # accepts traffic with a missing or mismatched verifier key.
    await db_manager.create_tables_async()
    bind_control_plane_verifier_key(db_manager, agent_enrollment_service, environment=settings.environment)
    logger.info("✅ Database initialized")

    # Start behavioral monitoring
    if behavioral_monitor is not None and config['monitoring']['real_time_enabled']:
        behavioral_monitor.start_monitoring()
        logger.info("✅ Behavioral monitoring active")
    if assessment_schedule_worker.enabled:
        assessment_schedule_worker.start()
    maintenance_stop = asyncio.Event()
    maintenance = asyncio.create_task(_maintain_control_plane(maintenance_stop))

    logger.info("🟢 RAVEN-X Enterprise API READY!")

    yield

    # Shutdown
    logger.info("🛑 Shutting down RAVEN-X Enterprise API...")
    if behavioral_monitor is not None:
        behavioral_monitor.stop_monitoring()
    assessment_schedule_worker.stop()
    maintenance_stop.set()
    await maintenance
    await db_manager.close_async()
    logger.info("✅ Shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="RAVEN-X Enterprise Security Platform",
    description="AI-Powered Windows Vulnerability Scanner & Auto-Remediation Engine",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
# Same-origin by default.  An empty allow-list means no cross-origin request is
# permitted, so a page a lab user happens to open cannot call this API from
# their browser.  Cross-origin access is opt-in via RAVENX_CORS_ORIGINS.  The
# Vite dev server proxies /api to this process, so local development is
# same-origin and unaffected.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=bool(settings.cors_origins),
    allow_methods=["*"] if settings.cors_origins else [],
    allow_headers=["*"] if settings.cors_origins else [],
)


def _is_mounted_legacy_path(path: str) -> bool:
    # /api/v1/stats is a standalone optional monitoring endpoint outside the
    # five compatibility routers.  It receives the same local-only boundary.
    return (_legacy_routes_enabled and path == "/api/v1/stats") or any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in _mounted_legacy_prefixes)


def _is_loopback_asgi_peer(client) -> bool:
    """Read the ASGI peer only; forwarded headers are never authority here."""
    if not isinstance(client, (tuple, list)) or len(client) != 2 or not isinstance(client[0], str):
        return False
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


@app.middleware("http")
async def operational_request_middleware(request: Request, call_next):
    supplied = request.headers.get("X-Request-ID", "")
    request_id = supplied if re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", supplied) else str(uuid.uuid4())
    request.state.request_id = request_id
    started = time.monotonic()
    try:
        # Legacy host-action APIs are local-personal features.  A direct
        # development Uvicorn bind must not turn explicit opt-in into a LAN
        # remediation endpoint.  This uses only the ASGI client address.
        if _is_mounted_legacy_path(request.scope.get("path", "")) and not _is_loopback_asgi_peer(request.scope.get("client")):
            response = JSONResponse({"error": "legacy_routes_require_loopback"}, status_code=403)
        else:
            response = await call_next(request)
    except Exception as error:
        metrics.increment("http.requests")
        metrics.increment("http.errors")
        # Log only a safe exception category; exception text can contain
        # credentials supplied by an upstream dependency.
        logger.error("http_request_failed request_id=%s method=%s path=%s error_type=%s",
                     request_id, request.method, request.url.path, type(error).__name__)
        raise
    duration_ms = round((time.monotonic() - started) * 1000, 2)
    metrics.increment("http.requests")
    if response.status_code >= 400:
        metrics.increment("http.errors")
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    if request.url.path.startswith("/api/v1/auth/") or "/export" in request.url.path:
        response.headers.setdefault("Cache-Control", "no-store")
    logger.info("http_request request_id=%s method=%s path=%s status=%s duration_ms=%s",
                request_id, request.method, request.url.path, response.status_code, duration_ms)
    return response

if _legacy_routes_enabled:
    try:
        from ..core.ai.learning_engine import learning_engine as _learning_engine
        learning_engine = _learning_engine
        optional_components["backend.core.ai.learning_engine"] = "available"
    except Exception as error:
        optional_components["backend.core.ai.learning_engine"] = f"unavailable: {type(error).__name__}"

    try:
        from ..core.monitoring.behavioral_monitoring import behavioral_monitor as _behavioral_monitor
        behavioral_monitor = _behavioral_monitor
        optional_components["backend.core.monitoring.behavioral_monitoring"] = "available"
    except Exception as error:
        optional_components["backend.core.monitoring.behavioral_monitoring"] = f"unavailable: {type(error).__name__}"
else:
    _optional_reason = ("refused: legacy routes are not served in production"
                        if _legacy_routes_requested
                        else "disabled: set RAVENX_ENABLE_LEGACY_ROUTES=true")
    optional_components["backend.core.ai.learning_engine"] = _optional_reason
    optional_components["backend.core.monitoring.behavioral_monitoring"] = _optional_reason

# Machine-to-machine agent transport. The router is deliberately assembled
# from existing authentication/protocol boundaries; it does not expose an
# inbound endpoint-agent listener or create a second message pipeline.
agent_sessions = AgentSessionRegistry()
agent_assessments = SQLAlchemyRemoteAssessmentRepository(db_manager)
agent_endpoint_repository = SQLAlchemyEndpointRepository(db_manager)
presence_repository = SQLAlchemyEndpointPresenceRepository(db_manager)
presence_service = EndpointPresenceService(
    agent_endpoint_repository, presence_repository,
    policy=PresencePolicy(settings.heartbeat_interval_seconds, settings.heartbeat_stale_after_seconds,
                          settings.heartbeat_offline_after_seconds),
    metrics=metrics,
)
presence_maintenance_runner = PresenceMaintenanceRunner(
    presence_service, batch_size=settings.presence_evaluation_batch_size)


async def _maintain_control_plane(stop):
    next_presence = 0.0
    while not stop.is_set():
        try:
            if settings.presence_maintenance_enabled and time.monotonic() >= next_presence:
                await asyncio.to_thread(presence_maintenance_runner.run_once)
                next_presence = time.monotonic() + settings.presence_maintenance_interval_seconds
            now = datetime.now(timezone.utc)
            await asyncio.to_thread(
                agent_work_repository.release_expired_leases,
                now=now, max_attempts=3, retry_delay=timedelta(seconds=0))
            await asyncio.to_thread(assessment_reconciler.reconcile_all, now=now)
        except Exception as error:
            logger.error("control_plane_maintenance_failed error_type=%s", type(error).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=15)
        except asyncio.TimeoutError:
            pass


agent_work_repository = SQLAlchemyAgentWorkRepository(db_manager, endpoint_repository=agent_endpoint_repository,
                                                      assessment_repository=agent_assessments)
security_audit_repository = SQLAlchemySecurityAuditRepository(db_manager)
assessment_reconciler = RemoteAssessmentReconciler(
    agent_assessments, agent_work_repository,
    execution_timeout=timedelta(seconds=settings.assessment_execution_timeout_seconds),
    audit_sink=security_audit_repository)
agent_handlers = ControlPlaneAgentHandlers(agent_sessions, agent_assessments, agent_work_repository, security_audit_repository,
                                           endpoint_repository=agent_endpoint_repository, presence_service=presence_service)
agent_message_router = TypedMessageRouter()
agent_handlers.register_routes(agent_message_router)
agent_enrollment_service = EnrollmentService(
    SQLAlchemyEnrollmentRepository(db_manager),
    audit_sink=security_audit_repository,
    organization_repository=SQLAlchemyOrganizationRepository(db_manager),
    defer_verifier_key=True,
)
# One durable message-id namespace for protocol messages and credential renewal.
agent_replay_guard = SQLAlchemyReplayGuard(db_manager)
agent_message_processor = AgentMessageProcessor(
    CredentialEndpointAuthenticator(agent_enrollment_service),
    agent_replay_guard,
    router=agent_message_router,
    audit_repository=security_audit_repository,
)
agent_http_transport = HttpControlPlaneTransport()
app.include_router(
    create_agent_http_router(agent_message_processor, agent_enrollment_service, agent_http_transport.outbox,
                             # A full Windows scan can span many individually bounded OS queries.
                             work_repository=agent_work_repository, replay_guard=agent_replay_guard,
                             lease_duration=timedelta(minutes=15)),
    prefix="/api/v1/agent",
    tags=["Agent Transport"],
)

# Human control-plane composition.  These routes use opaque server-side human
# sessions and resolve organization context on every request.  They are kept
# separate from /api/v1/agent, whose credential boundary remains unchanged.
human_user_repository = SQLAlchemyUserRepository(db_manager)
human_organization_repository = SQLAlchemyOrganizationRepository(db_manager)
human_membership_repository = SQLAlchemyOrganizationMembershipRepository(db_manager)
human_role_repository = SQLAlchemyRoleRepository(db_manager)
human_role_binding_repository = SQLAlchemyRoleBindingRepository(db_manager)
human_authorizer = OrganizationRbacAuthorizer(
    telemetry=security_telemetry,
    audit_policy=AuthorizationAuditPolicy(
        record_successful_authorizations=settings.audit_record_authorization_success),
    membership_repository=human_membership_repository,
    role_binding_repository=human_role_binding_repository,
    role_repository=human_role_repository,
    organization_repository=human_organization_repository,
    endpoint_repository=agent_endpoint_repository,
    audit_sink=security_audit_repository,
)
human_context_resolver = OrganizationContextResolver(
    human_user_repository, human_membership_repository, human_organization_repository,
    audit_sink=security_audit_repository,
)
human_authentication = HumanAuthenticationService(human_user_repository, audit_sink=security_audit_repository,
                                                 telemetry=security_telemetry)
human_sessions = HumanSessionAuthenticator(human_user_repository, audit_sink=security_audit_repository)
human_organization_service = OrganizationService(human_organization_repository, audit_sink=security_audit_repository)
human_membership_service = OrganizationMembershipService(
    human_membership_repository, human_organization_repository, human_user_repository,
    audit_sink=security_audit_repository,
)
human_organization_admin_service = TenantOrganizationAdministrationService(
    human_organization_service, human_membership_service, human_organization_repository,
    human_membership_repository, human_authorizer,
)
human_dispatcher = RemoteAssessmentDispatcher(
    agent_endpoint_repository, agent_sessions, agent_http_transport, agent_assessments,
    work_repository=agent_work_repository, authorization_service=human_authorizer,
    audit_sink=security_audit_repository,
)
human_cancellation = RemoteAssessmentCancellationService(
    agent_assessments, agent_work_repository, authorization_service=human_authorizer,
    audit_sink=security_audit_repository,
)
human_endpoint_service = TenantEndpointService(agent_endpoint_repository, human_authorizer, audit_sink=security_audit_repository)
human_presence_service = TenantEndpointPresenceService(presence_service, human_authorizer)
human_fleet_presence_service = TenantFleetPresenceService(agent_endpoint_repository, presence_repository, human_authorizer)
human_fleet_query_service = TenantFleetQueryService(agent_endpoint_repository, human_authorizer, presence_repository=presence_repository, metrics=metrics)
human_group_service = TenantEndpointGroupService(SQLAlchemyEndpointGroupRepository(db_manager), agent_endpoint_repository, human_authorizer, max_members=200, metrics=metrics, audit_sink=security_audit_repository)
human_scope_service = TenantSavedFleetScopeService(SQLAlchemySavedFleetScopeRepository(db_manager), human_fleet_query_service, human_authorizer, metrics=metrics, audit_sink=security_audit_repository)
human_compliance_service = TenantComplianceService(agent_endpoint_repository, agent_assessments, human_authorizer, ravenx_windows_baseline_registry(), max_endpoints=settings.compliance_evaluation_max_endpoints, evaluator=ComplianceControlEvaluator(max_age_hours=settings.compliance_evidence_max_age_hours), metrics=metrics, logger=logger)
human_compliance_snapshot_service = TenantComplianceSnapshotService(human_compliance_service, agent_endpoint_repository, SQLAlchemyComplianceSnapshotRepository(db_manager), human_authorizer, max_endpoints=settings.compliance_evaluation_max_endpoints, audit_sink=security_audit_repository, metrics=metrics, logger=logger, group_repository=SQLAlchemyEndpointGroupRepository(db_manager), scope_repository=SQLAlchemySavedFleetScopeRepository(db_manager))
human_security_overview_service = TenantSecurityOverviewService(
    agent_endpoint_repository, presence_repository, agent_assessments, human_authorizer,
    metrics=metrics, logger=logger,
)
human_assessment_detail_service = TenantAssessmentDetailService(
    agent_endpoint_repository, agent_assessments, human_authorizer, metrics=metrics, logger=logger,
)
human_finding_recurrence_service = TenantFindingRecurrenceService(
    agent_assessments, human_assessment_detail_service, metrics=metrics, logger=logger,
)
human_finding_coverage_service = TenantFindingCoverageService(
    agent_assessments, human_assessment_detail_service,
    max_assessments=settings.finding_history_max_assessments, metrics=metrics, logger=logger,
)
human_security_observability_service = TenantSecurityObservabilityService(
    security_telemetry, human_authorizer, metrics=metrics,
)
human_audit_query_service = TenantAuditQueryService(
    security_audit_repository, human_authorizer, metrics=metrics, logger=logger,
)
human_assessment_service = TenantAssessmentService(
    agent_endpoint_repository, agent_assessments, human_dispatcher, human_authorizer,
    cancellation_service=human_cancellation,
)
human_schedule_repository = SQLAlchemyAssessmentScheduleRepository(db_manager)
human_schedule_run_repository = SQLAlchemyAssessmentScheduleRunRepository(db_manager)
human_schedule_service = TenantAssessmentScheduleService(
    human_schedule_repository, agent_endpoint_repository, human_organization_repository, human_authorizer,
    audit_sink=security_audit_repository, max_targets=settings.assessment_schedule_max_targets,
)
assessment_schedule_runner = AssessmentScheduleRunner(
    human_schedule_repository, human_schedule_run_repository, human_assessment_service,
    agent_endpoint_repository, human_organization_repository, agent_assessments,
    batch_size=settings.assessment_schedule_batch_size, audit_sink=security_audit_repository, metrics=metrics,
    group_repository=SQLAlchemyEndpointGroupRepository(db_manager), scope_repository=SQLAlchemySavedFleetScopeRepository(db_manager),
    max_targets=settings.assessment_schedule_max_targets,
)
assessment_schedule_worker = AssessmentScheduleWorker(
    assessment_schedule_runner,
    poll_interval_seconds=settings.assessment_scheduler_poll_interval_seconds,
    enabled=settings.assessment_scheduler_enabled,
    metrics=metrics,
    logger=logger,
)
app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
    human_authentication, human_sessions, human_user_repository, human_context_resolver,
    human_endpoint_service, human_assessment_service, human_organization_repository,
    human_membership_repository, human_organization_admin_service,
    login_rate_limiter, security_audit_repository, metrics, human_presence_service, human_fleet_presence_service,
    human_security_overview_service,
    human_assessment_detail_service,
    human_finding_recurrence_service,
    human_finding_coverage_service,
    human_schedule_service,
    human_fleet_query_service,
    human_group_service,
    human_scope_service,
    human_schedule_run_repository,
    human_compliance_service,
    human_compliance_snapshot_service,
    human_audit_query_service,
    human_security_observability_service,
    enrollment_service=TenantEnrollmentService(
        SQLAlchemyEnrollmentRepository(db_manager), human_authorizer,
        audit_sink=security_audit_repository),
)), prefix="/api/v1")

human_report_service = TenantFleetReportService(
    agent_endpoint_repository, presence_repository, agent_assessments, human_authorizer)
local_ai_provider = LocalOpenAIProvider(LocalAIConfig.from_config(config))
human_local_analysis_service = TenantLocalAnalysisService(human_report_service, human_authorizer, local_ai_provider)
app.include_router(create_tenant_insights_router(TenantInsightsDependencies(
    human_sessions, human_user_repository, human_context_resolver,
    human_report_service, human_local_analysis_service)), prefix="/api/v1")

# Optional legacy routes remain available when their feature dependencies are
# installed.  Core agent and human control-plane routes do not depend on them.
_mount_optional_router("backend.api.v1.scan", "/api/v1/scan", "Scanning")
_mount_optional_router("backend.api.v1.analysis", "/api/v1/analysis", "AI Analysis")
_mount_optional_router("backend.api.v1.remediation", "/api/v1/remediation", "Remediation")
_mount_optional_router("backend.api.v1.reports", "/api/v1/reports", "Reports")
_mount_optional_router("backend.api.system", "/api/v1/system", "System")

@app.websocket("/ws/realtime")
async def websocket_endpoint(websocket: WebSocket):
    """Retired channel: polling is the supported browser transport."""
    metrics.increment("websocket.rejected")
    await websocket.close(code=1008)

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    if _serve_frontend:
        return FileResponse(_frontend_dist / "index.html", headers={"Cache-Control": "no-store"})
    return {
        "name": "RAVEN-X Enterprise Security Platform",
        "version": "4.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "docs": "/api/docs",
            "health": "/health",
            "scan": "/api/v1/scan",
            "analysis": "/api/v1/analysis",
            "remediation": "/api/v1/remediation",
            "reports": "/api/v1/reports",
            "system": "/api/v1/system"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "operational",
            "ai_engine": "operational" if learning_engine is not None else "unavailable",
            "behavioral_monitor": "active" if behavioral_monitor is not None and behavioral_monitor.is_monitoring else "inactive"
        }
    }


@app.get("/ready")
async def readiness_check():
    """Report whether core control-plane dependencies can serve requests."""
    try:
        async with db_manager.get_async_db() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        metrics.increment("readiness.failures")
        return JSONResponse(status_code=503, content={"status": "not_ready", "reason": "database_unavailable"})
    return {"status": "ready", "services": {"database": "operational", "control_plane": "operational"}}

@app.get("/api/v1/stats")
async def get_platform_stats():
    """Get overall platform statistics"""
    if learning_engine is None or behavioral_monitor is None:
        raise HTTPException(status_code=503, detail="optional monitoring components are unavailable")
    learning_stats = await learning_engine.get_learning_stats()
    monitoring_stats = await behavioral_monitor.get_monitoring_stats()

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "learning": learning_stats,
        "monitoring": monitoring_stats,
        "uptime": "N/A"  # Would calculate actual uptime
    }

_frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
_serve_frontend = os.getenv("RAVENX_SERVE_FRONTEND", "false").lower() == "true"
if _serve_frontend:
    if not (_frontend_dist / "index.html").is_file():
        raise RuntimeError("Frontend build missing; run npm ci and npm run build in frontend")
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="portal")


if __name__ == "__main__":
    # Run the API server
    settings.validate()
    server_config = config.get('server', {})

    uvicorn.run(
        "backend.api.main:app",
        host=settings.server_host,
        port=server_config.get('port', 8000),
        reload=server_config.get('reload', False),
        workers=settings.server_workers,
        log_level=server_config.get('log_level', 'info')
    )
