"""Domain and application tests for the organization security activity feed."""
from datetime import datetime, timedelta, timezone

import pytest

from backend.application.audit import TenantAuditQueryService
from backend.application.organization.context import OrganizationContext
from backend.domain.audit import (AuditQuery, AuditSeverity, derive_severity, project_metadata,
                                  view_from_event)
from backend.domain.organization import OrganizationId
from backend.domain.security import (AuthorizationAction, AuthorizationResource, SecurityAuditEvent,
                                     SecurityAuditEventType, SecurityAuditOutcome, SecurityPrincipal)
from backend.domain.user import UserId
from backend.infrastructure.persistence.in_memory_security_audit_repository import (
    InMemorySecurityAuditRepository)

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


class AllowAll:
    def authorize(self, request):
        assert request.action is AuthorizationAction.AUDIT_READ
        class Decision:
            allowed = True
            reason_code = "allowed"
        return Decision()


class DenyAll:
    def __init__(self, reason="permission_not_granted"):
        self.reason = reason

    def authorize(self, request):
        outer = self
        class Decision:
            allowed = False
            reason_code = outer.reason
        return Decision()


def _event(organization_id, *, event_type="endpoint.registered", outcome=SecurityAuditOutcome.SUCCESS,
           occurred_at=NOW, principal=None, metadata=None, endpoint_id=None, user_id="user-1"):
    return SecurityAuditEvent(
        event_type=event_type,
        occurred_at=occurred_at,
        principal=principal or SecurityPrincipal.human(UserId.new()),
        action=AuthorizationAction.ENDPOINT_CREATE,
        resource=AuthorizationResource("endpoint", "endpoint-1", {"organization_id": str(organization_id)}),
        outcome=outcome,
        endpoint_id=endpoint_id,
        organization_id=str(organization_id) if organization_id else None,
        user_id=user_id,
        metadata=metadata or {},
    )


def _context(organization_id):
    return OrganizationContext(organization_id, "membership-1", UserId.new())


def _service(repository, authorizer=None):
    return TenantAuditQueryService(repository, authorizer or AllowAll())


# ----------------------------------------------------------------- severity

def test_denied_and_control_rejections_are_critical():
    assert derive_severity("authorization.denied", "denied") is AuditSeverity.CRITICAL
    assert derive_severity("agent.message_replay_rejected", "success") is AuditSeverity.CRITICAL
    assert derive_severity("endpoint.registered", "denied") is AuditSeverity.CRITICAL


def test_lifecycle_removals_and_failures_are_warnings():
    assert derive_severity("endpoint.revoked", "success") is AuditSeverity.WARNING
    assert derive_severity("assessment.failed", "success") is AuditSeverity.WARNING
    assert derive_severity("endpoint.registered", "failed") is AuditSeverity.WARNING


def test_routine_success_is_info():
    assert derive_severity("endpoint.registered", "success") is AuditSeverity.INFO


# ---------------------------------------------------------------- redaction

def test_metadata_allowlist_drops_unknown_and_sensitive_keys():
    projected = project_metadata({
        "framework_id": "ravenx.windows.baseline",
        "login": "operator@example.com",
        "email": "operator@example.com",
        "session_id": "sess-123",
        "credential_id": "cred-123",
        "client_key": "abc",
        "request_id": "req-1",
        "some_future_key": "leak",
    })
    assert projected == {"framework_id": "ravenx.windows.baseline"}


def test_projection_drops_pii_and_secret_bearing_metadata():
    org = OrganizationId.new()
    event = _event(org, metadata={"login": "operator@example.com", "session_id": "s-1",
                                  "api_token": "super-secret", "framework_id": "fw-1"})
    view = view_from_event(event)
    serialized = str(view.to_dict())
    assert "operator@example.com" not in serialized
    assert "super-secret" not in serialized
    assert "s-1" not in serialized
    assert view.metadata == {"framework_id": "fw-1"}


def test_resource_metadata_is_not_exposed():
    org = OrganizationId.new()
    view = view_from_event(_event(org))
    assert view.resource.to_dict() == {"resource_type": "endpoint", "resource_id": "endpoint-1"}
    assert "metadata" not in view.resource.to_dict()


def test_long_metadata_values_and_lists_are_bounded():
    projected = project_metadata({"reason": "x" * 5000, "scanner_ids": [f"s{i}" for i in range(50)]})
    assert len(projected["reason"]) == 200
    assert len(projected["scanner_ids"]) == 10


# --------------------------------------------------------- tenant isolation

def test_organization_a_cannot_read_organization_b_events():
    org_a, org_b = OrganizationId.new(), OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org_a, event_type="endpoint.registered"))
    repository.append(_event(org_b, event_type="endpoint.revoked"))
    repository.append(_event(org_b, event_type="assessment.created"))

    page = _service(repository).query(SecurityPrincipal.human(UserId.new()), _context(org_a), AuditQuery())
    assert page.total == 1
    assert [item.event_type for item in page.items] == ["endpoint.registered"]


def test_unattributed_events_are_never_returned_to_a_tenant():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(None, event_type="human.authentication_failed"))
    repository.append(_event(org, event_type="endpoint.registered"))

    page = _service(repository).query(SecurityPrincipal.human(UserId.new()), _context(org), AuditQuery())
    assert page.total == 1
    assert page.items[0].event_type == "endpoint.registered"


def test_caller_cannot_widen_scope_because_query_has_no_organization_field():
    assert not hasattr(AuditQuery(), "organization_id")


# ------------------------------------------------------------ authorization

def test_unauthorized_principal_is_rejected():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org))
    with pytest.raises(PermissionError):
        _service(repository, DenyAll()).query(SecurityPrincipal.human(UserId.new()), _context(org), AuditQuery())


def test_non_human_principal_is_rejected():
    org = OrganizationId.new()
    with pytest.raises(PermissionError):
        _service(InMemorySecurityAuditRepository()).query(SecurityPrincipal.system(), _context(org), AuditQuery())


def test_missing_organization_context_is_rejected():
    with pytest.raises(PermissionError):
        _service(InMemorySecurityAuditRepository()).query(SecurityPrincipal.human(UserId.new()), None, AuditQuery())


def test_denied_read_is_not_silently_empty():
    """A forbidden read must raise, never return an empty page."""
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org))
    with pytest.raises(PermissionError):
        _service(repository, DenyAll()).query(SecurityPrincipal.human(UserId.new()), _context(org), AuditQuery())


# ---------------------------------------------------------------- ordering

def test_events_are_returned_newest_first():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    for index in range(5):
        repository.append(_event(org, event_type=f"event.{index}",
                                 occurred_at=NOW + timedelta(minutes=index)))
    page = _service(repository).query(SecurityPrincipal.human(UserId.new()), _context(org), AuditQuery())
    assert [item.event_type for item in page.items] == ["event.4", "event.3", "event.2", "event.1", "event.0"]


# -------------------------------------------------------------- pagination

def test_pagination_pages_without_overlap_and_reports_total():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    for index in range(30):
        repository.append(_event(org, event_type=f"event.{index:02d}",
                                 occurred_at=NOW + timedelta(minutes=index)))
    principal, context = SecurityPrincipal.human(UserId.new()), _context(org)
    service = _service(repository)

    first = service.query(principal, context, AuditQuery(limit=10, offset=0))
    second = service.query(principal, context, AuditQuery(limit=10, offset=10))
    third = service.query(principal, context, AuditQuery(limit=10, offset=20))

    assert first.total == second.total == third.total == 30
    assert first.returned == second.returned == third.returned == 10
    assert first.has_next and second.has_next and not third.has_next
    seen = [item.event_id for item in first.items + second.items + third.items]
    assert len(set(seen)) == 30


def test_offset_beyond_total_returns_empty_page_not_error():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org))
    page = _service(repository).query(SecurityPrincipal.human(UserId.new()), _context(org),
                                      AuditQuery(limit=10, offset=500))
    assert page.items == () and page.total == 1 and not page.has_next


def test_empty_result_is_a_valid_page():
    org = OrganizationId.new()
    page = _service(InMemorySecurityAuditRepository()).query(
        SecurityPrincipal.human(UserId.new()), _context(org), AuditQuery())
    assert page.items == ()
    assert page.total == 0
    assert page.to_dict()["pagination"]["has_next"] is False


# ----------------------------------------------------------------- filtering

def test_filter_by_event_type_and_outcome():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org, event_type="endpoint.registered"))
    repository.append(_event(org, event_type="assessment.created"))
    repository.append(_event(org, event_type="authorization.denied", outcome=SecurityAuditOutcome.DENIED))
    principal, context = SecurityPrincipal.human(UserId.new()), _context(org)
    service = _service(repository)

    by_type = service.query(principal, context, AuditQuery(event_types=("assessment.created",)))
    assert by_type.total == 1 and by_type.items[0].event_type == "assessment.created"

    by_outcome = service.query(principal, context, AuditQuery(outcomes=("denied",)))
    assert by_outcome.total == 1 and by_outcome.items[0].outcome == "denied"


def test_filter_by_severity_actor_and_time_range():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    actor = SecurityPrincipal.human("11111111-1111-1111-1111-111111111111")
    repository.append(_event(org, event_type="authorization.denied",
                             outcome=SecurityAuditOutcome.DENIED, principal=actor))
    repository.append(_event(org, event_type="endpoint.registered", occurred_at=NOW - timedelta(days=5)))
    principal, context = SecurityPrincipal.human(UserId.new()), _context(org)
    service = _service(repository)

    critical = service.query(principal, context, AuditQuery(severities=("critical",)))
    assert critical.total == 1 and critical.items[0].severity is AuditSeverity.CRITICAL

    by_actor = service.query(principal, context, AuditQuery(actor_id=actor.principal_id))
    assert by_actor.total == 1

    recent = service.query(principal, context, AuditQuery(occurred_after=NOW - timedelta(hours=1)))
    assert recent.total == 1 and recent.items[0].event_type == "authorization.denied"


# ------------------------------------------------------- query validation

@pytest.mark.parametrize("kwargs", [
    {"limit": 0},
    {"limit": -1},
    {"limit": 101},
    {"limit": "twenty"},
    {"offset": -1},
    {"outcomes": ("not-an-outcome",)},
    {"severities": ("catastrophic",)},
    {"event_types": tuple(f"e{i}" for i in range(11))},
    {"actor_id": "a" * 300},
    {"occurred_after": datetime(2026, 1, 1)},
    {"occurred_after": NOW, "occurred_before": NOW - timedelta(days=1)},
])
def test_malformed_queries_are_rejected(kwargs):
    with pytest.raises(ValueError):
        AuditQuery(**kwargs)


def test_limit_is_capped_so_pagination_cannot_be_abused():
    assert AuditQuery(limit=100).limit == 100
    with pytest.raises(ValueError):
        AuditQuery(limit=100000)


def test_service_rejects_a_non_audit_query_object():
    org = OrganizationId.new()
    with pytest.raises(ValueError):
        _service(InMemorySecurityAuditRepository()).query(
            SecurityPrincipal.human(UserId.new()), _context(org), {"limit": 10})


# ------------------------------------------- permission-check suppression

def test_permission_checks_are_excluded_by_default_but_retrievable():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    for index in range(12):
        repository.append(_event(org, event_type="authorization.allowed",
                                 occurred_at=NOW + timedelta(seconds=index)))
    repository.append(_event(org, event_type="assessment.created",
                             occurred_at=NOW + timedelta(minutes=1)))
    principal, context = SecurityPrincipal.human(UserId.new()), _context(org)
    service = _service(repository)

    default = service.query(principal, context, AuditQuery())
    assert default.total == 1
    assert default.items[0].event_type == "assessment.created"
    assert default.excluded_event_types == ("authorization.allowed",)
    assert default.to_dict()["excluded_event_types"] == ["authorization.allowed"]

    complete = service.query(principal, context, AuditQuery(include_permission_checks=True))
    assert complete.total == 13
    assert complete.excluded_event_types == ()


def test_explicitly_requesting_permission_checks_by_type_returns_them():
    """An explicit event_type filter is honoured verbatim."""
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org, event_type="authorization.allowed"))
    page = _service(repository).query(SecurityPrincipal.human(UserId.new()), _context(org),
                                      AuditQuery(event_types=("authorization.allowed",)))
    assert page.total == 1
    assert page.excluded_event_types == ()


def test_include_permission_checks_must_be_boolean():
    with pytest.raises(ValueError):
        AuditQuery(include_permission_checks="yes")


# ------------------------------------------------------------- serialization

def test_page_serializes_with_pagination_envelope():
    org = OrganizationId.new()
    repository = InMemorySecurityAuditRepository()
    repository.append(_event(org, event_type=SecurityAuditEventType.ENDPOINT_REGISTERED.value))
    page = _service(repository).query(SecurityPrincipal.human(UserId.new()), _context(org), AuditQuery(limit=5))
    data = page.to_dict()
    assert set(data) == {"items", "pagination", "excluded_event_types"}
    assert data["pagination"] == {"limit": 5, "offset": 0, "returned": 1, "total": 1, "has_next": False}
    item = data["items"][0]
    assert item["event_type"] == "endpoint.registered"
    assert item["severity"] == "info"
    assert item["actor"]["principal_type"] == "human"
    assert item["occurred_at"].endswith("+00:00")
