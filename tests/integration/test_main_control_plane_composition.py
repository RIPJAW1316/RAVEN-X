"""Actual production-app composition checks with isolated SQLite state."""
import os
from fastapi.testclient import TestClient
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from backend.application.identity import HumanIdentityService
from backend.application.organization import OrganizationMembershipService, OrganizationService
from backend.application.rbac import RoleBindingService, RoleService
from backend.domain.security import SecurityPrincipal


def test_main_mounts_human_and_agent_boundaries_with_isolated_database(tmp_path):
    import backend.api.main as main

    from backend.infrastructure.security.windows_files import protect_private_directory
    database_dir = Path(os.environ["LOCALAPPDATA"]) / "RAVEN-X" / "ws01-api-tests" / uuid4().hex
    database_dir.mkdir(parents=True)
    if os.name == "nt":
        protect_private_directory(database_dir)
    manager = main.db_manager
    manager.config = {"type": "sqlite", "sqlite_path": str(database_dir / "control-plane.db"), "echo": False}
    manager.engine = manager.async_engine = manager.SessionLocal = manager.AsyncSessionLocal = None
    manager.create_tables()

    user = HumanIdentityService(main.human_user_repository).create_initial_user("admin@example.com", "Admin", "CONTROL_PLANE_PASSWORD")
    organization = OrganizationService(main.human_organization_repository).create("Control Plane")
    membership = OrganizationMembershipService(main.human_membership_repository, main.human_organization_repository, main.human_user_repository).create(user.user_id, organization.organization_id)
    role = RoleService(main.human_role_repository).create(organization.organization_id, "Reader", ["organization.read"])
    RoleBindingService(main.human_role_binding_repository, main.human_role_repository, main.human_membership_repository).create(organization.organization_id, membership.membership_id, role.role_id)

    with TestClient(main.app) as client:
        assert any("/findings/{occurrence_id}/coverage" in route.path for route in main.app.routes)
        login = client.post("/api/v1/auth/login", json={"email": user.email, "password": "CONTROL_PLANE_PASSWORD"})
        assert login.status_code == 200
        token = login.json()["session_token"]
        assert client.get(f"/api/v1/organizations/{organization.organization_id}", headers={"Authorization": f"Bearer {token}"}).status_code == 200
        # A human session never authenticates as an endpoint credential.
        endpoint_id = str(uuid4())
        envelope = {"message_id": str(uuid4()), "message_type": "agent.heartbeat", "protocol_version": "1.0",
                    "endpoint_id": endpoint_id, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "correlation_id": None, "nonce": None,
                    "payload": {"endpoint_id": endpoint_id, "agent_version": "1.0", "protocol_version": "1.0",
                                "observed_at": datetime.now(timezone.utc).isoformat()}}
        assert client.post("/api/v1/agent/messages", json=envelope, headers={"Authorization": f"Bearer {token}"}).status_code == 401
