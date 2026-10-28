"""WS-01 upgrade planning, SQLite migration, and rollback refusal gates."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets

import pytest
from sqlalchemy import create_engine, inspect, text

from backend.application.enrollment import EnrollmentService
from backend.application.ops.rollback import evaluate_database_restore, evaluate_server_rollback
from backend.application.ops.schema import (
    CURRENT_SCHEMA_VERSION,
    apply_sqlite_migrations,
    schema_version,
)
from backend.application.ops.upgrade import apply_staged_code, plan_inplace_upgrade
from backend.domain.endpoint import EndpointStatus, PlatformInfo
from backend.domain.enrollment import CredentialId, EnrollmentRequest
from backend.domain.organization import Organization, OrganizationId
from backend.infrastructure.persistence.in_memory_enrollment_repository import InMemoryEnrollmentRepository
from backend.infrastructure.persistence.in_memory_organization_repository import InMemoryOrganizationRepository
from backend.infrastructure.persistence.in_memory_security_audit_repository import InMemorySecurityAuditRepository


T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
RENEW_AT = T0 + timedelta(days=1)


def _service():
    repository = InMemoryEnrollmentRepository()
    organizations = InMemoryOrganizationRepository()
    organization = Organization(OrganizationId.new(), "Tenant", created_at=T0, updated_at=T0)
    organizations.add(organization)
    service = EnrollmentService(repository, audit_sink=InMemorySecurityAuditRepository(),
                                organization_repository=organizations, verifier_key=secrets.token_bytes(32))
    authorization, token = service.create_enrollment_authorization(now=T0, organization_id=organization.organization_id)
    endpoint, credential, secret = service.accept_enrollment(
        authorization.enrollment_id, token.value, EnrollmentRequest("win-01", PlatformInfo("Windows")),
        now=T0, credential_ttl=timedelta(days=5))
    repository.endpoints[str(endpoint.endpoint_id)] = endpoint.transition_to(EndpointStatus.ACTIVE, T0)
    return repository, service, credential, secret.value


def test_pre_renewal_sqlite_database_gains_the_versioned_renewal_table(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'v1.db').as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE endpoints (endpoint_id VARCHAR(36) PRIMARY KEY)"))
    assert schema_version(engine) == 1
    assert "endpoint_credential_renewals" not in inspect(engine).get_table_names()

    version = apply_sqlite_migrations(engine)
    assert version == CURRENT_SCHEMA_VERSION
    assert schema_version(engine) == CURRENT_SCHEMA_VERSION
    tables = set(inspect(engine).get_table_names())
    assert "endpoint_credential_renewals" in tables
    assert "ravenx_schema_versions" in tables
    apply_sqlite_migrations(engine)
    with engine.connect() as connection:
        count = connection.execute(text("SELECT COUNT(*) FROM ravenx_schema_versions WHERE version = 2")).scalar()
    assert count == 1


def test_postgres_migration_is_an_explicit_separate_gate():
    class _Engine:
        dialect = type("D", (), {"name": "postgresql"})()

    with pytest.raises(ValueError, match="PostgreSQL is a separate validation gate"):
        apply_sqlite_migrations(_Engine())


def test_rollback_before_any_renewal_is_allowed():
    repository, service, credential, secret = _service()
    decision = evaluate_server_rollback(repository, target_schema=1)
    assert decision.allowed and decision.code == "code_rollback_safe"
    assert service.verify_credential(
        repository.endpoints[str(credential.endpoint_id)].endpoint_id, secret, now=RENEW_AT
    ).credential_id == credential.credential_id


def test_rollback_is_refused_while_a_renewal_is_unconfirmed():
    repository, service, credential, secret = _service()
    successor = CredentialId.new(), secrets.token_urlsafe(32)
    service.renew_credential(credential.endpoint_id, secret, claimed_credential_id=credential.credential_id,
                             successor_credential_id=successor[0], successor_secret=successor[1], now=RENEW_AT)
    decision = evaluate_server_rollback(repository, target_schema=1)
    assert not decision.allowed
    assert decision.code == "pending_renewal_lineage"
    assert decision.operator_action == "wait_for_confirmation_or_revoke_and_reenroll"


def test_rollback_after_confirmation_is_refused_while_hmac_successors_remain_active():
    repository, service, credential, secret = _service()
    successor = CredentialId.new(), secrets.token_urlsafe(32)
    service.renew_credential(credential.endpoint_id, secret, claimed_credential_id=credential.credential_id,
                             successor_credential_id=successor[0], successor_secret=successor[1], now=RENEW_AT)
    service.confirm_credential_renewal(credential.endpoint_id, successor[1],
                                      claimed_credential_id=successor[0], now=RENEW_AT + timedelta(minutes=1))
    decision = evaluate_server_rollback(repository, target_schema=1)
    assert not decision.allowed
    assert decision.code == "incompatible_hmac_successors"
    assert "token-hmac-v2" in decision.message


def test_rollback_is_allowed_again_after_compromise_revocation_and_no_active_hmac():
    repository, service, credential, secret = _service()
    successor = CredentialId.new(), secrets.token_urlsafe(32)
    service.renew_credential(credential.endpoint_id, secret, claimed_credential_id=credential.credential_id,
                             successor_credential_id=successor[0], successor_secret=successor[1], now=RENEW_AT)
    service.confirm_credential_renewal(credential.endpoint_id, successor[1],
                                      claimed_credential_id=successor[0], now=RENEW_AT + timedelta(minutes=1))
    service.revoke_compromised_credential(credential.credential_id, now=RENEW_AT + timedelta(minutes=2),
                                          reason="contain before rollback")
    decision = evaluate_server_rollback(repository, target_schema=1)
    assert decision.allowed and decision.code == "code_rollback_safe"


def test_database_restore_is_refused_when_the_backup_is_missing_live_credentials():
    refused = evaluate_database_restore(live_credential_ids=("live-new", "live-old"),
                                        backup_credential_ids=("live-old",))
    assert not refused.allowed
    assert refused.code == "backup_missing_live_credentials"
    # Identifier equality used to approve a backup. That ignored status and
    # revocation history, so a matching id is now an incomplete history refusal.
    incomplete = evaluate_database_restore(live_credential_ids=("live-old",),
                                           backup_credential_ids=("live-old", "archived"))
    assert not incomplete.allowed
    assert incomplete.code == "restore_history_incomplete"


def test_upgrade_scripts_refuse_installed_omen_paths():
    root = Path(__file__).resolve().parents[2]
    for name in ("upgrade-server.ps1", "upgrade-agent.ps1"):
        text = (root / "scripts" / name).read_text(encoding="utf-8")
        assert "installed Omen path and is refused" in text
        assert "Execute" in text


def test_inplace_upgrade_plan_is_testable_against_disposable_trees(tmp_path):
    source, install, data = tmp_path / "pkg", tmp_path / "install", tmp_path / "data"
    source.mkdir()
    install.mkdir()
    data.mkdir()
    (install / "VERSION").write_text("0.4.0", encoding="utf-8")
    (source / "VERSION").write_text("0.5.0-ws01", encoding="utf-8")
    plan = plan_inplace_upgrade(source_root=source, install_root=install, data_root=data,
                                package_sha256="ab" * 32, expected_sha256="AB" * 32)
    assert plan.allowed
    assert "apply_sqlite_migrations" in plan.steps
    assert "evaluate_server_rollback_before_any_downgrade" in plan.steps
    assert not plan_inplace_upgrade(source_root=source, install_root=install, data_root=data,
                                    package_sha256="00" * 32, expected_sha256="ff" * 32).allowed
    assert not plan_inplace_upgrade(source_root=source, install_root=tmp_path / "missing",
                                    data_root=data).allowed

    class _Files:
        def atomic_write_protected(self, path, data):
            Path(path).write_bytes(data)

        def atomic_create_protected(self, path, data):
            Path(path).write_bytes(data)

    apply_staged_code(staged_root=source, install_root=install, files=_Files())
    assert (install / "VERSION").read_text(encoding="utf-8") == "0.5.0-ws01"
