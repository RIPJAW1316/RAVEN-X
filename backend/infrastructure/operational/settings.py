"""Explicit, small application-operational settings model."""

from dataclasses import dataclass
import os
import sys
from typing import Mapping


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class ApplicationSettings:
    environment: str = "development"
    server_host: str = "127.0.0.1"
    server_workers: int = 1
    database_type: str = "sqlite"
    session_lifetime_seconds: int = 8 * 60 * 60
    login_rate_limit: int = 5
    login_rate_window_seconds: int = 60
    heartbeat_interval_seconds: int = 60
    heartbeat_stale_after_seconds: int = 180
    heartbeat_offline_after_seconds: int = 600
    presence_maintenance_enabled: bool = False
    presence_maintenance_interval_seconds: int = 60
    presence_evaluation_batch_size: int = 100
    trusted_proxy: bool = False
    cors_origins: tuple[str, ...] = ()
    # Legacy scan/analysis/remediation/system routers are unauthenticated and
    # execute on the server host.  They are opt-in, never on by default, and
    # are refused outright in production.
    enable_legacy_routes: bool = False
    max_request_id_length: int = 64
    finding_history_max_assessments: int = 100
    assessment_schedule_max_targets: int = 100
    assessment_schedule_batch_size: int = 100
    assessment_scheduler_enabled: bool = False
    assessment_scheduler_poll_interval_seconds: int = 30
    assessment_execution_timeout_seconds: int = 1800
    compliance_evidence_max_age_hours: int = 24
    compliance_evaluation_max_endpoints: int = 100
    compliance_retention_enabled: bool = False
    compliance_retention_interval_hours: int = 24
    compliance_retention_max_age_days: int = 365
    compliance_retention_max_snapshots: int = 1000
    compliance_retention_min_snapshots: int = 10
    # Diagnostic only: persist an audit record for every successful
    # permission check.  Off by default because routine checks are
    # implementation detail, not audit records.  Denials are always
    # recorded and are unaffected by this flag.
    audit_record_authorization_success: bool = False

    @classmethod
    def from_environment(cls, config: Mapping | None = None) -> "ApplicationSettings":
        config = config or {}
        app_config = config.get("application", {}) if isinstance(config, Mapping) else {}
        server_config = config.get("server", {}) if isinstance(config, Mapping) else {}
        database_config = config.get("database", {}) if isinstance(config, Mapping) else {}
        security = config.get("security", {}) if isinstance(config, Mapping) else {}
        limits = security.get("rate_limiting", {}) if isinstance(security, Mapping) else {}
        # Precedence: RAVENX_ENVIRONMENT, then config.yaml, then "development".
        # The env var default used to be a non-empty string, so the config
        # file value could never win and a config declaring production ran
        # with development safety checks.
        env = (os.getenv("RAVENX_ENVIRONMENT") or "").strip().lower()
        configured_env = str(app_config.get("environment", "") or "").strip().lower()
        origins_raw = os.getenv("RAVENX_CORS_ORIGINS", "")
        origins = tuple(item.strip() for item in origins_raw.split(",") if item.strip())
        return cls(
            environment=env or configured_env or "development",
            server_host=str(server_config.get("host", "127.0.0.1")),
            server_workers=_int_env("RAVENX_SERVER_WORKERS", int(server_config.get("workers", 1))),
            database_type=str(database_config.get("type", "sqlite")).strip().lower(),
            session_lifetime_seconds=_int_env("RAVENX_SESSION_LIFETIME_SECONDS", 8 * 60 * 60),
            login_rate_limit=_int_env("RAVENX_LOGIN_RATE_LIMIT", int(limits.get("requests_per_minute", 5) or 5)),
            login_rate_window_seconds=_int_env("RAVENX_LOGIN_RATE_WINDOW_SECONDS", 60),
            heartbeat_interval_seconds=_int_env("RAVENX_HEARTBEAT_INTERVAL_SECONDS", 60),
            heartbeat_stale_after_seconds=_int_env("RAVENX_HEARTBEAT_STALE_AFTER_SECONDS", 180),
            heartbeat_offline_after_seconds=_int_env("RAVENX_HEARTBEAT_OFFLINE_AFTER_SECONDS", 600),
            presence_maintenance_enabled=_bool_env("RAVENX_PRESENCE_MAINTENANCE_ENABLED", False),
            presence_maintenance_interval_seconds=_int_env("RAVENX_PRESENCE_MAINTENANCE_INTERVAL_SECONDS", 60),
            presence_evaluation_batch_size=_int_env("RAVENX_PRESENCE_EVALUATION_BATCH_SIZE", 100),
            trusted_proxy=_bool_env("RAVENX_TRUSTED_PROXY", False),
            cors_origins=origins,
            enable_legacy_routes=_bool_env("RAVENX_ENABLE_LEGACY_ROUTES", False),
            finding_history_max_assessments=_int_env("RAVENX_FINDING_HISTORY_MAX_ASSESSMENTS", 100),
            assessment_schedule_max_targets=_int_env("RAVENX_ASSESSMENT_SCHEDULE_MAX_TARGETS", 100),
            assessment_schedule_batch_size=_int_env("RAVENX_ASSESSMENT_SCHEDULE_BATCH_SIZE", 100),
            assessment_scheduler_enabled=_bool_env("RAVENX_ASSESSMENT_SCHEDULER_ENABLED", False),
            assessment_scheduler_poll_interval_seconds=_int_env("RAVENX_ASSESSMENT_SCHEDULER_POLL_INTERVAL_SECONDS", 30),
            assessment_execution_timeout_seconds=_int_env("RAVENX_ASSESSMENT_EXECUTION_TIMEOUT_SECONDS", 1800),
            compliance_evidence_max_age_hours=_int_env("RAVENX_COMPLIANCE_EVIDENCE_MAX_AGE_HOURS", 24),
            compliance_evaluation_max_endpoints=_int_env("RAVENX_COMPLIANCE_EVALUATION_MAX_ENDPOINTS", 100),
            compliance_retention_enabled=_bool_env("RAVENX_COMPLIANCE_RETENTION_ENABLED", False),
            compliance_retention_interval_hours=_int_env("RAVENX_COMPLIANCE_RETENTION_INTERVAL_HOURS", 24),
            compliance_retention_max_age_days=_int_env("RAVENX_COMPLIANCE_RETENTION_MAX_AGE_DAYS", 365),
            compliance_retention_max_snapshots=_int_env("RAVENX_COMPLIANCE_RETENTION_MAX_SNAPSHOTS", 1000),
            compliance_retention_min_snapshots=_int_env("RAVENX_COMPLIANCE_RETENTION_MIN_SNAPSHOTS", 10),
            audit_record_authorization_success=_bool_env("RAVENX_AUDIT_AUTHORIZATION_SUCCESS", False),
        )

    def validate(self) -> "ApplicationSettings":
        self.validate_pre_mount()
        if self.environment == "production" and self.enable_legacy_routes:
            # The legacy routers run PowerShell and remediation on the server
            # host with no authentication.  Refuse to start rather than serve
            # them in production.
            raise ConfigurationError(
                "production refuses legacy routes: unset RAVENX_ENABLE_LEGACY_ROUTES")
        if self.environment == "production" and sys.version_info[:2] != (3, 13):
            raise ConfigurationError("production requires supported Python 3.13 runtime")
        return self

    def validate_pre_mount(self) -> "ApplicationSettings":
        """Reject settings that would create an unsafe ASGI app before lifespan."""
        if self.environment not in {"development", "test", "production"}:
            raise ConfigurationError("environment must be development, test, or production")
        if self.server_workers <= 0:
            raise ConfigurationError("server workers must be positive")
        if self.database_type == "sqlite" and self.server_workers != 1:
            raise ConfigurationError("SQLite requires exactly one server worker")
        if self.session_lifetime_seconds <= 0:
            raise ConfigurationError("session lifetime must be positive")
        if self.login_rate_limit <= 0 or self.login_rate_window_seconds <= 0:
            raise ConfigurationError("login rate-limit values must be positive")
        if self.heartbeat_interval_seconds <= 0 or self.heartbeat_stale_after_seconds <= self.heartbeat_interval_seconds or self.heartbeat_offline_after_seconds <= self.heartbeat_stale_after_seconds:
            raise ConfigurationError("heartbeat thresholds must be interval < stale < offline")
        if self.presence_maintenance_interval_seconds <= 0 or self.presence_evaluation_batch_size <= 0:
            raise ConfigurationError("presence maintenance values must be positive")
        if self.finding_history_max_assessments <= 0:
            raise ConfigurationError("finding history bound must be positive")
        if self.assessment_schedule_max_targets <= 0 or self.assessment_schedule_batch_size <= 0:
            raise ConfigurationError("assessment schedule bounds must be positive")
        if self.assessment_scheduler_poll_interval_seconds <= 0:
            raise ConfigurationError("assessment scheduler poll interval must be positive")
        if not 60 <= self.assessment_execution_timeout_seconds <= 86400:
            raise ConfigurationError("assessment execution timeout must be between 60 and 86400 seconds")
        if self.compliance_evidence_max_age_hours <= 0 or self.compliance_evaluation_max_endpoints <= 0:
            raise ConfigurationError("compliance bounds must be positive")
        if self.compliance_retention_interval_hours <= 0 or self.compliance_retention_max_age_days < 0 or self.compliance_retention_max_snapshots <= 0 or self.compliance_retention_min_snapshots <= 0 or self.compliance_retention_min_snapshots > self.compliance_retention_max_snapshots:
            raise ConfigurationError("invalid compliance retention settings")
        if self.environment == "production" and "*" in self.cors_origins:
            raise ConfigurationError("production refuses wildcard CORS origins")
        return self


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return int(default)
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes"}
