"""Versioned SQLite schema upgrades for existing installations.

PostgreSQL is an explicit separate validation requirement and is refused here.
``create_all`` remains additive; this module records a version and creates the
WS-01 renewal table if an older database is missing it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import inspect, text


PRE_RENEWAL_SCHEMA_VERSION = 1
CURRENT_SCHEMA_VERSION = 2
SCHEMA_NAMES = {
    1: "baseline-pre-renewal",
    2: "ws01-credential-renewal",
}


class SchemaVersionError(RuntimeError):
    """Version metadata is missing, empty, or inconsistent with stored credentials."""


def renewal_capability_counts(engine) -> tuple[int, int]:
    """Return ``(open renewal lineages, active token-hmac-v2 credentials)``."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    open_lineages = 0
    active_hmac = 0
    with engine.connect() as connection:
        if "endpoint_credential_renewals" in tables:
            open_lineages = int(connection.execute(text(
                "SELECT COUNT(*) FROM endpoint_credential_renewals "
                "WHERE confirmed_at IS NULL OR predecessor_closed_at IS NULL"
            )).scalar() or 0)
        if "endpoint_credentials" in tables:
            active_hmac = int(connection.execute(text(
                "SELECT COUNT(*) FROM endpoint_credentials "
                "WHERE status = 'active' AND verifier LIKE 'token-hmac-v2$%'"
            )).scalar() or 0)
    return open_lineages, active_hmac


def schema_version(engine) -> int:
    """Return the recorded schema version.

    An empty or missing ``ravenx_schema_versions`` table is schema 1 only when
    the database also has no renewal rows and no active HMAC credentials.
    Those rows make the metadata ambiguous: this function refuses instead of
    reporting a pre-renewal database.
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    has_versions = "ravenx_schema_versions" in tables
    has_renewals = "endpoint_credential_renewals" in tables
    open_lineages, active_hmac = renewal_capability_counts(engine)
    renewal_rows = 0
    if has_renewals:
        with engine.connect() as connection:
            renewal_rows = int(connection.execute(text(
                "SELECT COUNT(*) FROM endpoint_credential_renewals")).scalar() or 0)
    evidence = bool(renewal_rows or open_lineages or active_hmac)
    if not has_versions:
        if evidence:
            raise SchemaVersionError(
                "schema version metadata is missing while renewal or HMAC credentials exist")
        return PRE_RENEWAL_SCHEMA_VERSION
    with engine.connect() as connection:
        version_rows = int(connection.execute(text(
            "SELECT COUNT(*) FROM ravenx_schema_versions")).scalar() or 0)
        recorded = connection.execute(text("SELECT MAX(version) FROM ravenx_schema_versions")).scalar()
    if version_rows == 0 or recorded is None:
        if evidence:
            raise SchemaVersionError(
                "schema version metadata is empty while renewal or HMAC credentials exist")
        return PRE_RENEWAL_SCHEMA_VERSION
    try:
        version = int(recorded)
    except (TypeError, ValueError) as error:
        raise SchemaVersionError("schema version metadata is malformed") from error
    if version not in SCHEMA_NAMES:
        raise SchemaVersionError("schema version metadata is not recognized")
    if version < CURRENT_SCHEMA_VERSION and evidence:
        raise SchemaVersionError(
            "recorded schema version is inconsistent with renewal or HMAC credentials")
    return version


def apply_sqlite_migrations(engine, *, now=None) -> int:
    if engine.dialect.name != "sqlite":
        raise ValueError("this prototype migrates SQLite only; PostgreSQL is a separate validation gate")
    current = schema_version(engine)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        if "ravenx_schema_versions" not in tables:
            connection.execute(text(
                "CREATE TABLE ravenx_schema_versions ("
                "version INTEGER PRIMARY KEY, name VARCHAR(80) NOT NULL, applied_at DATETIME NOT NULL)"
            ))
        if "endpoint_credential_renewals" not in tables:
            connection.execute(text(
                "CREATE TABLE endpoint_credential_renewals ("
                "successor_credential_id VARCHAR(36) PRIMARY KEY, "
                "predecessor_credential_id VARCHAR(36) NOT NULL UNIQUE, "
                "endpoint_id VARCHAR(36) NOT NULL, "
                "organization_id VARCHAR(36), "
                "issued_at DATETIME NOT NULL, "
                "predecessor_valid_until DATETIME NOT NULL, "
                "confirmed_at DATETIME, "
                "predecessor_closed_at DATETIME, "
                "closed_reason VARCHAR(40), "
                "CHECK (successor_credential_id <> predecessor_credential_id))"
            ))
            connection.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_endpoint_credential_renewals_endpoint_id "
                "ON endpoint_credential_renewals (endpoint_id)"
            ))
        applied = now or datetime.now(timezone.utc)
        stored = applied.astimezone(timezone.utc).replace(tzinfo=None)
        if current < CURRENT_SCHEMA_VERSION:
            connection.execute(
                text("INSERT OR IGNORE INTO ravenx_schema_versions (version, name, applied_at) "
                     "VALUES (:version, :name, :applied_at)"),
                {"version": CURRENT_SCHEMA_VERSION, "name": SCHEMA_NAMES[CURRENT_SCHEMA_VERSION],
                 "applied_at": stored},
            )
        elif current == CURRENT_SCHEMA_VERSION:
            connection.execute(
                text("INSERT OR IGNORE INTO ravenx_schema_versions (version, name, applied_at) "
                     "VALUES (:version, :name, :applied_at)"),
                {"version": CURRENT_SCHEMA_VERSION, "name": SCHEMA_NAMES[CURRENT_SCHEMA_VERSION],
                 "applied_at": stored},
            )
    return CURRENT_SCHEMA_VERSION
