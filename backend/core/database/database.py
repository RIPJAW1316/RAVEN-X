"""
RAVEN-X Enterprise - Database Manager
Handles all database connections and session management
"""

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool, StaticPool
from contextlib import asynccontextmanager, contextmanager
import yaml
import logging
import os
from pathlib import Path
from typing import AsyncGenerator, Generator

from .models import Base

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"


def resolve_config_path(config_path=None) -> Path:
    """Resolve the shared API/database configuration independently of cwd."""
    selected = config_path if config_path is not None else os.getenv("RAVENX_CONFIG_PATH")
    return Path(selected).expanduser().resolve() if selected else DEFAULT_CONFIG_PATH


def _configure_sqlite_connection(dbapi_conn, *, memory: bool) -> None:
    """Apply durability pragmas on every SQLite connection.

    ``synchronous=FULL`` (integer 2) makes SQLite wait until the WAL frames for
    a commit are flushed to the operating system. That is stronger than
    ``NORMAL``, which may defer that flush. It does not, by itself, prove that
    a disk write cache or a sudden power loss cannot drop the commit. Hardware
    power-loss safety remains a physical qualification gate.

    Each commit pays for that flush, so enrollment, revocation, and assessment
    writes have higher latency than they did under ``NORMAL``: about one
    storage flush per transaction instead of a deferred checkpoint.
    """
    cursor = dbapi_conn.cursor()
    try:
        cursor.execute("PRAGMA busy_timeout=30000")
        if not memory:
            cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA synchronous")
        if int(cursor.fetchone()[0]) != 2:
            raise RuntimeError("SQLite synchronous mode is not FULL")
        if not memory:
            cursor.execute("PRAGMA journal_mode")
            if str(cursor.fetchone()[0]).lower() != "wal":
                raise RuntimeError("SQLite journal mode is not WAL")
    finally:
        cursor.close()


class DatabaseManager:
    def __init__(self, config_path: str | Path | None = None):
        """Initialize database manager with configuration"""
        self.config_path = resolve_config_path(config_path)
        self.config = self._load_config(self.config_path)
        self.engine = None
        self.async_engine = None
        self.SessionLocal = None
        self.AsyncSessionLocal = None

    def _load_config(self, config_path: Path) -> dict:
        """Load database configuration from YAML"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            database_config = config['database']
            if not isinstance(database_config, dict):
                raise ValueError("database configuration must be a mapping")
            return database_config
        except Exception as e:
            logger.error("Failed to load database configuration error_type=%s", type(e).__name__)
            raise ValueError("database configuration is unavailable or invalid") from e

    def _sqlite_database_path(self) -> str:
        override = os.getenv("RAVENX_DATABASE_PATH")
        if override is not None and not override.strip():
            raise ValueError("RAVENX_DATABASE_PATH must not be empty")
        selected = override if override is not None else self.config.get('sqlite_path', 'data/raven_x.db')
        if str(selected) == ':memory:':
            return ':memory:'
        path = Path(selected).expanduser()
        if not path.is_absolute():
            # The shipped config historically names data/raven_x.db relative to
            # the repository root. Custom configs resolve their own relative DB
            # paths beside the config file.
            base = PROJECT_ROOT if self.config_path == DEFAULT_CONFIG_PATH else self.config_path.parent
            path = base / path
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path.as_posix()

    def get_database_url(self, async_mode: bool = False) -> str:
        """Get database URL based on configuration"""
        db_type = self.config.get('type', 'sqlite')

        if db_type == 'sqlite':
            db_path = self._sqlite_database_path()

            if async_mode:
                return f"sqlite+aiosqlite:///{db_path}"
            return f"sqlite:///{db_path}"

        elif db_type == 'postgresql':
            if os.getenv("RAVENX_DATABASE_PATH") is not None:
                raise ValueError("RAVENX_DATABASE_PATH requires SQLite configuration")
            pg_config = self.config.get('postgresql', {})
            host = pg_config.get('host', 'localhost')
            port = pg_config.get('port', 5432)
            database = pg_config.get('database', 'raven_x')
            username = pg_config.get('username', 'raven_admin')
            password = pg_config.get('password', 'password')

            driver = "postgresql+asyncpg" if async_mode else "postgresql"
            return URL.create(driver, username=username, password=password,
                              host=host, port=port, database=database).render_as_string(hide_password=False)

        else:
            raise ValueError(f"Unsupported database type: {db_type}")

    def initialize_sync_engine(self):
        """Initialize synchronous database engine"""
        database_url = self.get_database_url(async_mode=False)

        connect_args = {}
        engine_kwargs = {'echo': self.config.get('echo', False)}

        if database_url.startswith('sqlite'):
            # SQLite-specific configuration
            connect_args = {"check_same_thread": False, "timeout": 30.0}
            engine_kwargs['poolclass'] = StaticPool if database_url.endswith(':memory:') else NullPool
            # Don't add pool_size and max_overflow for SQLite
        else:
            # PostgreSQL-specific configuration
            engine_kwargs['pool_size'] = self.config.get('pool_size', 20)
            engine_kwargs['max_overflow'] = self.config.get('max_overflow', 10)

        self.engine = create_engine(
            database_url,
            connect_args=connect_args,
            **engine_kwargs
        )

        # Enable WAL mode for SQLite
        if database_url.startswith('sqlite'):
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                _configure_sqlite_connection(dbapi_conn, memory=database_url.endswith(':memory:'))

        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

        logger.info("Sync database engine initialized type=%s", self.config.get('type', 'sqlite'))

    def initialize_async_engine(self):
        """Initialize asynchronous database engine"""
        database_url = self.get_database_url(async_mode=True)

        connect_args = {}
        engine_kwargs = {'echo': self.config.get('echo', False)}

        if database_url.startswith('sqlite'):
            connect_args = {"check_same_thread": False, "timeout": 30.0}
            engine_kwargs['poolclass'] = StaticPool if database_url.endswith(':memory:') else NullPool
        else:
            # PostgreSQL only
            pass

        self.async_engine = create_async_engine(
            database_url,
            connect_args=connect_args,
            **engine_kwargs
        )
        if database_url.startswith('sqlite'):
            @event.listens_for(self.async_engine.sync_engine, "connect")
            def set_async_sqlite_pragma(dbapi_conn, connection_record):
                _configure_sqlite_connection(dbapi_conn, memory=database_url.endswith(':memory:'))

        self.AsyncSessionLocal = async_sessionmaker(
            self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        logger.info("Async database engine initialized type=%s", self.config.get('type', 'sqlite'))

    def create_tables(self):
        """Create all database tables"""
        if not self.engine:
            self.initialize_sync_engine()

        try:
            Base.metadata.create_all(bind=self.engine)
            self._upgrade_legacy_tenancy_columns()
            if self.engine.dialect.name == "sqlite":
                from backend.application.ops.schema import apply_sqlite_migrations
                apply_sqlite_migrations(self.engine)
            # create_all does not add indexes to pre-existing tables.  Bearer
            # authentication must use an indexed exact verifier lookup there.
            with self.engine.begin() as connection:
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_human_sessions_token_verifier ON human_sessions (token_verifier)"))
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error("Failed to create tables error_type=%s", type(e).__name__)
            raise

    def _upgrade_legacy_tenancy_columns(self):
        """Apply only the additive tenancy columns needed by Phase 3D.

        ``create_all`` does not alter existing SQLite tables.  This narrow,
        idempotent upgrade preserves legacy rows as NULL/unassigned and avoids
        introducing a general migration framework in this phase.
        """
        if self.engine is None or self.engine.dialect.name != "sqlite":
            return
        inspector = inspect(self.engine)
        with self.engine.begin() as connection:
            tables = set(inspector.get_table_names())
            if "endpoints" in tables:
                columns = {item["name"] for item in inspector.get_columns("endpoints")}
                if "organization_id" not in columns:
                    connection.execute(text("ALTER TABLE endpoints ADD COLUMN organization_id VARCHAR(36)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_endpoints_organization_id ON endpoints (organization_id)"))
            if "endpoint_enrollments" in tables:
                columns = {item["name"] for item in inspector.get_columns("endpoint_enrollments")}
                if "organization_id" not in columns:
                    connection.execute(text("ALTER TABLE endpoint_enrollments ADD COLUMN organization_id VARCHAR(36)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_endpoint_enrollments_organization_id ON endpoint_enrollments (organization_id)"))
            if "remote_assessments" in tables:
                columns = {item["name"] for item in inspector.get_columns("remote_assessments")}
                if "organization_id" not in columns:
                    connection.execute(text("ALTER TABLE remote_assessments ADD COLUMN organization_id VARCHAR(36)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_remote_assessments_organization_id ON remote_assessments (organization_id)"))
                if "schedule_id" not in columns:
                    connection.execute(text("ALTER TABLE remote_assessments ADD COLUMN schedule_id VARCHAR(36)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_remote_assessments_schedule_id ON remote_assessments (schedule_id)"))
            if "assessment_schedules" in tables:
                columns={item["name"] for item in inspector.get_columns("assessment_schedules")}
                if "target_type" not in columns: connection.execute(text("ALTER TABLE assessment_schedules ADD COLUMN target_type VARCHAR(40)"))
                if "target_reference_id" not in columns: connection.execute(text("ALTER TABLE assessment_schedules ADD COLUMN target_reference_id VARCHAR(36)"))
                connection.execute(text("UPDATE assessment_schedules SET target_type='explicit_endpoints' WHERE target_type IS NULL"))
            if "assessment_schedule_runs" in tables:
                columns={item["name"] for item in inspector.get_columns("assessment_schedule_runs")}
                for name,kind in (("resolved_endpoint_ids","JSON"),("targets_resolved_at","DATETIME"),("target_type","VARCHAR(40)"),("target_reference_id","VARCHAR(36)"),("scope_criteria_snapshot","JSON"),("resolution_reason","VARCHAR(100)")):
                    if name not in columns: connection.execute(text(f"ALTER TABLE assessment_schedule_runs ADD COLUMN {name} {kind}"))
                # Backfill only where the endpoint has one unambiguous owner.
                connection.execute(text("""UPDATE remote_assessments
                    SET organization_id = (SELECT organization_id FROM endpoints e
                                           WHERE e.endpoint_id = remote_assessments.endpoint_id)
                    WHERE organization_id IS NULL
                      AND EXISTS (SELECT 1 FROM endpoints e
                                  WHERE e.endpoint_id = remote_assessments.endpoint_id
                                    AND e.organization_id IS NOT NULL)"""))
            if "agent_work_items" in tables:
                columns = {item["name"] for item in inspector.get_columns("agent_work_items")}
                if "organization_id" not in columns:
                    connection.execute(text("ALTER TABLE agent_work_items ADD COLUMN organization_id VARCHAR(36)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_agent_work_items_organization_id ON agent_work_items (organization_id)"))
                connection.execute(text("""UPDATE agent_work_items
                    SET organization_id = (SELECT organization_id FROM remote_assessments r
                                           WHERE r.assessment_id = agent_work_items.assessment_id)
                    WHERE organization_id IS NULL
                      AND EXISTS (SELECT 1 FROM remote_assessments r
                                  WHERE r.assessment_id = agent_work_items.assessment_id
                                    AND r.organization_id IS NOT NULL)"""))
            if "compliance_posture_snapshots" in tables:
                columns = {item["name"] for item in inspector.get_columns("compliance_posture_snapshots")}
                if "snapshot_digest_sha256" not in columns:
                    connection.execute(text("ALTER TABLE compliance_posture_snapshots ADD COLUMN snapshot_digest_sha256 VARCHAR(64)"))
            if "security_audit_events" in tables:
                columns = {item["name"] for item in inspector.get_columns("security_audit_events")}
                for name in ("organization_id", "user_id"):
                    if name not in columns:
                        connection.execute(text(f"ALTER TABLE security_audit_events ADD COLUMN {name} VARCHAR(36)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_security_audit_events_organization_id ON security_audit_events (organization_id)"))
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_security_audit_events_user_id ON security_audit_events (user_id)"))
                # Composite index matching the feed's access path: tenant rows,
                # newest first.
                connection.execute(text("CREATE INDEX IF NOT EXISTS ix_security_audit_events_org_occurred ON security_audit_events (organization_id, occurred_at)"))
                # Historic rows stored tenancy inside event_metadata. Promote it
                # to the column so those rows remain visible to their owner and
                # are not silently dropped from the feed.
                for name in ("organization_id", "user_id"):
                    connection.execute(text(f"""UPDATE security_audit_events
                        SET {name} = json_extract(event_metadata, '$.{name}')
                        WHERE {name} IS NULL
                          AND json_valid(event_metadata)
                          AND json_extract(event_metadata, '$.{name}') IS NOT NULL"""))

    async def create_tables_async(self):
        """Create all database tables asynchronously"""
        if not self.async_engine:
            self.initialize_async_engine()

        try:
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_human_sessions_token_verifier ON human_sessions (token_verifier)")
                if self.async_engine.dialect.name == "sqlite":
                    exists = (await conn.exec_driver_sql("SELECT 1 FROM sqlite_master WHERE type='table' AND name='compliance_posture_snapshots'")).first()
                    if exists:
                        cols = (await conn.exec_driver_sql("PRAGMA table_info(compliance_posture_snapshots)")).all()
                        if not any(row[1] == "snapshot_digest_sha256" for row in cols):
                            await conn.exec_driver_sql("ALTER TABLE compliance_posture_snapshots ADD COLUMN snapshot_digest_sha256 VARCHAR(64)")
                    # The audit feed filters tenancy in SQL, so an existing
                    # deployment must gain the columns on startup as well as
                    # through the sync path.
                    audit_exists = (await conn.exec_driver_sql("SELECT 1 FROM sqlite_master WHERE type='table' AND name='security_audit_events'")).first()
                    if audit_exists:
                        audit_cols = {row[1] for row in (await conn.exec_driver_sql("PRAGMA table_info(security_audit_events)")).all()}
                        for name in ("organization_id", "user_id"):
                            if name not in audit_cols:
                                await conn.exec_driver_sql(f"ALTER TABLE security_audit_events ADD COLUMN {name} VARCHAR(36)")
                        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_security_audit_events_organization_id ON security_audit_events (organization_id)")
                        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_security_audit_events_user_id ON security_audit_events (user_id)")
                        await conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_security_audit_events_org_occurred ON security_audit_events (organization_id, occurred_at)")
                        for name in ("organization_id", "user_id"):
                            await conn.exec_driver_sql(
                                f"UPDATE security_audit_events SET {name} = json_extract(event_metadata, '$.{name}') "
                                f"WHERE {name} IS NULL AND json_valid(event_metadata) "
                                f"AND json_extract(event_metadata, '$.{name}') IS NOT NULL")
            if self.async_engine.dialect.name == "sqlite":
                if not self.engine:
                    self.initialize_sync_engine()
                from backend.application.ops.schema import apply_sqlite_migrations
                apply_sqlite_migrations(self.engine)
            logger.info("Database tables created successfully (async)")
        except Exception as e:
            logger.error("Failed to create tables (async) error_type=%s", type(e).__name__)
            raise

    @contextmanager
    def get_db(self) -> Generator[Session, None, None]:
        """Get synchronous database session (context manager)"""
        if not self.SessionLocal:
            self.initialize_sync_engine()

        db = self.SessionLocal()
        try:
            yield db
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error("Database error error_type=%s", type(e).__name__)
            raise
        finally:
            db.close()

    @asynccontextmanager
    async def get_async_db(self) -> AsyncGenerator[AsyncSession, None]:
        """Get asynchronous database session (async context manager)"""
        if not self.AsyncSessionLocal:
            self.initialize_async_engine()

        async with self.AsyncSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error("Database error (async) error_type=%s", type(e).__name__)
                raise

    def close(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()
            logger.info("Sync database engine disposed")

    async def close_async(self):
        """Close async database connections"""
        if self.async_engine:
            await self.async_engine.dispose()
            logger.info("Async database engine disposed")


# Global database manager instance
db_manager = DatabaseManager()


# Dependency for FastAPI
def get_db_session():
    """FastAPI dependency for database sessions"""
    with db_manager.get_db() as db:
        yield db


async def get_async_db_session():
    """FastAPI dependency for async database sessions"""
    async with db_manager.get_async_db() as db:
        yield db
