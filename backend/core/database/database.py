"""
RAVEN-X Enterprise - Database Manager
Handles all database connections and session management
"""

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import asynccontextmanager, contextmanager
import yaml
import logging
from pathlib import Path
from typing import AsyncGenerator, Generator

from .models import Base

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize database manager with configuration"""
        self.config = self._load_config(config_path)
        self.engine = None
        self.async_engine = None
        self.SessionLocal = None
        self.AsyncSessionLocal = None
        
    def _load_config(self, config_path: str) -> dict:
        """Load database configuration from YAML"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config['database']
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Fallback to SQLite
            return {
                'type': 'sqlite',
                'sqlite_path': 'data/raven_x.db',
                'pool_size': 20,
                'max_overflow': 10,
                'echo': False
            }
    
    def get_database_url(self, async_mode: bool = False) -> str:
        """Get database URL based on configuration"""
        db_type = self.config.get('type', 'sqlite')
        
        if db_type == 'sqlite':
            db_path = self.config.get('sqlite_path', 'data/raven_x.db')
            # Ensure directory exists
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            if async_mode:
                return f"sqlite+aiosqlite:///{db_path}"
            return f"sqlite:///{db_path}"
        
        elif db_type == 'postgresql':
            pg_config = self.config.get('postgresql', {})
            host = pg_config.get('host', 'localhost')
            port = pg_config.get('port', 5432)
            database = pg_config.get('database', 'raven_x')
            username = pg_config.get('username', 'raven_admin')
            password = pg_config.get('password', 'password')
            
            if async_mode:
                return f"postgresql+asyncpg://{username}:{password}@{host}:{port}/{database}"
            return f"postgresql://{username}:{password}@{host}:{port}/{database}"
        
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
    
    def initialize_sync_engine(self):
        """Initialize synchronous database engine"""
        database_url = self.get_database_url(async_mode=False)
        
        connect_args = {}
        engine_kwargs = {'echo': self.config.get('echo', False)}
        
        if 'sqlite' in database_url:
            # SQLite-specific configuration
            connect_args = {"check_same_thread": False}
            engine_kwargs['poolclass'] = StaticPool
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
        if 'sqlite' in database_url:
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()
        
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        logger.info(f"Sync database engine initialized: {database_url}")
    
    def initialize_async_engine(self):
        """Initialize asynchronous database engine"""
        database_url = self.get_database_url(async_mode=True)
        
        connect_args = {}
        engine_kwargs = {'echo': self.config.get('echo', False)}
        
        if 'sqlite' in database_url:
            connect_args = {"check_same_thread": False}
            engine_kwargs['poolclass'] = StaticPool
        else:
            # PostgreSQL only
            pass
        
        self.async_engine = create_async_engine(
            database_url,
            connect_args=connect_args,
            **engine_kwargs
        )
        
        self.AsyncSessionLocal = async_sessionmaker(
            self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info(f"Async database engine initialized: {database_url}")
    
    def create_tables(self):
        """Create all database tables"""
        if not self.engine:
            self.initialize_sync_engine()
        
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    async def create_tables_async(self):
        """Create all database tables asynchronously"""
        if not self.async_engine:
            self.initialize_async_engine()
        
        try:
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully (async)")
        except Exception as e:
            logger.error(f"Failed to create tables (async): {e}")
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
            logger.error(f"Database error: {e}")
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
                logger.error(f"Database error (async): {e}")
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