import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pgdn.models.validator import Base

class DatabaseConfig:
    """Database configuration class"""
    
    def __init__(self):
        self.database_url = os.getenv('DATABASE_URL', 'postgresql://simon@localhost/depin')
        self.echo_sql = os.getenv('DB_ECHO_SQL', 'false').lower() == 'true'
        
        # Connection pool settings
        self.pool_size = int(os.getenv('DB_POOL_SIZE', '10'))
        self.max_overflow = int(os.getenv('DB_MAX_OVERFLOW', '20'))
        self.pool_timeout = int(os.getenv('DB_POOL_TIMEOUT', '30'))
        self.pool_recycle = int(os.getenv('DB_POOL_RECYCLE', '3600'))  # 1 hour
        
        # Create engine with connection pool settings
        self.engine = create_engine(
            self.database_url,
            echo=self.echo_sql,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            pool_recycle=self.pool_recycle
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
    
    def get_session(self):
        """Get a new database session"""
        return self.SessionLocal()
    
    def get_db_context(self):
        """Get database session context manager"""
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    def create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(bind=self.engine)
    
    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        Base.metadata.drop_all(bind=self.engine)

# Global database configuration instance
db_config = DatabaseConfig()

# Convenience functions for backward compatibility
def get_db():
    """Get database session (generator function for FastAPI dependency injection)"""
    db = db_config.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_session():
    """Get a new database session"""
    return db_config.get_session()

def create_tables():
    """Create all tables"""
    db_config.create_tables()

# Export commonly used objects
engine = db_config.engine
SessionLocal = db_config.SessionLocal
