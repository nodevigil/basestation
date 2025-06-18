"""
Database management and models for the DePIN infrastructure scanner.
"""

import os
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime
from typing import Optional, Generator
from contextlib import contextmanager
from core.config import DatabaseConfig

# Current scanner version - update this when scanner logic changes
SCANNER_VERSION = "v0.1"

Base = declarative_base()


class ValidatorAddress(Base):
    """Model for validator network addresses."""
    __tablename__ = 'validator_addresses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    source = Column(String(100), nullable=False)  # e.g., 'sui', 'filecoin', 'manual'
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Relationship to scans
    scans = relationship("ValidatorScan", back_populates="validator_address")

    def __repr__(self):
        return f"<ValidatorAddress(address='{self.address}', name='{self.name}', source='{self.source}', active={self.active})>"

    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'address': self.address,
            'name': self.name,
            'source': self.source,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'active': self.active
        }


class ValidatorScan(Base):
    """Model for validator scan results."""
    __tablename__ = 'validator_scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    validator_address_id = Column(Integer, ForeignKey('validator_addresses.id'), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    score = Column(Integer, nullable=True)
    scan_hash = Column(String(64), nullable=True)  # SHA-256 hash
    scan_results = Column(JSON, nullable=True)  # JSON field to store scan results
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    failed = Column(Boolean, default=False, nullable=False)
    version = Column(String(20), nullable=False)  # Scanner version - must be set explicitly
    
    # Relationship back to validator address
    validator_address = relationship("ValidatorAddress", back_populates="scans")
    
    def __repr__(self):
        return f"<ValidatorScan(id={self.id}, validator_address_id='{self.validator_address_id}', score={self.score}, scan_date='{self.scan_date}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'validator_address_id': self.validator_address_id,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'ip_address': self.ip_address,
            'score': self.score,
            'scan_hash': self.scan_hash,
            'scan_results': self.scan_results,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'failed': self.failed,
            'version': self.version,
        }


class CVERecord(Base):
    """Model for storing CVE vulnerability data."""
    __tablename__ = 'cve_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False)  # UUID for external references
    cve_id = Column(String(20), unique=True, nullable=False)  # e.g., CVE-2019-20372
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    source = Column(String(50), default='NVD', nullable=False)  # NVD, MITRE, etc.
    
    # Vulnerability details
    description = Column(String(2000), nullable=True)
    severity = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score = Column(String(10), nullable=True)  # e.g., "7.5"
    cvss_vector = Column(String(100), nullable=True)
    
    # Affected software (JSON array of CPE URIs and version ranges)
    affected_products = Column(JSON, nullable=True)
    
    # Raw CVE data for future reference
    raw_data = Column(JSON, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<CVERecord(cve_id='{self.cve_id}', severity='{self.severity}', cvss_score='{self.cvss_score}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'cve_id': self.cve_id,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'source': self.source,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'affected_products': self.affected_products,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class CVEUpdateLog(Base):
    """Model for tracking CVE database updates."""
    __tablename__ = 'cve_update_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False)  # UUID for external references
    update_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    total_cves_processed = Column(Integer, default=0, nullable=False)
    new_cves_added = Column(Integer, default=0, nullable=False)
    updated_cves = Column(Integer, default=0, nullable=False)
    source = Column(String(50), default='NVD', nullable=False)
    status = Column(String(20), default='SUCCESS', nullable=False)  # SUCCESS, FAILED, PARTIAL
    error_message = Column(String(1000), nullable=True)
    processing_time_seconds = Column(Integer, nullable=True)
    
    def __repr__(self):
        return f"<CVEUpdateLog(update_date='{self.update_date}', status='{self.status}', new_cves={self.new_cves_added})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'update_date': self.update_date.isoformat() if self.update_date else None,
            'total_cves_processed': self.total_cves_processed,
            'new_cves_added': self.new_cves_added,
            'updated_cves': self.updated_cves,
            'source': self.source,
            'status': self.status,
            'error_message': self.error_message,
            'processing_time_seconds': self.processing_time_seconds
        }


class DatabaseManager:
    """
    Manages database connections and operations.
    
    Provides a centralized interface for database operations with
    connection pooling and session management.
    """
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        """
        Initialize database manager.
        
        Args:
            config: Database configuration. If None, uses default config.
        """
        self.config = config or DatabaseConfig()
        self.engine = self._create_engine()
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
    
    def _create_engine(self):
        """Create SQLAlchemy engine with connection pooling."""
        return create_engine(
            self.config.url,
            echo=self.config.echo_sql,
            pool_size=self.config.pool_size,
            max_overflow=self.config.max_overflow,
            pool_timeout=self.config.pool_timeout,
            pool_recycle=self.config.pool_recycle
        )
    
    def create_tables(self) -> None:
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()
    
    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope around a series of operations.
        
        Yields:
            Database session
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def health_check(self) -> bool:
        """
        Check database connectivity.
        
        Returns:
            True if database is accessible, False otherwise
        """
        try:
            with self.session_scope() as session:
                session.execute("SELECT 1")
                return True
        except Exception:
            return False


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager(config: Optional[DatabaseConfig] = None) -> DatabaseManager:
    """
    Get the global database manager instance.
    
    Args:
        config: Database configuration
        
    Returns:
        DatabaseManager instance
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(config)
    return _db_manager


def create_tables(config: Optional[DatabaseConfig] = None) -> None:
    """
    Create all database tables.
    
    Args:
        config: Database configuration
    """
    db_manager = get_database_manager(config)
    db_manager.create_tables()


@contextmanager
def get_db_session(config: Optional[DatabaseConfig] = None) -> Generator[Session, None, None]:
    """
    Get a database session context manager.
    
    Args:
        config: Database configuration
        
    Yields:
        Database session
    """
    db_manager = get_database_manager(config)
    with db_manager.session_scope() as session:
        yield session
