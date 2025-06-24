from sqlalchemy import Column, String, DateTime, Boolean, Integer, ForeignKey, JSON, create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import uuid

Base = declarative_base()

class Organization(Base):
    """Organization model."""
    __tablename__ = 'organizations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    description = Column(String, nullable=True)
    website = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(Integer, nullable=True)  # References users.id
    
    # Relationships
    nodes = relationship("Node", back_populates="organization")
    
    def __repr__(self):
        return f"<Organization(uuid='{self.uuid}', name='{self.name}', slug='{self.slug}')>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'website': self.website,
            'contact_email': self.contact_email,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
        }


class Protocol(Base):
    """Protocol model."""
    __tablename__ = 'protocols'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False)
    display_name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    ports = Column(JSON, nullable=False)
    endpoints = Column(JSON, nullable=False)
    banners = Column(JSON, nullable=False)
    rpc_methods = Column(JSON, nullable=False)
    metrics_keywords = Column(JSON, nullable=False)
    http_paths = Column(JSON, nullable=False)
    identification_hints = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    nodes = relationship("Node", back_populates="protocol")
    
    def __repr__(self):
        return f"<Protocol(name='{self.name}', display_name='{self.display_name}')>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'name': self.name,
            'display_name': self.display_name,
            'category': self.category,
            'ports': self.ports,
            'endpoints': self.endpoints,
            'banners': self.banners,
            'rpc_methods': self.rpc_methods,
            'metrics_keywords': self.metrics_keywords,
            'http_paths': self.http_paths,
            'identification_hints': self.identification_hints,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Node(Base):
    """Node metadata model for tracking discovered and scanned nodes."""
    __tablename__ = 'nodes'
    
    uuid = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(String(36), ForeignKey('organizations.uuid'), nullable=False)  # Match organizations.uuid type
    status = Column(String(50), nullable=False, default='new')  # new, discovered, scanned, error
    protocol_id = Column(Integer, ForeignKey('protocols.id'), nullable=True)
    meta = Column(JSON, nullable=True)  # Store IP, hostname, and other metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    organization = relationship("Organization", back_populates="nodes")
    protocol = relationship("Protocol", back_populates="nodes")
    
    def __repr__(self):
        return f"<Node(uuid='{self.uuid}', status='{self.status}', org_id='{self.org_id}')>"
    
    def to_dict(self):
        return {
            'uuid': str(self.uuid) if self.uuid else None,
            'org_id': str(self.org_id) if self.org_id else None,
            'status': self.status,
            'protocol_id': self.protocol_id,
            'meta': self.meta,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class ValidatorAddress(Base):
    __tablename__ = 'validator_addresses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)  # UUID for external references
    address = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    protocol_id = Column(Integer, ForeignKey('protocols.id'), nullable=False)  # Link to protocol table
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    scans = relationship("ValidatorScan", back_populates="validator_address")
    # Note: Protocol relationship is available via foreign key, 
    # but avoid circular imports by not defining it here

    def __repr__(self):
        return f"<ValidatorAddress(address='{self.address}', name='{self.name}', protocol_id={self.protocol_id}, active={self.active})>"

    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'address': self.address,
            'name': self.name,
            'protocol_id': self.protocol_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'active': self.active
        }


class ValidatorScan(Base):
    __tablename__ = 'validator_scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    validator_address_id = Column(Integer, ForeignKey('validator_addresses.id'), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    score = Column(Integer, nullable=True)
    scan_hash = Column(String(64), nullable=True)  # SHA-256 hash
    scan_results = Column(JSON, nullable=True)  # JSON field to store scan results
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    failed = Column(Boolean, default=False, nullable=False)  # New column to mark failed scans
    version = Column(String(20), nullable=False)  # Scanner version - must be set explicitly
    signature_created = Column(Boolean, default=False, nullable=False)  # Track if protocol signature was created from this scan
    
    # Relationship back to validator address
    validator_address = relationship("ValidatorAddress", back_populates="scans")
    
    def __repr__(self):
        return f"<ValidatorScan(id={self.id}, validator_address_id='{self.validator_address_id}', score={self.score}, scan_date='{self.scan_date}')>"
    
    def to_dict(self):
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
            'signature_created': self.signature_created,
        }


class ValidatorScanReport(Base):
    """Model for storing generated security reports."""
    __tablename__ = 'validator_scan_reports'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False)  # UUID for external references
    scan_id = Column(Integer, ForeignKey('validator_scans.id'), nullable=False)
    report_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    report_type = Column(String(50), default='security_analysis', nullable=False)
    report_format = Column(String(20), default='json', nullable=False)  # json, html, pdf, etc.
    overall_risk_level = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_vulnerabilities = Column(Integer, default=0, nullable=False)
    report_data = Column(JSON, nullable=False)  # Full report JSON
    report_summary = Column(String(1000), nullable=True)  # Brief text summary
    processed = Column(Boolean, default=True, nullable=False)  # Mark as processed
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    report_email_body = Column(String, nullable=True)  # Email body content
    report_email_subject = Column(String(255), nullable=True)  # Email subject line
    report_email_to = Column(String(255), nullable=True)  # Email recipient
    
    # Relationship back to scan
    scan = relationship("ValidatorScan", backref="reports")
    
    def __repr__(self):
        return f"<ValidatorScanReport(id={self.id}, scan_id={self.scan_id}, risk_level='{self.overall_risk_level}', report_date='{self.report_date}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'scan_id': self.scan_id,
            'report_date': self.report_date.isoformat() if self.report_date else None,
            'report_type': self.report_type,
            'report_format': self.report_format,
            'overall_risk_level': self.overall_risk_level,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_vulnerabilities': self.critical_vulnerabilities,
            'report_data': self.report_data,
            'report_summary': self.report_summary,
            'processed': self.processed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'report_email_body': self.report_email_body,
            'report_email_subject': self.report_email_subject,
            'report_email_to': self.report_email_to,
        }
