"""
Database management and models for the DePIN infrastructure scanner.
"""

import os
import uuid
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, ForeignKey, JSON, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime
from typing import Optional, Generator
from contextlib import contextmanager
from pgdn.core.config import DatabaseConfig

# Current scanner version - update this when scanner logic changes
SCANNER_VERSION = "v0.1"

Base = declarative_base()


class ValidatorAddress(Base):
    """Model for validator network addresses."""
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
    protocol = relationship("Protocol")

    def __repr__(self):
        return f"<ValidatorAddress(address='{self.address}', name='{self.name}', protocol_id={self.protocol_id}, active={self.active})>"

    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'address': self.address,
            'name': self.name,
            'protocol_id': self.protocol_id,
            'protocol_name': self.protocol.name if self.protocol else None,
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
    signature_created = Column(Boolean, default=False, nullable=False)  # Track if protocol signature was created from this scan
    scan_type = Column(String(50), nullable=True)  # Type of scan performed (e.g., 'web', 'geo', 'generic', 'target_scan')
    
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
            'signature_created': self.signature_created,
            'scan_type': self.scan_type,
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
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False, onupdate=datetime.utcnow)
    
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
    
    # Email notification fields
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


class Protocol(Base):
    """Model for storing protocol definitions."""
    __tablename__ = 'protocols'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)  # UUID for external references
    name = Column(String(50), unique=True, nullable=False)  # Protocol name (sui, filecoin, etc.)
    display_name = Column(String(100), nullable=False)  # Human readable name
    category = Column(String(50), nullable=False)  # DePIN category
    ports = Column(JSON, nullable=False)  # JSON array of common ports
    endpoints = Column(JSON, nullable=False)  # JSON array of common endpoints
    banners = Column(JSON, nullable=False)  # JSON array of banner patterns
    rpc_methods = Column(JSON, nullable=False)  # JSON array of RPC methods
    metrics_keywords = Column(JSON, nullable=False)  # JSON array of metrics keywords
    http_paths = Column(JSON, nullable=False)  # JSON array of HTTP paths
    identification_hints = Column(JSON, nullable=False)  # JSON array of identification hints
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship to signatures
    signature = relationship("ProtocolSignature", back_populates="protocol", uselist=False)
    
    def __repr__(self):
        return f"<Protocol(name='{self.name}', display_name='{self.display_name}', category='{self.category}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
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
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ProtocolSignature(Base):
    """Model for storing binary protocol signatures for fast matching."""
    __tablename__ = 'protocol_signatures'
    
    protocol_id = Column(Integer, ForeignKey('protocols.id'), primary_key=True)
    port_signature = Column(String, nullable=False)  # Binary signature as base64 string
    banner_signature = Column(String, nullable=False)  # Binary signature as base64 string
    endpoint_signature = Column(String, nullable=False)  # Binary signature as base64 string
    keyword_signature = Column(String, nullable=False)  # Binary signature as base64 string
    uniqueness_score = Column(Float, nullable=False)  # Uniqueness score for ranking
    signature_version = Column(Integer, default=1, nullable=False)  # Version for signature updates
    
    # Relationship back to protocol
    protocol = relationship("Protocol", back_populates="signature")
    
    def __repr__(self):
        return f"<ProtocolSignature(protocol_id={self.protocol_id}, uniqueness_score={self.uniqueness_score})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'protocol_id': self.protocol_id,
            'port_signature': self.port_signature,
            'banner_signature': self.banner_signature,
            'endpoint_signature': self.endpoint_signature,
            'keyword_signature': self.keyword_signature,
            'uniqueness_score': self.uniqueness_score,
            'signature_version': self.signature_version
        }


class NetworkTopology(Base):
    """Model for storing network topology discoveries."""
    __tablename__ = 'network_topology'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)  # UUID for external references
    source_scan_id = Column(Integer, ForeignKey('validator_scans.id'), nullable=False)
    network_type = Column(String(50), nullable=False)  # e.g., 'peer_network', 'blockchain', 'infrastructure'
    node_count = Column(Integer, nullable=False)  # Number of nodes discovered
    relationship_count = Column(Integer, nullable=False)  # Number of relationships discovered
    topology_data = Column(JSON, nullable=False)  # Full topology data in JSON format
    confidence_score = Column(Float, nullable=True)  # Confidence in topology mapping (0.0-1.0)
    discovery_method = Column(String(100), nullable=False)  # Method used for discovery
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship to the scan
    source_scan = relationship("ValidatorScan")
    
    def __repr__(self):
        return f"<NetworkTopology(id={self.id}, network_type='{self.network_type}', node_count={self.node_count})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'source_scan_id': self.source_scan_id,
            'network_type': self.network_type,
            'node_count': self.node_count,
            'relationship_count': self.relationship_count,
            'topology_data': self.topology_data,
            'confidence_score': self.confidence_score,
            'discovery_method': self.discovery_method,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class InfrastructureMapping(Base):
    """Model for storing infrastructure component mappings."""
    __tablename__ = 'infrastructure_mapping'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)  # UUID for external references
    source_scan_id = Column(Integer, ForeignKey('validator_scans.id'), nullable=False)
    component_type = Column(String(50), nullable=False)  # e.g., 'load_balancer', 'database', 'api_gateway'
    component_name = Column(String(255), nullable=True)  # Human-readable component name
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6 address
    ports = Column(JSON, nullable=True)  # JSON array of discovered ports
    services = Column(JSON, nullable=True)  # JSON array of discovered services
    dependencies = Column(JSON, nullable=True)  # JSON array of component dependencies
    component_metadata = Column(JSON, nullable=True)  # Additional component metadata
    discovery_method = Column(String(100), nullable=False)  # Method used for discovery
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship to the scan
    source_scan = relationship("ValidatorScan")
    
    def __repr__(self):
        return f"<InfrastructureMapping(id={self.id}, component_type='{self.component_type}', ip_address='{self.ip_address}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'source_scan_id': self.source_scan_id,
            'component_type': self.component_type,
            'component_name': self.component_name,
            'ip_address': self.ip_address,
            'ports': self.ports,
            'services': self.services,
            'dependencies': self.dependencies,
            'component_metadata': self.component_metadata,
            'discovery_method': self.discovery_method,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class DiscoveryResult(Base):
    """Model for storing general discovery results and findings."""
    __tablename__ = 'discovery_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)  # UUID for external references
    source_scan_id = Column(Integer, ForeignKey('validator_scans.id'), nullable=False)
    discovery_type = Column(String(50), nullable=False)  # e.g., 'network_scan', 'service_enum', 'protocol_analysis'
    title = Column(String(255), nullable=False)  # Human-readable discovery title
    description = Column(String(2000), nullable=True)  # Detailed description of the discovery
    severity = Column(String(20), nullable=True)  # Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    confidence = Column(Float, nullable=True)  # Confidence in the discovery (0.0-1.0)
    discovery_data = Column(JSON, nullable=False)  # Full discovery data in JSON format
    tags = Column(JSON, nullable=True)  # JSON array of tags for categorization
    agent_name = Column(String(100), nullable=False)  # Name of agent that made the discovery
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship to the scan
    source_scan = relationship("ValidatorScan")
    
    def __repr__(self):
        return f"<DiscoveryResult(id={self.id}, discovery_type='{self.discovery_type}', title='{self.title}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'source_scan_id': self.source_scan_id,
            'discovery_type': self.discovery_type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'discovery_data': self.discovery_data,
            'tags': self.tags,
            'agent_name': self.agent_name,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ==============================================================================
# DISCOVERY DATABASE MODELS
# ==============================================================================

class ScanSession(Base):
    """Model for grouping related discovery scans."""
    __tablename__ = 'scan_sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), unique=True, nullable=False)  # UUID for grouping related scans
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default='running', nullable=False)  # 'running', 'completed', 'failed', 'cancelled'
    total_hosts = Column(Integer, default=0, nullable=False)
    successful_detections = Column(Integer, default=0, nullable=False)
    failed_scans = Column(Integer, default=0, nullable=False)
    scanner_version = Column(String(20), nullable=True)
    config_hash = Column(String(64), nullable=True)  # Hash of scanner configuration used
    created_by = Column(String(100), nullable=True)  # User/system that initiated scan
    notes = Column(String, nullable=True)
    
    # Relationships
    host_discoveries = relationship("HostDiscovery", back_populates="scan_session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanSession(session_id='{self.session_id}', status='{self.status}', total_hosts={self.total_hosts})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'total_hosts': self.total_hosts,
            'successful_detections': self.successful_detections,
            'failed_scans': self.failed_scans,
            'scanner_version': self.scanner_version,
            'config_hash': self.config_hash,
            'created_by': self.created_by,
            'notes': self.notes
        }


class HostDiscovery(Base):
    """Model for individual host discovery results."""
    __tablename__ = 'host_discoveries'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey('scan_sessions.session_id'), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    
    # Detection Results
    detected_protocol = Column(String(100), nullable=True)  # Protocol name if detected
    confidence_level = Column(String(20), default='unknown', nullable=False)  # 'high', 'medium', 'low', 'unknown'
    confidence_score = Column(Float, default=0.0, nullable=False)  # Numeric confidence (0.0 - 1.0)
    detection_method = Column(String(100), nullable=True)  # 'hybrid_binary_detailed', 'ai_analysis', etc.
    
    # Scan Metadata
    scan_started_at = Column(DateTime, nullable=False)
    scan_completed_at = Column(DateTime, nullable=True)
    scan_duration_seconds = Column(Float, nullable=True)
    scan_status = Column(String(20), default='pending', nullable=False)  # 'pending', 'scanning', 'completed', 'failed'
    error_message = Column(String, nullable=True)
    
    # Performance Metrics (JSON)
    performance_metrics = Column(JSON, nullable=True)  # JSON: timing, candidates, etc.
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    scan_session = relationship("ScanSession", back_populates="host_discoveries")
    network_scan_data = relationship("NetworkScanData", back_populates="host_discovery", cascade="all, delete-orphan")
    protocol_probe_results = relationship("ProtocolProbeResult", back_populates="host_discovery", cascade="all, delete-orphan")
    signature_match_results = relationship("SignatureMatchResult", back_populates="host_discovery", cascade="all, delete-orphan")
    ai_analysis_results = relationship("AIAnalysisResult", back_populates="host_discovery", cascade="all, delete-orphan")
    validation_results = relationship("ValidationResult", back_populates="host_discovery", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<HostDiscovery(hostname='{self.hostname}', detected_protocol='{self.detected_protocol}', confidence='{self.confidence_level}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'detected_protocol': self.detected_protocol,
            'confidence_level': self.confidence_level,
            'confidence_score': self.confidence_score,
            'detection_method': self.detection_method,
            'scan_started_at': self.scan_started_at.isoformat() if self.scan_started_at else None,
            'scan_completed_at': self.scan_completed_at.isoformat() if self.scan_completed_at else None,
            'scan_duration_seconds': self.scan_duration_seconds,
            'scan_status': self.scan_status,
            'error_message': self.error_message,
            'performance_metrics': self.performance_metrics,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class NetworkScanData(Base):
    """Model for network scan data and port scan results."""
    __tablename__ = 'network_scan_data'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    discovery_id = Column(Integer, ForeignKey('host_discoveries.id'), nullable=False)
    
    # Port Scan Results
    open_ports = Column(JSON, nullable=False)  # JSON array of open ports
    total_ports_scanned = Column(Integer, default=65535, nullable=False)
    scan_technique = Column(String(50), default='tcp_syn', nullable=False)  # 'tcp_syn', 'tcp_connect', 'udp', etc.
    
    # Service Detection Results (JSON)
    services_detected = Column(JSON, nullable=True)  # JSON: {port: {name, product, version, banner}}
    os_detection = Column(JSON, nullable=True)  # JSON: OS fingerprinting results
    
    # Raw Nmap Data
    nmap_command = Column(String, nullable=True)  # Actual nmap command executed
    nmap_output = Column(String, nullable=True)  # Raw nmap output (truncated if large)
    nmap_xml = Column(String, nullable=True)  # Nmap XML output (compressed/truncated)
    nmap_duration_seconds = Column(Float, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    host_discovery = relationship("HostDiscovery", back_populates="network_scan_data")
    
    def __repr__(self):
        return f"<NetworkScanData(discovery_id={self.discovery_id}, ports_count={len(self.open_ports) if self.open_ports else 0})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'discovery_id': self.discovery_id,
            'open_ports': self.open_ports,
            'total_ports_scanned': self.total_ports_scanned,
            'scan_technique': self.scan_technique,
            'services_detected': self.services_detected,
            'os_detection': self.os_detection,
            'nmap_command': self.nmap_command,
            'nmap_output': self.nmap_output,
            'nmap_xml': self.nmap_xml,
            'nmap_duration_seconds': self.nmap_duration_seconds,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ProtocolProbeResult(Base):
    """Model for protocol probe results and HTTP/RPC probes."""
    __tablename__ = 'protocol_probe_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    discovery_id = Column(Integer, ForeignKey('host_discoveries.id'), nullable=False)
    
    # Probe Details
    probe_type = Column(String(50), nullable=False)  # 'http', 'rpc', 'tcp_banner', 'custom'
    target_port = Column(Integer, nullable=False)
    endpoint_path = Column(String(500), nullable=True)  # HTTP path or RPC method
    protocol_hint = Column(String(100), nullable=True)  # Expected protocol being tested
    
    # Request Details
    request_method = Column(String(20), nullable=True)  # 'GET', 'POST', 'RPC', etc.
    request_headers = Column(JSON, nullable=True)  # JSON: request headers sent
    request_body = Column(String, nullable=True)  # Request payload (truncated if large)
    request_timestamp = Column(DateTime, nullable=False)
    
    # Response Details
    response_status_code = Column(Integer, nullable=True)
    response_headers = Column(JSON, nullable=True)  # JSON: response headers
    response_body = Column(String, nullable=True)  # Response body (truncated to ~10KB)
    response_size_bytes = Column(Integer, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    
    # Analysis Results
    protocol_indicators_found = Column(JSON, nullable=True)  # JSON: array of protocol clues found
    confidence_contribution = Column(Float, default=0.0, nullable=False)  # How much this probe contributed to final score
    
    # Error Handling
    error_occurred = Column(Boolean, default=False, nullable=False)
    error_message = Column(String, nullable=True)
    timeout_occurred = Column(Boolean, default=False, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    host_discovery = relationship("HostDiscovery", back_populates="protocol_probe_results")
    
    def __repr__(self):
        return f"<ProtocolProbeResult(discovery_id={self.discovery_id}, probe_type='{self.probe_type}', port={self.target_port})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'discovery_id': self.discovery_id,
            'probe_type': self.probe_type,
            'target_port': self.target_port,
            'endpoint_path': self.endpoint_path,
            'protocol_hint': self.protocol_hint,
            'request_method': self.request_method,
            'request_headers': self.request_headers,
            'request_body': self.request_body,
            'request_timestamp': self.request_timestamp.isoformat() if self.request_timestamp else None,
            'response_status_code': self.response_status_code,
            'response_headers': self.response_headers,
            'response_body': self.response_body,
            'response_size_bytes': self.response_size_bytes,
            'response_time_ms': self.response_time_ms,
            'protocol_indicators_found': self.protocol_indicators_found,
            'confidence_contribution': self.confidence_contribution,
            'error_occurred': self.error_occurred,
            'error_message': self.error_message,
            'timeout_occurred': self.timeout_occurred,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SignatureMatchResult(Base):
    """Model for binary signature matching results."""
    __tablename__ = 'signature_match_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    discovery_id = Column(Integer, ForeignKey('host_discoveries.id'), nullable=False)
    
    # Binary Signature Analysis
    scan_port_signature = Column(String, nullable=True)  # Base64 encoded binary signature from scan
    scan_banner_signature = Column(String, nullable=True)
    scan_endpoint_signature = Column(String, nullable=True)
    scan_keyword_signature = Column(String, nullable=True)
    
    # Protocol Matching Results
    protocol_id = Column(Integer, ForeignKey('protocols.id'), nullable=True)  # Reference to matched protocol
    protocol_name = Column(String(100), nullable=False)
    binary_similarity_score = Column(Float, nullable=False)  # Binary pre-filter score
    detailed_analysis_score = Column(Float, nullable=False)  # Detailed analysis score
    combined_final_score = Column(Float, nullable=False)  # Final weighted score
    uniqueness_boost_applied = Column(Float, default=0.0, nullable=False)  # Boost from protocol uniqueness
    
    # Evidence Details (JSON)
    port_evidence = Column(JSON, nullable=True)  # JSON: matching ports and coverage
    banner_evidence = Column(JSON, nullable=True)  # JSON: banner matches with strength
    content_evidence = Column(JSON, nullable=True)  # JSON: keyword/content matches
    rpc_evidence = Column(JSON, nullable=True)  # JSON: RPC method matches
    
    # Performance Tracking
    binary_analysis_time_ms = Column(Float, nullable=True)
    detailed_analysis_time_ms = Column(Float, nullable=True)
    total_protocols_checked = Column(Integer, nullable=True)
    binary_candidates_generated = Column(Integer, nullable=True)
    
    # Ranking
    match_rank = Column(Integer, nullable=False)  # 1=best match, 2=second best, etc.
    above_threshold = Column(Boolean, nullable=False)  # Whether this match exceeded confidence threshold
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    host_discovery = relationship("HostDiscovery", back_populates="signature_match_results")
    
    def __repr__(self):
        return f"<SignatureMatchResult(discovery_id={self.discovery_id}, protocol='{self.protocol_name}', score={self.combined_final_score:.3f})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'discovery_id': self.discovery_id,
            'scan_port_signature': self.scan_port_signature,
            'scan_banner_signature': self.scan_banner_signature,
            'scan_endpoint_signature': self.scan_endpoint_signature,
            'scan_keyword_signature': self.scan_keyword_signature,
            'protocol_id': self.protocol_id,
            'protocol_name': self.protocol_name,
            'binary_similarity_score': self.binary_similarity_score,
            'detailed_analysis_score': self.detailed_analysis_score,
            'combined_final_score': self.combined_final_score,
            'uniqueness_boost_applied': self.uniqueness_boost_applied,
            'port_evidence': self.port_evidence,
            'banner_evidence': self.banner_evidence,
            'content_evidence': self.content_evidence,
            'rpc_evidence': self.rpc_evidence,
            'binary_analysis_time_ms': self.binary_analysis_time_ms,
            'detailed_analysis_time_ms': self.detailed_analysis_time_ms,
            'total_protocols_checked': self.total_protocols_checked,
            'binary_candidates_generated': self.binary_candidates_generated,
            'match_rank': self.match_rank,
            'above_threshold': self.above_threshold,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AIAnalysisResult(Base):
    """Model for AI analysis results and LLM responses."""
    __tablename__ = 'ai_analysis_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    discovery_id = Column(Integer, ForeignKey('host_discoveries.id'), nullable=False)
    
    # AI Analysis Details
    ai_provider = Column(String(50), nullable=False)  # 'anthropic', 'openai', etc.
    model_used = Column(String(100), nullable=False)  # 'claude-3-sonnet', etc.
    analysis_timestamp = Column(DateTime, nullable=False)
    
    # Input Data
    input_prompt = Column(String, nullable=True)  # Prompt sent to AI (truncated)
    input_data_hash = Column(String(64), nullable=True)  # Hash of scan data sent
    
    # AI Response
    ai_response_raw = Column(String, nullable=True)  # Raw AI response
    ai_confidence = Column(String(20), nullable=True)  # AI's stated confidence level
    ai_reasoning = Column(String, nullable=True)  # AI's explanation
    ai_suggested_protocol = Column(String(100), nullable=True)  # AI's protocol suggestion
    
    # Processing Results
    parsed_successfully = Column(Boolean, default=False, nullable=False)
    parse_error_message = Column(String, nullable=True)
    
    # Usage Metrics
    tokens_used = Column(Integer, nullable=True)
    api_cost_usd = Column(Float, nullable=True)
    response_time_seconds = Column(Float, nullable=True)
    
    # Integration
    influenced_final_result = Column(Boolean, default=False, nullable=False)  # Whether AI result changed final detection
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    host_discovery = relationship("HostDiscovery", back_populates="ai_analysis_results")
    
    def __repr__(self):
        return f"<AIAnalysisResult(discovery_id={self.discovery_id}, provider='{self.ai_provider}', suggested='{self.ai_suggested_protocol}')>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'discovery_id': self.discovery_id,
            'ai_provider': self.ai_provider,
            'model_used': self.model_used,
            'analysis_timestamp': self.analysis_timestamp.isoformat() if self.analysis_timestamp else None,
            'input_prompt': self.input_prompt,
            'input_data_hash': self.input_data_hash,
            'ai_response_raw': self.ai_response_raw,
            'ai_confidence': self.ai_confidence,
            'ai_reasoning': self.ai_reasoning,
            'ai_suggested_protocol': self.ai_suggested_protocol,
            'parsed_successfully': self.parsed_successfully,
            'parse_error_message': self.parse_error_message,
            'tokens_used': self.tokens_used,
            'api_cost_usd': self.api_cost_usd,
            'response_time_seconds': self.response_time_seconds,
            'influenced_final_result': self.influenced_final_result,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ValidationResult(Base):
    """Model for validation results and ground truth data."""
    __tablename__ = 'validation_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    discovery_id = Column(Integer, ForeignKey('host_discoveries.id'), nullable=False)
    
    # Validation Details
    validation_type = Column(String(50), nullable=False)  # 'manual', 'automated', 'ground_truth'
    validated_by = Column(String(100), nullable=True)  # User/system performing validation
    validation_timestamp = Column(DateTime, nullable=False)
    
    # Ground Truth
    actual_protocol = Column(String(100), nullable=True)  # What the host actually runs
    validation_confidence = Column(String(20), nullable=False)  # 'certain', 'likely', 'unsure'
    validation_source = Column(String(100), nullable=True)  # 'admin_confirmed', 'documentation', etc.
    
    # Accuracy Assessment
    detection_was_correct = Column(Boolean, nullable=True)
    detection_was_close = Column(Boolean, nullable=True)  # Same category but wrong specific protocol
    false_positive = Column(Boolean, default=False, nullable=False)
    false_negative = Column(Boolean, default=False, nullable=False)
    
    # Notes
    validation_notes = Column(String, nullable=True)
    correction_needed = Column(Boolean, default=False, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    host_discovery = relationship("HostDiscovery", back_populates="validation_results")
    
    def __repr__(self):
        return f"<ValidationResult(discovery_id={self.discovery_id}, actual='{self.actual_protocol}', correct={self.detection_was_correct})>"
    
    def to_dict(self):
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'discovery_id': self.discovery_id,
            'validation_type': self.validation_type,
            'validated_by': self.validated_by,
            'validation_timestamp': self.validation_timestamp.isoformat() if self.validation_timestamp else None,
            'actual_protocol': self.actual_protocol,
            'validation_confidence': self.validation_confidence,
            'validation_source': self.validation_source,
            'detection_was_correct': self.detection_was_correct,
            'detection_was_close': self.detection_was_close,
            'false_positive': self.false_positive,
            'false_negative': self.false_negative,
            'validation_notes': self.validation_notes,
            'correction_needed': self.correction_needed,
            'created_at': self.created_at.isoformat() if self.created_at else None
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
