"""
Models for ledger publishing and blockchain interaction logging.
"""

from sqlalchemy import Column, String, DateTime, Boolean, Integer, ForeignKey, JSON, Text, DECIMAL
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from models.validator import Base


class LedgerPublishLog(Base):
    """
    Log table for tracking all ledger publishing attempts and results.
    This table captures the complete lifecycle of scan publishing to blockchain.
    """
    __tablename__ = 'ledger_publish_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    
    # Scan reference
    scan_id = Column(Integer, ForeignKey('validator_scans.id'), nullable=False)
    
    # Publishing attempt metadata
    attempt_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    publishing_agent = Column(String(100), default='PublishLedgerAgent', nullable=False)
    agent_version = Column(String(20), nullable=True)
    
    # Blockchain connection details
    blockchain_network = Column(String(50), nullable=True)  # e.g., 'zkSync Era Sepolia'
    rpc_url = Column(String(255), nullable=True)
    contract_address = Column(String(42), nullable=True)  # Ethereum address format
    publisher_address = Column(String(42), nullable=True)  # Publisher's address
    
    # Publishing status
    success = Column(Boolean, default=False, nullable=False)
    is_batch = Column(Boolean, default=False, nullable=False)
    batch_id = Column(Integer, nullable=True)  # For batch operations
    
    # Transaction details
    transaction_hash = Column(String(66), nullable=True)  # 0x + 64 hex chars
    block_number = Column(Integer, nullable=True)
    gas_used = Column(Integer, nullable=True)
    gas_price_gwei = Column(DECIMAL(10, 2), nullable=True)
    transaction_confirmed = Column(Boolean, default=False, nullable=False)
    confirmation_timestamp = Column(DateTime, nullable=True)
    
    # Scan data that was published
    host_uid = Column(String(100), nullable=True)
    scan_time = Column(Integer, nullable=True)  # Unix timestamp
    summary_hash = Column(String(66), nullable=True)  # 0x + 64 hex chars
    trust_score = Column(Integer, nullable=True)
    report_pointer = Column(String(255), nullable=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    error_type = Column(String(100), nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    
    # Timing and performance
    processing_duration_ms = Column(Integer, nullable=True)
    confirmation_duration_ms = Column(Integer, nullable=True)
    
    # Additional metadata
    extra_data = Column(JSON, nullable=True)  # Additional context data
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    scan = relationship("ValidatorScan", backref="ledger_publish_logs")
    
    def __repr__(self):
        return f"<LedgerPublishLog(id={self.id}, scan_id={self.scan_id}, success={self.success}, tx_hash='{self.transaction_hash}')>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'scan_id': self.scan_id,
            'attempt_timestamp': self.attempt_timestamp.isoformat() if self.attempt_timestamp else None,
            'publishing_agent': self.publishing_agent,
            'agent_version': self.agent_version,
            'blockchain_network': self.blockchain_network,
            'rpc_url': self.rpc_url,
            'contract_address': self.contract_address,
            'publisher_address': self.publisher_address,
            'success': self.success,
            'is_batch': self.is_batch,
            'batch_id': self.batch_id,
            'transaction_hash': self.transaction_hash,
            'block_number': self.block_number,
            'gas_used': self.gas_used,
            'gas_price_gwei': float(self.gas_price_gwei) if self.gas_price_gwei else None,
            'transaction_confirmed': self.transaction_confirmed,
            'confirmation_timestamp': self.confirmation_timestamp.isoformat() if self.confirmation_timestamp else None,
            'host_uid': self.host_uid,
            'scan_time': self.scan_time,
            'summary_hash': self.summary_hash,
            'trust_score': self.trust_score,
            'report_pointer': self.report_pointer,
            'error_message': self.error_message,
            'error_type': self.error_type,
            'retry_count': self.retry_count,
            'processing_duration_ms': self.processing_duration_ms,
            'confirmation_duration_ms': self.confirmation_duration_ms,
            'extra_data': self.extra_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class LedgerBatch(Base):
    """
    Track batch publishing operations for multiple scans.
    """
    __tablename__ = 'ledger_batches'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    
    # Batch metadata
    batch_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    batch_size = Column(Integer, nullable=False)
    successful_publishes = Column(Integer, default=0, nullable=False)
    failed_publishes = Column(Integer, default=0, nullable=False)
    
    # Blockchain details
    blockchain_network = Column(String(50), nullable=True)
    contract_address = Column(String(42), nullable=True)
    publisher_address = Column(String(42), nullable=True)
    
    # Transaction details
    transaction_hash = Column(String(66), nullable=True)
    block_number = Column(Integer, nullable=True)
    blockchain_batch_id = Column(Integer, nullable=True)  # On-chain batch ID
    gas_used = Column(Integer, nullable=True)
    gas_price_gwei = Column(DECIMAL(10, 2), nullable=True)
    
    # Status
    success = Column(Boolean, default=False, nullable=False)
    confirmed = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Timing
    processing_duration_ms = Column(Integer, nullable=True)
    confirmation_duration_ms = Column(Integer, nullable=True)
    
    # Additional data
    extra_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<LedgerBatch(id={self.id}, batch_size={self.batch_size}, success={self.success}, tx_hash='{self.transaction_hash}')>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'batch_timestamp': self.batch_timestamp.isoformat() if self.batch_timestamp else None,
            'batch_size': self.batch_size,
            'successful_publishes': self.successful_publishes,
            'failed_publishes': self.failed_publishes,
            'blockchain_network': self.blockchain_network,
            'contract_address': self.contract_address,
            'publisher_address': self.publisher_address,
            'transaction_hash': self.transaction_hash,
            'block_number': self.block_number,
            'blockchain_batch_id': self.blockchain_batch_id,
            'gas_used': self.gas_used,
            'gas_price_gwei': float(self.gas_price_gwei) if self.gas_price_gwei else None,
            'success': self.success,
            'confirmed': self.confirmed,
            'error_message': self.error_message,
            'processing_duration_ms': self.processing_duration_ms,
            'confirmation_duration_ms': self.confirmation_duration_ms,
            'extra_data': self.extra_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class LedgerConnectionLog(Base):
    """
    Log blockchain connection attempts and status for monitoring and debugging.
    """
    __tablename__ = 'ledger_connection_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    
    # Connection attempt details
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    agent_name = Column(String(100), default='PublishLedgerAgent', nullable=False)
    
    # Network details
    rpc_url = Column(String(255), nullable=True)
    network_name = Column(String(50), nullable=True)
    contract_address = Column(String(42), nullable=True)
    
    # Connection results
    connection_successful = Column(Boolean, default=False, nullable=False)
    contract_loaded = Column(Boolean, default=False, nullable=False)
    is_authorized_publisher = Column(Boolean, default=False, nullable=False)
    
    # Account details
    account_address = Column(String(42), nullable=True)
    account_balance_wei = Column(String(50), nullable=True)  # String to handle large numbers
    account_balance_eth = Column(DECIMAL(20, 10), nullable=True)
    
    # Contract information
    contract_version = Column(String(20), nullable=True)
    contract_paused = Column(Boolean, nullable=True)
    total_summaries = Column(Integer, nullable=True)
    publish_cooldown = Column(Integer, nullable=True)
    reputation_threshold = Column(Integer, nullable=True)
    active_hosts = Column(Integer, nullable=True)
    
    # Error details
    error_message = Column(Text, nullable=True)
    error_type = Column(String(100), nullable=True)
    
    # Performance
    connection_duration_ms = Column(Integer, nullable=True)
    
    # Additional context
    extra_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<LedgerConnectionLog(id={self.id}, successful={self.connection_successful}, address='{self.account_address}')>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid) if self.uuid else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'agent_name': self.agent_name,
            'rpc_url': self.rpc_url,
            'network_name': self.network_name,
            'contract_address': self.contract_address,
            'connection_successful': self.connection_successful,
            'contract_loaded': self.contract_loaded,
            'is_authorized_publisher': self.is_authorized_publisher,
            'account_address': self.account_address,
            'account_balance_wei': self.account_balance_wei,
            'account_balance_eth': float(self.account_balance_eth) if self.account_balance_eth else None,
            'contract_version': self.contract_version,
            'contract_paused': self.contract_paused,
            'total_summaries': self.total_summaries,
            'publish_cooldown': self.publish_cooldown,
            'reputation_threshold': self.reputation_threshold,
            'active_hosts': self.active_hosts,
            'error_message': self.error_message,
            'error_type': self.error_type,
            'connection_duration_ms': self.connection_duration_ms,
            'extra_data': self.extra_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
