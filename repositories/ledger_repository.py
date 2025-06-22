"""
Repository class for managing ledger publishing logs and database operations.
"""

from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_
from datetime import datetime, timedelta

from models.ledger import LedgerPublishLog, LedgerBatch, LedgerConnectionLog
from db_config import DatabaseConfig


class LedgerRepository:
    """Repository for ledger-related database operations."""
    
    def __init__(self, db_config: Optional[DatabaseConfig] = None):
        """Initialize repository with database configuration."""
        self.db_config = db_config or DatabaseConfig()
    
    def create_publish_log(self, 
                          scan_id: int,
                          publishing_agent: str = 'PublishLedgerAgent',
                          **kwargs) -> LedgerPublishLog:
        """
        Create a new ledger publish log entry.
        
        Args:
            scan_id: ID of the scan being published
            publishing_agent: Name of the publishing agent
            **kwargs: Additional fields for the log entry
            
        Returns:
            Created LedgerPublishLog instance
        """
        with self.db_config.get_session() as session:
            log_entry = LedgerPublishLog(
                scan_id=scan_id,
                publishing_agent=publishing_agent,
                attempt_timestamp=datetime.utcnow(),
                success=kwargs.get('success', False),
                is_batch=kwargs.get('is_batch', False),
                transaction_confirmed=kwargs.get('transaction_confirmed', False),
                retry_count=kwargs.get('retry_count', 0),
                **{k: v for k, v in kwargs.items() if k not in ['success', 'is_batch', 'transaction_confirmed', 'retry_count']}
            )
            
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)
            return log_entry
    
    def update_publish_log(self, 
                          log_id: int, 
                          **updates) -> Optional[LedgerPublishLog]:
        """
        Update an existing publish log entry.
        
        Args:
            log_id: ID of the log entry to update
            **updates: Fields to update
            
        Returns:
            Updated LedgerPublishLog instance or None if not found
        """
        with self.db_config.get_session() as session:
            log_entry = session.query(LedgerPublishLog).filter(LedgerPublishLog.id == log_id).first()
            if log_entry:
                for key, value in updates.items():
                    if hasattr(log_entry, key):
                        setattr(log_entry, key, value)
                
                log_entry.updated_at = datetime.utcnow()
                session.commit()
                session.refresh(log_entry)
                return log_entry
            return None
    
    def get_publish_logs_for_scan(self, scan_id: int) -> List[LedgerPublishLog]:
        """Get all publish logs for a specific scan."""
        with self.db_config.get_session() as session:
            return session.query(LedgerPublishLog).filter(
                LedgerPublishLog.scan_id == scan_id
            ).order_by(desc(LedgerPublishLog.attempt_timestamp)).all()
    
    def get_recent_publish_logs(self, limit: int = 100) -> List[LedgerPublishLog]:
        """Get recent publish logs."""
        with self.db_config.get_session() as session:
            return session.query(LedgerPublishLog).order_by(
                desc(LedgerPublishLog.attempt_timestamp)
            ).limit(limit).all()
    
    def get_publish_log_by_id(self, log_id: int) -> Optional[LedgerPublishLog]:
        """Get a specific publish log entry by ID."""
        with self.db_config.get_session() as session:
            return session.query(LedgerPublishLog).filter(
                LedgerPublishLog.id == log_id
            ).first()

    def get_failed_publish_logs(self, hours_back: int = 24) -> List[LedgerPublishLog]:
        """Get failed publish attempts within the specified time period."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        with self.db_config.get_session() as session:
            return session.query(LedgerPublishLog).filter(
                and_(
                    LedgerPublishLog.success == False,
                    LedgerPublishLog.attempt_timestamp >= cutoff_time
                )
            ).order_by(desc(LedgerPublishLog.attempt_timestamp)).all()
    
    def create_batch_log(self, 
                        batch_size: int,
                        **kwargs) -> LedgerBatch:
        """
        Create a new batch log entry.
        
        Args:
            batch_size: Number of scans in the batch
            **kwargs: Additional fields for the batch log
            
        Returns:
            Created LedgerBatch instance
        """
        with self.db_config.get_session() as session:
            batch_log = LedgerBatch(
                batch_timestamp=datetime.utcnow(),
                batch_size=batch_size,
                successful_publishes=kwargs.get('successful_publishes', 0),
                failed_publishes=kwargs.get('failed_publishes', 0),
                success=kwargs.get('success', False),
                confirmed=kwargs.get('confirmed', False),
                **{k: v for k, v in kwargs.items() if k not in ['successful_publishes', 'failed_publishes', 'success', 'confirmed']}
            )
            
            session.add(batch_log)
            session.commit()
            session.refresh(batch_log)
            return batch_log
    
    def update_batch_log(self, 
                        batch_id: int, 
                        **updates) -> Optional[LedgerBatch]:
        """Update an existing batch log entry."""
        with self.db_config.get_session() as session:
            batch_log = session.query(LedgerBatch).filter(LedgerBatch.id == batch_id).first()
            if batch_log:
                for key, value in updates.items():
                    if hasattr(batch_log, key):
                        setattr(batch_log, key, value)
                
                batch_log.updated_at = datetime.utcnow()
                session.commit()
                session.refresh(batch_log)
                return batch_log
            return None
    
    def create_connection_log(self, 
                             agent_name: str = 'PublishLedgerAgent',
                             **kwargs) -> LedgerConnectionLog:
        """
        Create a new connection log entry.
        
        Args:
            agent_name: Name of the agent making the connection
            **kwargs: Additional fields for the connection log
            
        Returns:
            Created LedgerConnectionLog instance
        """
        with self.db_config.get_session() as session:
            connection_log = LedgerConnectionLog(
                timestamp=datetime.utcnow(),
                agent_name=agent_name,
                connection_successful=kwargs.get('connection_successful', False),
                contract_loaded=kwargs.get('contract_loaded', False),
                is_authorized_publisher=kwargs.get('is_authorized_publisher', False),
                **{k: v for k, v in kwargs.items() if k not in ['connection_successful', 'contract_loaded', 'is_authorized_publisher']}
            )
            
            session.add(connection_log)
            session.commit()
            session.refresh(connection_log)
            return connection_log
    
    def get_recent_connection_logs(self, limit: int = 50) -> List[LedgerConnectionLog]:
        """Get recent connection logs."""
        with self.db_config.get_session() as session:
            return session.query(LedgerConnectionLog).order_by(
                desc(LedgerConnectionLog.timestamp)
            ).limit(limit).all()
    
    def get_publish_stats(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Get publishing statistics for the specified time period.
        
        Args:
            hours_back: Number of hours to look back
            
        Returns:
            Dictionary with publishing statistics
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        with self.db_config.get_session() as session:
            # Get publish logs within time period
            logs = session.query(LedgerPublishLog).filter(
                LedgerPublishLog.attempt_timestamp >= cutoff_time
            ).all()
            
            total_attempts = len(logs)
            successful_attempts = len([log for log in logs if log.success])
            failed_attempts = total_attempts - successful_attempts
            
            # Get batch statistics
            batch_logs = session.query(LedgerBatch).filter(
                LedgerBatch.batch_timestamp >= cutoff_time
            ).all()
            
            total_batches = len(batch_logs)
            successful_batches = len([batch for batch in batch_logs if batch.success])
            
            # Calculate success rates
            success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
            batch_success_rate = (successful_batches / total_batches * 100) if total_batches > 0 else 0
            
            return {
                'time_period_hours': hours_back,
                'total_publish_attempts': total_attempts,
                'successful_publishes': successful_attempts,
                'failed_publishes': failed_attempts,
                'publish_success_rate': round(success_rate, 2),
                'total_batches': total_batches,
                'successful_batches': successful_batches,
                'batch_success_rate': round(batch_success_rate, 2),
                'unique_scans_published': len(set(log.scan_id for log in logs if log.success)),
                'average_processing_time_ms': round(
                    sum(log.processing_duration_ms for log in logs if log.processing_duration_ms) / 
                    len([log for log in logs if log.processing_duration_ms])
                ) if any(log.processing_duration_ms for log in logs) else None
            }
    
    def get_pending_publishes(self) -> List[LedgerPublishLog]:
        """Get publish attempts that were sent but not yet confirmed."""
        with self.db_config.get_session() as session:
            return session.query(LedgerPublishLog).filter(
                and_(
                    LedgerPublishLog.success == True,
                    LedgerPublishLog.transaction_confirmed == False,
                    LedgerPublishLog.transaction_hash.isnot(None)
                )
            ).order_by(LedgerPublishLog.attempt_timestamp).all()
    
    def mark_transaction_confirmed(self, 
                                  transaction_hash: str, 
                                  block_number: Optional[int] = None,
                                  gas_used: Optional[int] = None) -> Optional[LedgerPublishLog]:
        """Mark a transaction as confirmed."""
        with self.db_config.get_session() as session:
            log_entry = session.query(LedgerPublishLog).filter(
                LedgerPublishLog.transaction_hash == transaction_hash
            ).first()
            
            if log_entry:
                log_entry.transaction_confirmed = True
                log_entry.confirmation_timestamp = datetime.utcnow()
                if block_number:
                    log_entry.block_number = block_number
                if gas_used:
                    log_entry.gas_used = gas_used
                
                # Calculate confirmation duration
                if log_entry.attempt_timestamp:
                    duration = datetime.utcnow() - log_entry.attempt_timestamp
                    log_entry.confirmation_duration_ms = int(duration.total_seconds() * 1000)
                
                log_entry.updated_at = datetime.utcnow()
                session.commit()
                session.refresh(log_entry)
                return log_entry
            return None
