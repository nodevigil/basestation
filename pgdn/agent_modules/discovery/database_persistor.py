"""
Database Result Persister - Handles saving discovery results to database
"""

import json
import uuid
import logging
from typing import Dict, Optional
from datetime import datetime
from sqlalchemy import text
from pgdn.core.database import get_db_session


class DatabaseResultPersister:
    """Handles persisting discovery results to database"""
    
    def __init__(self, config=None):
        self.config = config
    
    @staticmethod
    def _sanitize_string(s: str) -> str:
        """Remove problematic characters from strings"""
        if not isinstance(s, str):
            s = str(s)
        return s.replace('\x00', '').replace('\r', '').replace('\n', ' ')
    
    def create_scan_session(self, session_id: Optional[str] = None, created_by: Optional[str] = None) -> str:
        """Create a new scan session"""
        if session_id is None:
            session_id = str(uuid.uuid4())
            
        try:
            with get_db_session() as session:
                session.execute(
                    text("""INSERT INTO scan_sessions 
                           (session_id, started_at, status, created_by, scanner_version, 
                            total_hosts, successful_detections, failed_scans) 
                           VALUES (:session_id, :started_at, :status, :created_by, :scanner_version, 
                                   :total_hosts, :successful_detections, :failed_scans)
                           ON CONFLICT (session_id) DO UPDATE SET
                           started_at = EXCLUDED.started_at,
                           status = EXCLUDED.status"""),
                    {
                        'session_id': session_id,
                        'started_at': datetime.utcnow(),
                        'status': 'running',
                        'created_by': created_by or 'discovery_agent',
                        'scanner_version': '2.1',
                        'total_hosts': 0,
                        'successful_detections': 0,
                        'failed_scans': 0
                    }
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to create scan session: {e}")
            
        return session_id
    
    def start_host_discovery(self, session_id: str, hostname: str, ip_address: Optional[str] = None) -> int:
        """Start a host discovery"""
        try:
            with get_db_session() as session:
                result = session.execute(
                    text("""INSERT INTO host_discoveries 
                           (session_id, hostname, ip_address, confidence_level, confidence_score, 
                            scan_started_at, scan_status, created_at, updated_at) 
                           VALUES (:session_id, :hostname, :ip_address, 'unknown', 0.0, :started_at, 'scanning', :created_at, :updated_at)
                           RETURNING id"""),
                    {
                        'session_id': session_id,
                        'hostname': hostname,
                        'ip_address': ip_address,
                        'started_at': datetime.utcnow(),
                        'created_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                )
                discovery_id = result.fetchone()[0]
                session.commit()
                return discovery_id
        except Exception as e:
            logging.error(f"Failed to start host discovery: {e}")
            return hash(f"{session_id}_{hostname}") % 1000000
    
    def complete_host_discovery(self, discovery_id: int, result, total_duration: float):
        """Complete host discovery with results"""
        try:
            with get_db_session() as session:
                session.execute(
                    text("""UPDATE host_discoveries 
                       SET detected_protocol = :detected_protocol, confidence_level = :confidence_level, 
                           confidence_score = :confidence_score, detection_method = :detection_method, 
                           scan_completed_at = :scan_completed_at, scan_duration_seconds = :scan_duration_seconds,
                           scan_status = 'completed', performance_metrics = :performance_metrics
                       WHERE id = :discovery_id"""),
                    {
                        'detected_protocol': result.protocol,
                        'confidence_level': result.confidence.value,
                        'confidence_score': result.confidence_score,
                        'detection_method': result.signature_match.get('analysis_method', 'unknown') if result.signature_match else 'unknown',
                        'scan_completed_at': datetime.utcnow(),
                        'scan_duration_seconds': total_duration,
                        'performance_metrics': json.dumps(result.performance_metrics or {}),
                        'discovery_id': discovery_id
                    }
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to complete host discovery: {e}")
    
    def mark_discovery_failed(self, discovery_id: int, error_message: str):
        """Mark discovery as failed"""
        try:
            with get_db_session() as session:
                session.execute(
                    text("""UPDATE host_discoveries 
                       SET scan_status = 'failed', error_message = :error_message, scan_completed_at = :completed_at
                       WHERE id = :discovery_id"""),
                    {
                        'error_message': error_message,
                        'completed_at': datetime.utcnow(),
                        'discovery_id': discovery_id
                    }
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to mark discovery as failed: {e}")