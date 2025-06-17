"""
CVE Repository - Database operations for CVE records.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_
from core.database import CVERecord, CVEUpdateLog, DatabaseManager
from core.logging import get_logger

logger = get_logger(__name__)


class CVERepository:
    """Repository for CVE database operations."""
    
    def __init__(self, db_manager: DatabaseManager):
        """Initialize CVE repository.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
    
    def save_cve(self, session: Session, cve_data: Dict[str, Any]) -> CVERecord:
        """Save or update a CVE record.
        
        Args:
            session: Database session
            cve_data: CVE data dictionary
            
        Returns:
            CVERecord instance
        """
        cve_id = cve_data.get('cve_id')
        
        # Check if CVE already exists
        existing_cve = session.query(CVERecord).filter(CVERecord.cve_id == cve_id).first()
        
        if existing_cve:
            # Update existing record
            existing_cve.last_modified = cve_data.get('last_modified')
            existing_cve.description = cve_data.get('description')
            existing_cve.severity = cve_data.get('severity')
            existing_cve.cvss_score = cve_data.get('cvss_score')
            existing_cve.cvss_vector = cve_data.get('cvss_vector')
            existing_cve.affected_products = cve_data.get('affected_products')
            existing_cve.raw_data = cve_data.get('raw_data')
            existing_cve.updated_at = datetime.utcnow()
            return existing_cve
        else:
            # Create new record
            cve_record = CVERecord(
                cve_id=cve_id,
                published_date=cve_data.get('published_date'),
                last_modified=cve_data.get('last_modified'),
                source=cve_data.get('source', 'NVD'),
                description=cve_data.get('description'),
                severity=cve_data.get('severity'),
                cvss_score=cve_data.get('cvss_score'),
                cvss_vector=cve_data.get('cvss_vector'),
                affected_products=cve_data.get('affected_products'),
                raw_data=cve_data.get('raw_data')
            )
            session.add(cve_record)
            return cve_record
    
    def bulk_save_cves(self, cve_data_list: List[Dict[str, Any]]) -> Dict[str, int]:
        """Bulk save CVE records.
        
        Args:
            cve_data_list: List of CVE data dictionaries
            
        Returns:
            Dictionary with counts of new and updated CVEs
        """
        new_count = 0
        updated_count = 0
        
        with self.db_manager.get_session() as session:
            try:
                for cve_data in cve_data_list:
                    cve_id = cve_data.get('cve_id')
                    if not cve_id:
                        continue
                        
                    existing = session.query(CVERecord).filter(CVERecord.cve_id == cve_id).first()
                    
                    if existing:
                        # Update existing
                        existing.last_modified = cve_data.get('last_modified')
                        existing.description = cve_data.get('description')
                        existing.severity = cve_data.get('severity')
                        existing.cvss_score = cve_data.get('cvss_score')
                        existing.cvss_vector = cve_data.get('cvss_vector')
                        existing.affected_products = cve_data.get('affected_products')
                        existing.raw_data = cve_data.get('raw_data')
                        existing.updated_at = datetime.utcnow()
                        updated_count += 1
                    else:
                        # Create new
                        cve_record = CVERecord(
                            cve_id=cve_id,
                            published_date=cve_data.get('published_date'),
                            last_modified=cve_data.get('last_modified'),
                            source=cve_data.get('source', 'NVD'),
                            description=cve_data.get('description'),
                            severity=cve_data.get('severity'),
                            cvss_score=cve_data.get('cvss_score'),
                            cvss_vector=cve_data.get('cvss_vector'),
                            affected_products=cve_data.get('affected_products'),
                            raw_data=cve_data.get('raw_data')
                        )
                        session.add(cve_record)
                        new_count += 1
                
                session.commit()
                logger.info(f"Bulk saved CVEs: {new_count} new, {updated_count} updated")
                
            except Exception as e:
                session.rollback()
                logger.error(f"Error bulk saving CVEs: {e}")
                raise
        
        return {"new": new_count, "updated": updated_count}
    
    def get_cve_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Get CVE record by ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2019-20372)
            
        Returns:
            CVERecord instance or None
        """
        with self.db_manager.get_session() as session:
            return session.query(CVERecord).filter(CVERecord.cve_id == cve_id).first()
    
    def search_cves_by_product(self, product_name: str, limit: int = 100) -> List[CVERecord]:
        """Search CVEs affecting a specific product.
        
        Args:
            product_name: Product name to search for (e.g., 'nginx', 'apache')
            limit: Maximum number of results
            
        Returns:
            List of CVERecord instances
        """
        with self.db_manager.get_session() as session:
            # Search in description and affected_products JSON
            return session.query(CVERecord).filter(
                or_(
                    CVERecord.description.ilike(f'%{product_name}%'),
                    CVERecord.affected_products.astext.ilike(f'%{product_name}%')
                )
            ).order_by(desc(CVERecord.published_date)).limit(limit).all()
    
    def get_recent_cves(self, days: int = 30, limit: int = 100) -> List[CVERecord]:
        """Get recently published CVEs.
        
        Args:
            days: Number of days back to search
            limit: Maximum number of results
            
        Returns:
            List of CVERecord instances
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        with self.db_manager.get_session() as session:
            return session.query(CVERecord).filter(
                CVERecord.published_date >= cutoff_date
            ).order_by(desc(CVERecord.published_date)).limit(limit).all()
    
    def get_high_severity_cves(self, limit: int = 100) -> List[CVERecord]:
        """Get high severity CVEs.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of CVERecord instances
        """
        with self.db_manager.get_session() as session:
            return session.query(CVERecord).filter(
                CVERecord.severity.in_(['HIGH', 'CRITICAL'])
            ).order_by(desc(CVERecord.published_date)).limit(limit).all()
    
    def get_cve_count(self) -> int:
        """Get total number of CVEs in database.
        
        Returns:
            Count of CVE records
        """
        with self.db_manager.get_session() as session:
            return session.query(CVERecord).count()
    
    def log_update(self, log_data: Dict[str, Any]) -> CVEUpdateLog:
        """Log a CVE update operation.
        
        Args:
            log_data: Update log data
            
        Returns:
            CVEUpdateLog instance
        """
        with self.db_manager.get_session() as session:
            try:
                log_entry = CVEUpdateLog(
                    total_cves_processed=log_data.get('total_processed', 0),
                    new_cves_added=log_data.get('new_added', 0),
                    updated_cves=log_data.get('updated', 0),
                    source=log_data.get('source', 'NVD'),
                    status=log_data.get('status', 'SUCCESS'),
                    error_message=log_data.get('error_message'),
                    processing_time_seconds=log_data.get('processing_time')
                )
                session.add(log_entry)
                session.commit()
                return log_entry
            except Exception as e:
                session.rollback()
                logger.error(f"Error logging CVE update: {e}")
                raise
    
    def get_last_update(self) -> Optional[CVEUpdateLog]:
        """Get the last successful CVE update log.
        
        Returns:
            CVEUpdateLog instance or None
        """
        with self.db_manager.get_session() as session:
            return session.query(CVEUpdateLog).filter(
                CVEUpdateLog.status == 'SUCCESS'
            ).order_by(desc(CVEUpdateLog.update_date)).first()
    
    def needs_update(self, hours_threshold: int = 24) -> bool:
        """Check if CVE database needs updating.
        
        Args:
            hours_threshold: Hours since last update to trigger update
            
        Returns:
            True if update is needed
        """
        last_update = self.get_last_update()
        
        if not last_update:
            return True
        
        time_since_update = datetime.utcnow() - last_update.update_date
        return time_since_update.total_seconds() > (hours_threshold * 3600)
    
    def get_matching_cves_for_banner(self, banner: str) -> List[CVERecord]:
        """Get CVEs that might match a service banner.
        
        Args:
            banner: Service banner string
            
        Returns:
            List of potentially matching CVE records
        """
        if not banner:
            return []
        
        # Extract common software names and versions from banner
        banner_lower = banner.lower()
        software_hints = []
        
        # Common software patterns
        patterns = {
            'nginx': r'nginx[\/\s]+([0-9]+\.[0-9]+\.[0-9]+)',
            'apache': r'apache[\/\s]+([0-9]+\.[0-9]+\.[0-9]+)',
            'openssh': r'openssh[_\s]+([0-9]+\.[0-9]+)',
            'mysql': r'mysql[\/\s]+([0-9]+\.[0-9]+\.[0-9]+)',
            'postgresql': r'postgresql[\/\s]+([0-9]+\.[0-9]+)',
        }
        
        import re
        for software, pattern in patterns.items():
            if software in banner_lower:
                software_hints.append(software)
                matches = re.findall(pattern, banner_lower)
                if matches:
                    software_hints.extend([f"{software}/{version}" for version in matches])
        
        if not software_hints:
            return []
        
        # Search for CVEs matching the detected software
        matching_cves = []
        with self.db_manager.get_session() as session:
            for hint in software_hints:
                cves = session.query(CVERecord).filter(
                    or_(
                        CVERecord.description.ilike(f'%{hint}%'),
                        CVERecord.affected_products.astext.ilike(f'%{hint}%')
                    )
                ).limit(10).all()
                matching_cves.extend(cves)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_cves = []
        for cve in matching_cves:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique_cves.append(cve)
        
        return unique_cves[:20]  # Limit to top 20 matches
