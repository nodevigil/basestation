from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pgdn.models.validator import ValidatorScan, ValidatorAddress
from pgdn.core.database import SessionLocal
from pgdn.core.database import SCANNER_VERSION
from typing import List, Optional
from datetime import datetime

class ScanRepository:
    """Repository for managing validator scans"""
    
    def __init__(self, db: Session = None):
        self.db = db or SessionLocal()
        self._should_close = db is None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._should_close:
            self.db.close()
    
    def add_scan(self, validator_address_id: int, ip_address: str, score: int, 
                 scan_hash: str, scan_results: dict, failed: bool = False, version: str = SCANNER_VERSION) -> ValidatorScan:
        """Add a new scan result for a validator"""
        try:
            # Ensure the validator exists by id
            validator = self.db.query(ValidatorAddress).filter(
                ValidatorAddress.id == validator_address_id
            ).first()
            if not validator:
                raise ValueError(f"Validator id {validator_address_id} not found")
            scan = ValidatorScan(
                validator_address_id=validator_address_id,
                scan_date=datetime.utcnow(),
                ip_address=ip_address,
                score=score,
                scan_hash=scan_hash,
                scan_results=scan_results,
                created_at=datetime.utcnow(),
                failed=failed,
                version=version
            )
            self.db.add(scan)
            self.db.commit()
            self.db.refresh(scan)
            return scan
        except Exception as e:
            self.db.rollback()
            raise e
    
    def get_scans_for_validator(self, validator_address_id: int) -> List[ValidatorScan]:
        """Get all scans for a specific validator by id"""
        return self.db.query(ValidatorScan).filter(
            ValidatorScan.validator_address_id == validator_address_id
        ).order_by(ValidatorScan.scan_date.desc()).all()
    
    def get_latest_scan_for_validator(self, validator_address_id: int) -> Optional[ValidatorScan]:
        """Get the most recent scan for a validator by id"""
        return self.db.query(ValidatorScan).filter(
            ValidatorScan.validator_address_id == validator_address_id
        ).order_by(ValidatorScan.scan_date.desc()).first()
    
    def get_scans_by_ip(self, ip_address: str) -> List[ValidatorScan]:
        """Get all scans for a specific IP address"""
        return self.db.query(ValidatorScan).filter(
            ValidatorScan.ip_address == ip_address
        ).order_by(ValidatorScan.scan_date.desc()).all()
    
    def get_all_scans(self, limit: int = None) -> List[ValidatorScan]:
        """Get all scans, optionally limited"""
        query = self.db.query(ValidatorScan).order_by(ValidatorScan.scan_date.desc())
        if limit:
            query = query.limit(limit)
        return query.all()
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan by ID"""
        scan = self.db.query(ValidatorScan).filter(ValidatorScan.id == scan_id).first()
        if scan:
            self.db.delete(scan)
            self.db.commit()
            return True
        return False
    
    def find_validator_by_ip(self, ip_address: str) -> Optional[int]:
        """Find validator id by IP address by checking if any validator resolves to this IP"""
        import socket
        validators = self.db.query(ValidatorAddress).filter(ValidatorAddress.active == True).all()
        for validator in validators:
            try:
                resolved_ip = socket.gethostbyname(validator.address)
                if resolved_ip == ip_address:
                    return validator.id
            except socket.gaierror:
                if validator.address == ip_address:
                    return validator.id
                continue
        return None
    
    def has_recent_scan(self, validator_address_id: int, days: int = 7) -> bool:
        """Check if a validator has been scanned within the specified number of days by id"""
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        recent_scan = self.db.query(ValidatorScan).filter(
            ValidatorScan.validator_address_id == validator_address_id,
            ValidatorScan.scan_date >= cutoff_date
        ).first()
        return recent_scan is not None
    
    def get_validators_needing_scan(self, days_ago: int = 7) -> List[int]:
        """Get list of validator ids that haven't been scanned within the specified days"""
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days_ago)
        all_validators = self.db.query(ValidatorAddress).filter(
            ValidatorAddress.active == True
        ).all()
        validators_needing_scan = []
        for validator in all_validators:
            recent_scan = self.db.query(ValidatorScan).filter(
                ValidatorScan.validator_address_id == validator.id,
                ValidatorScan.scan_date >= cutoff_date
            ).first()
            if not recent_scan:
                validators_needing_scan.append(validator.id)
        return validators_needing_scan
    
    def get_scans_for_signature_creation(self, protocol_filter=None):
        """
        Get scans that have a detected protocol but no signature has been created yet.
        
        Args:
            protocol_filter: Optional protocol name to filter by
            
        Returns:
            List of ValidatorScan objects that need signature creation
        """
        query = self.db.query(ValidatorScan).filter(
            ValidatorScan.failed == False,
            ValidatorScan.signature_created == False,
            ValidatorScan.scan_results.isnot(None)
        )
        
        if protocol_filter:
            # Filter by protocol mentioned in scan results
            query = query.filter(
                ValidatorScan.scan_results.op('->>')('detected_protocol') == protocol_filter
            )
        
        # Only include scans where we definitely know the protocol
        query = query.filter(
            ValidatorScan.scan_results.op('->>')('detected_protocol').isnot(None),
            ValidatorScan.scan_results.op('->>')('detected_protocol') != 'unknown'
        )
        
        return query.order_by(ValidatorScan.created_at.desc()).all()
    
    def mark_scan_signature_created(self, scan_id):
        """
        Mark a scan as having its protocol signature created.
        
        Args:
            scan_id: The ID of the scan to mark
            
        Returns:
            bool: True if successfully marked, False otherwise
        """
        try:
            scan = self.db.query(ValidatorScan).filter(ValidatorScan.id == scan_id).first()
            if scan:
                scan.signature_created = True
                self.db.commit()
                return True
            return False
        except Exception as e:
            self.db.rollback()
            return False
    
    def get_signature_creation_statistics(self):
        """
        Get statistics about signature creation status.
        
        Returns:
            dict: Stats including total scans, signatures created, pending, etc.
        """
        from sqlalchemy import func
        
        total_scans = self.db.query(ValidatorScan).filter(
            ValidatorScan.failed == False,
            ValidatorScan.scan_results.isnot(None)
        ).count()
        
        signatures_created = self.db.query(ValidatorScan).filter(
            ValidatorScan.failed == False,
            ValidatorScan.signature_created == True
        ).count()
        
        pending_signatures = self.db.query(ValidatorScan).filter(
            ValidatorScan.failed == False,
            ValidatorScan.signature_created == False,
            ValidatorScan.scan_results.op('->>')('detected_protocol').isnot(None),
            ValidatorScan.scan_results.op('->>')('detected_protocol') != 'unknown'
        ).count()
        
        # Get breakdown by protocol
        from sqlalchemy import Integer
        protocol_stats = self.db.query(
            ValidatorScan.scan_results.op('->>')('detected_protocol').label('protocol'),
            func.count().label('total'),
            func.sum(func.cast(ValidatorScan.signature_created, Integer)).label('created')
        ).filter(
            ValidatorScan.failed == False,
            ValidatorScan.scan_results.op('->>')('detected_protocol').isnot(None),
            ValidatorScan.scan_results.op('->>')('detected_protocol') != 'unknown'
        ).group_by(
            ValidatorScan.scan_results.op('->>')('detected_protocol')
        ).all()
        
        return {
            'total_scans': total_scans,
            'signatures_created': signatures_created,
            'pending_signatures': pending_signatures,
            'completion_rate': signatures_created / total_scans if total_scans > 0 else 0,
            'protocol_breakdown': [
                {
                    'protocol': stat.protocol,
                    'total_scans': stat.total,
                    'signatures_created': stat.created or 0,
                    'pending': stat.total - (stat.created or 0)
                }
                for stat in protocol_stats
            ]
        }
    
    def get_scan_by_id(self, scan_id: int) -> Optional[ValidatorScan]:
        """Get a scan by its ID"""
        return self.db.query(ValidatorScan).filter(ValidatorScan.id == scan_id).first()
