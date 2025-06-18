"""
Service for handling scan result saving and management
"""

from repositories.scan_repository import ScanRepository
from storage.history import HistoryStore
from core.database import SCANNER_VERSION
import logging


class ScanService:
    """Service for managing scan results and their persistence"""
    
    def __init__(self):
        self.history_store = HistoryStore()
    
    def save_scan_results(self, scored_results):
        """
        Save scan results to both history store and validator database
        
        Args:
            scored_results: List of scan result dictionaries with format:
                {
                    "ip": str,
                    "score": int,
                    "flags": list,
                    "summary": str,
                    "timestamp": str,
                    "hash": str,
                    "generic_scan": dict,
                    "sui_specific_scan": dict
                }
        """
        with ScanRepository() as scan_repo:
            for result in scored_results:
                # Save to history store (existing functionality)
                self.history_store.add_entry(result)
                
                # Save scan results to validator_addresses table
                try:
                    # Find the validator id that corresponds to this IP
                    validator_id = scan_repo.find_validator_by_ip(result["ip"])
                    failed = result.get("failed", False)
                    
                    if validator_id:
                        # Save the scan to the database
                        scan = scan_repo.add_scan(
                            validator_address_id=validator_id,
                            ip_address=result["ip"],
                            score=result["score"] if result["score"] is not None else None,
                            scan_hash=result["hash"] if result["hash"] is not None else None,
                            scan_results={
                                "flags": result["flags"],
                                "summary": result["summary"],
                                "timestamp": result["timestamp"],
                                "generic_scan": result["generic_scan"],
                                "sui_specific_scan": result["sui_specific_scan"]
                            },
                            failed=failed,
                            version=SCANNER_VERSION
                        )
                        logging.info(
                            f"Saved scan results for validator id {validator_id} "
                            f"(IP: {result['ip']}, Scan ID: {scan.id})"
                        )
                    else:
                        logging.error(f"Could not find validator id for IP {result['ip']}")
                        
                except Exception as e:
                    logging.error(f"Error saving scan results for IP {result['ip']}: {e}")

    def get_scan_summary_for_validator(self, validator_id):
        """Get scan summary for a specific validator by id"""
        with ScanRepository() as scan_repo:
            scans = scan_repo.get_scans_for_validator(validator_id)
            
            if not scans:
                return None
            
            latest_scan = scans[0]  # Most recent scan
            return {
                "validator_id": validator_id,
                "total_scans": len(scans),
                "latest_scan": {
                    "scan_date": latest_scan.scan_date,
                    "ip_address": latest_scan.ip_address,
                    "score": latest_scan.score,
                    "version": latest_scan.version,
                    "flags": latest_scan.scan_results.get("flags", []) if latest_scan.scan_results else []
                }
            }
    
    def get_scan_summary_for_ip(self, ip_address):
        """Get scan summary for a specific IP"""
        with ScanRepository() as scan_repo:
            scans = scan_repo.get_scans_by_ip(ip_address)
            
            if not scans:
                return None
            
            latest_scan = scans[0]  # Most recent scan
            return {
                "ip_address": ip_address,
                "total_scans": len(scans),
                "latest_scan": {
                    "scan_date": latest_scan.scan_date,
                    "validator_id": latest_scan.validator_address_id,
                    "score": latest_scan.score,
                    "version": latest_scan.version,
                    "flags": latest_scan.scan_results.get("flags", []) if latest_scan.scan_results else []
                }
            }
    
    def get_all_scan_summaries(self, limit=50):
        """Get summaries of all scans"""
        with ScanRepository() as scan_repo:
            scans = scan_repo.get_all_scans(limit=limit)
            
            summaries = []
            for scan in scans:
                summaries.append({
                    "scan_id": scan.id,
                    "validator_id": scan.validator_address_id,
                    "ip_address": scan.ip_address,
                    "score": scan.score,
                    "scan_date": scan.scan_date,
                    "version": scan.version,
                    "flags": scan.scan_results.get("flags", []) if scan.scan_results else []
                })
            
            return summaries
        
    def filter_validators_for_scanning(self, validator_ids, scan_interval_days=7):
        """
        Dummy filter: returns all ids unchanged. Replace with real logic if needed.
        """
        return validator_ids
    
    def get_first_unscanned_validator(self, validator_ids, scan_interval_days=7):
        """
        Return the first validator id that has not been scanned in the last scan_interval_days.
        """
        with ScanRepository() as scan_repo:
            for validator_id in validator_ids:
                if not scan_repo.has_recent_scan(validator_id, days=scan_interval_days):
                    return validator_id
        return None
