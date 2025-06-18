"""
CVE Updater Module - Fetches CVE data from NVD API and stores in database.

This module fetches the latest CVE data from the National Vulnerability Database
and stores it in the local database for use by the scanner.
"""

import json
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

import httpx
from core.logging import get_logger
from core.database import DatabaseManager
from repositories.cve_repository import CVERepository

logger = get_logger(__name__)


class CVEUpdater:
    """Fetches CVE data from NVD API and stores in database."""
    
    # CVE data sources
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, timeout: int = 30, db_manager: Optional[DatabaseManager] = None):
        """Initialize CVE updater.
        
        Args:
            timeout: HTTP request timeout in seconds
            db_manager: Database manager instance
        """
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)
        self.db_manager = db_manager or DatabaseManager()
        self.cve_repo = CVERepository(self.db_manager)
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()
    
    def fetch_nvd_cves(self, start_index: int = 0, results_per_page: int = 2000,
                      last_mod_start_date: Optional[str] = None,
                      last_mod_end_date: Optional[str] = None) -> List[Dict]:
        """Fetch CVEs from NVD API.
        
        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results per page (max 2000)
            last_mod_start_date: Filter by last modified start date (YYYY-MM-DDTHH:mm:ss.sss format)
            last_mod_end_date: Filter by last modified end date
            
        Returns:
            List of CVE data dictionaries
        """
        try:
            params = {
                "startIndex": start_index,
                "resultsPerPage": min(results_per_page, 2000)  # NVD API limit
            }
            
            if last_mod_start_date:
                params["lastModStartDate"] = last_mod_start_date
            if last_mod_end_date:
                params["lastModEndDate"] = last_mod_end_date
            
            logger.info(f"Fetching CVEs from NVD API (start={start_index}, limit={results_per_page})...")
            response = self.client.get(self.NVD_API_BASE, params=params)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", len(vulnerabilities))
            
            logger.info(f"Retrieved {len(vulnerabilities)} CVEs (total available: {total_results})")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error fetching CVEs from NVD API: {e}")
            return []
    
    def parse_cve_data(self, vulnerability: Dict) -> Optional[Dict[str, Any]]:
        """Parse a single CVE vulnerability from NVD API response.
        
        Args:
            vulnerability: Single vulnerability object from NVD API
            
        Returns:
            Parsed CVE data dictionary or None if parsing fails
        """
        try:
            cve = vulnerability.get("cve", {})
            cve_id = cve.get("id", "")
            
            if not cve_id:
                return None
            
            # Published and modified dates
            published_date = None
            last_modified = None
            
            if "published" in cve:
                try:
                    published_date = datetime.fromisoformat(cve["published"].replace('Z', '+00:00'))
                except:
                    pass
            
            if "lastModified" in cve:
                try:
                    last_modified = datetime.fromisoformat(cve["lastModified"].replace('Z', '+00:00'))
                except:
                    pass
            
            # Description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang", "") == "en":
                    description = desc.get("value", "")
                    break
            
            if not description and descriptions:
                description = descriptions[0].get("value", "")
            
            # CVSS metrics
            metrics = cve.get("metrics", {})
            severity = None
            cvss_score = None
            cvss_vector = None
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]  # Take first metric
                    cvss_data = metric.get("cvssData", {})
                    
                    if "baseSeverity" in cvss_data:
                        severity = cvss_data["baseSeverity"]
                    if "baseScore" in cvss_data:
                        cvss_score = str(cvss_data["baseScore"])
                    if "vectorString" in cvss_data:
                        cvss_vector = cvss_data["vectorString"]
                    break
            
            return {
                "cve_id": cve_id,
                "published_date": published_date,
                "last_modified": last_modified,
                "source": "NVD",
                "description": description[:2000] if description else None,  # Truncate for DB
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "raw_data": vulnerability  # Store complete raw data
            }
            
        except Exception as e:
            logger.warning(f"Error parsing CVE data: {e}")
            return None
    
    def fetch_and_store_recent_cves(self, days_back: int = 7) -> Dict[str, int]:
        """Fetch and store CVEs modified in the last N days.
        
        Args:
            days_back: Number of days back to fetch CVEs
            
        Returns:
            Dictionary with processing statistics
        """
        start_time = time.time()
        total_processed = 0
        new_added = 0
        updated = 0
        
        try:
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Format dates for NVD API
            start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            logger.info(f"Fetching CVEs modified between {start_date_str} and {end_date_str}")
            
            # Fetch CVEs in batches (NVD API pagination)
            start_index = 0
            batch_size = 2000  # NVD API limit
            all_cve_data = []
            
            while True:
                vulnerabilities = self.fetch_nvd_cves(
                    start_index=start_index,
                    results_per_page=batch_size,
                    last_mod_start_date=start_date_str,
                    last_mod_end_date=end_date_str
                )
                
                if not vulnerabilities:
                    break
                
                # Parse CVE data
                for vulnerability in vulnerabilities:
                    parsed_cve = self.parse_cve_data(vulnerability)
                    if parsed_cve:
                        all_cve_data.append(parsed_cve)
                        total_processed += 1
                
                # Check if we got less than requested (last page)
                if len(vulnerabilities) < batch_size:
                    break
                
                start_index += batch_size
                
                # Rate limiting - be respectful to NVD API
                time.sleep(1)
                
                logger.info(f"Processed {total_processed} CVEs so far...")
            
            # Bulk save to database
            if all_cve_data:
                logger.info(f"Saving {len(all_cve_data)} CVEs to database...")
                save_results = self.cve_repo.bulk_save_cves(all_cve_data)
                new_added = save_results["new"]
                updated = save_results["updated"]
            
            processing_time = int(time.time() - start_time)
            
            # Log the update
            self.cve_repo.log_update({
                "total_processed": total_processed,
                "new_added": new_added,
                "updated": updated,
                "source": "NVD",
                "status": "SUCCESS",
                "processing_time": processing_time
            })
            
            logger.info(f"CVE update completed: {new_added} new, {updated} updated, {processing_time}s")
            
            return {
                "total_processed": total_processed,
                "new_added": new_added,
                "updated": updated,
                "processing_time": processing_time
            }
            
        except Exception as e:
            # Log the failure
            processing_time = int(time.time() - start_time)
            self.cve_repo.log_update({
                "total_processed": total_processed,
                "new_added": new_added,
                "updated": updated,
                "source": "NVD",
                "status": "FAILED",
                "error_message": str(e),
                "processing_time": processing_time
            })
            
            logger.error(f"CVE update failed: {e}")
            raise
    
    def fetch_all_recent_cves(self, max_days: int = 30) -> Dict[str, int]:
        """Fetch all CVEs from recent period (for initial database population).
        
        Args:
            max_days: Maximum days back to fetch
            
        Returns:
            Dictionary with processing statistics
        """
        logger.info(f"Fetching all CVEs from last {max_days} days for database population...")
        return self.fetch_and_store_recent_cves(days_back=max_days)
    
    def update_if_needed(self, force_update: bool = False) -> bool:
        """Update CVE database if needed (daily check).
        
        Args:
            force_update: Force update even if not needed
            
        Returns:
            True if update was performed
        """
        if not force_update and not self.cve_repo.needs_update():
            logger.info("CVE database is up to date")
            return False
        
        try:
            # For daily updates, fetch CVEs from last 2 days to catch any modifications
            self.fetch_and_store_recent_cves(days_back=2)
            return True
        except Exception as e:
            logger.error(f"CVE update failed: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get CVE database statistics.
        
        Returns:
            Dictionary with database statistics
        """
        stats = {}
        
        try:
            stats["total_cves"] = self.cve_repo.get_cve_count()
            
            last_update = self.cve_repo.get_last_update()
            if last_update:
                stats["last_update"] = last_update.update_date.isoformat()
                stats["last_update_status"] = last_update.status
                stats["last_update_new_cves"] = last_update.new_cves_added
                stats["last_update_updated_cves"] = last_update.updated_cves
            
            # Recent high-severity CVEs count
            high_severity_cves = self.cve_repo.get_high_severity_cves(limit=1000)
            stats["high_severity_count"] = len(high_severity_cves)
            
            # Recent CVEs count (last 30 days)
            recent_cves = self.cve_repo.get_recent_cves(days=30)
            stats["recent_cves_30_days"] = len(recent_cves)
            
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            stats["error"] = str(e)
        
        return stats
    
def update_cves_database(force_update: bool = False, initial_populate: bool = False,
                        days_back: int = 7) -> bool:
    """Update CVE database with latest data from NVD API.
    
    Args:
        force_update: Force update even if not needed
        initial_populate: Populate database from scratch (fetch more CVEs)
        days_back: Number of days back to fetch CVEs
        
    Returns:
        True if update was successful
    """
    logger.info("Starting CVE database update...")
    
    try:
        with CVEUpdater() as updater:
            if initial_populate:
                # For initial population, fetch more CVEs
                logger.info("Performing initial CVE database population...")
                results = updater.fetch_all_recent_cves(max_days=30)
            else:
                # Regular update
                if force_update:
                    results = updater.fetch_and_store_recent_cves(days_back=days_back)
                else:
                    updated = updater.update_if_needed()
                    if not updated:
                        logger.info("CVE database is already up to date")
                        return True
                    results = {"total_processed": 0, "new_added": 0, "updated": 0}
            
            logger.info(f"CVE update completed successfully:")
            logger.info(f"  - Total processed: {results.get('total_processed', 0)}")
            logger.info(f"  - New CVEs added: {results.get('new_added', 0)}")
            logger.info(f"  - CVEs updated: {results.get('updated', 0)}")
            logger.info(f"  - Processing time: {results.get('processing_time', 0)}s")
            
            return True
            
    except Exception as e:
        logger.error(f"CVE database update failed: {e}")
        return False


def get_cve_stats() -> Dict[str, Any]:
    """Get CVE database statistics.
    
    Returns:
        Dictionary with CVE database statistics
    """
    try:
        with CVEUpdater() as updater:
            return updater.get_database_stats()
    except Exception as e:
        logger.error(f"Error getting CVE stats: {e}")
        return {"error": str(e)}


def search_cves_for_banner(banner: str) -> List[Dict[str, Any]]:
    """Search for CVEs matching a service banner.
    
    Args:
        banner: Service banner string
        
    Returns:
        List of matching CVE dictionaries (without affected_products for scan results)
    """
    try:
        with CVEUpdater() as updater:
            cve_records = updater.cve_repo.get_matching_cves_for_banner(banner)
            # Convert to dict but exclude affected_products from scan results
            result = []
            for cve in cve_records:
                cve_dict = cve.to_dict()
                # Remove affected_products from scan results to keep them cleaner
                if 'affected_products' in cve_dict:
                    del cve_dict['affected_products']
                result.append(cve_dict)
            return result
    except Exception as e:
        logger.error(f"Error searching CVEs for banner: {e}")
        return []


if __name__ == "__main__":
    # CLI for testing and manual operations
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE Database Updater")
    parser.add_argument("--update", action="store_true", help="Update CVE database")
    parser.add_argument("--force", action="store_true", help="Force update")
    parser.add_argument("--initial", action="store_true", help="Initial database population")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--days", type=int, default=7, help="Days back to fetch CVEs")
    parser.add_argument("--search", help="Search CVEs for given banner")
    
    args = parser.parse_args()
    
    if args.stats:
        stats = get_cve_stats()
        print("CVE Database Statistics:")
        print("=" * 40)
        for key, value in stats.items():
            print(f"{key}: {value}")
    elif args.search:
        cves = search_cves_for_banner(args.search)
        print(f"Found {len(cves)} matching CVEs for banner: {args.search}")
        for cve in cves[:5]:  # Show first 5
            print(f"  {cve['cve_id']}: {cve['description'][:100]}...")
    elif args.update or args.initial:
        success = update_cves_database(
            force_update=args.force,
            initial_populate=args.initial,
            days_back=args.days
        )
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
