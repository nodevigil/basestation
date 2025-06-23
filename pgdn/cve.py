"""
CVE Management Module

Provides CVE (Common Vulnerabilities and Exposures) database management functionality.
This module abstracts CVE operations from CLI concerns.
"""

from typing import Dict, Any, Optional
from datetime import datetime

from utils.cve_updater import update_cves_database, get_cve_stats


class CVEManager:
    """
    Manager for CVE database operations.
    
    This class provides a clean Python API for managing CVE database
    updates and statistics, independent of CLI concerns.
    """
    
    def __init__(self):
        """Initialize the CVE manager."""
        pass
    
    def update_database(self, 
                       force_update: bool = False,
                       initial_populate: bool = False,
                       days_back: int = 7) -> Dict[str, Any]:
        """
        Update the CVE database with latest vulnerability data.
        
        Args:
            force_update: Whether to replace existing CVEs or merge them
            initial_populate: Whether to perform initial database population
            days_back: Number of days back to fetch CVEs for
            
        Returns:
            dict: Update results including success status and statistics
        """
        try:
            # Adjust days_back for initial population
            if initial_populate:
                days_back = 30
            
            success = update_cves_database(
                force_update=force_update,
                initial_populate=initial_populate,
                days_back=days_back
            )
            
            if success:
                # Get database statistics
                stats = get_cve_stats()
                
                return {
                    "success": True,
                    "initial_populate": initial_populate,
                    "force_update": force_update,
                    "days_back": days_back,
                    "statistics": {
                        "total_cves": stats.get('total_cves', 'Unknown'),
                        "high_severity_count": stats.get('high_severity_count', 'Unknown'),
                        "recent_cves_30_days": stats.get('recent_cves_30_days', 'Unknown'),
                        "last_update": stats.get('last_update'),
                        "last_update_new_cves": stats.get('last_update_new_cves', 0),
                        "last_update_updated_cves": stats.get('last_update_updated_cves', 0)
                    },
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "error": "CVE database update failed. Check logs for details.",
                    "initial_populate": initial_populate,
                    "force_update": force_update,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"CVE database update failed: {str(e)}",
                "initial_populate": initial_populate,
                "force_update": force_update,
                "timestamp": datetime.now().isoformat()
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get CVE database statistics.
        
        Returns:
            dict: Database statistics
        """
        try:
            stats = get_cve_stats()
            
            return {
                "success": True,
                "statistics": {
                    "total_cves": stats.get('total_cves', 'Unknown'),
                    "high_severity_count": stats.get('high_severity_count', 'Unknown'),
                    "recent_cves_30_days": stats.get('recent_cves_30_days', 'Unknown'),
                    "last_update": stats.get('last_update'),
                    "last_update_new_cves": stats.get('last_update_new_cves', 0),
                    "last_update_updated_cves": stats.get('last_update_updated_cves', 0)
                },
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get CVE statistics: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def initial_populate(self) -> Dict[str, Any]:
        """
        Perform initial CVE database population.
        
        Returns:
            dict: Initial population results
        """
        return self.update_database(initial_populate=True)
    
    def force_update(self) -> Dict[str, Any]:
        """
        Force update of CVE database (replace existing).
        
        Returns:
            dict: Force update results
        """
        return self.update_database(force_update=True)
    
    def start_scheduler(self, update_time: str = '02:00') -> Dict[str, Any]:
        """
        Start the CVE update scheduler.
        
        Args:
            update_time: Time for daily CVE updates (HH:MM format)
            
        Returns:
            dict: Scheduler start results
        """
        try:
            from utils.cve_scheduler import start_cve_scheduler
            
            success = start_cve_scheduler(update_time)
            
            if success:
                return {
                    "success": True,
                    "message": f"CVE update scheduler started (daily at {update_time})",
                    "update_time": update_time,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to start CVE update scheduler",
                    "update_time": update_time,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"CVE scheduler startup failed: {str(e)}",
                "update_time": update_time,
                "timestamp": datetime.now().isoformat()
            }
