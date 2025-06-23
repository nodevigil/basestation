"""
CVE Scheduled Updater - Handles daily CVE database updates.
"""

import schedule
import time
import threading
from datetime import datetime
from typing import Optional
from pgdn.core.logging import get_logger
from pgdn.utils.cve_updater import update_cves_database

logger = get_logger(__name__)


class CVEScheduler:
    """Handles scheduled CVE updates."""
    
    def __init__(self, update_time: str = "02:00", enabled: bool = True):
        """Initialize CVE scheduler.
        
        Args:
            update_time: Time to run daily updates (HH:MM format)
            enabled: Whether scheduling is enabled
        """
        self.update_time = update_time
        self.enabled = enabled
        self.scheduler_thread = None
        self.running = False
        
    def daily_update_job(self):
        """Job function for daily CVE updates."""
        logger.info("Starting scheduled CVE update...")
        
        try:
            success = update_cves_database(
                force_update=False,
                initial_populate=False,
                days_back=2  # Check last 2 days for changes
            )
            
            if success:
                logger.info("Scheduled CVE update completed successfully")
            else:
                logger.error("Scheduled CVE update failed")
                
        except Exception as e:
            logger.error(f"Error in scheduled CVE update: {e}")
    
    def start_scheduler(self):
        """Start the CVE update scheduler."""
        if not self.enabled:
            logger.info("CVE scheduler is disabled")
            return
            
        if self.running:
            logger.warning("CVE scheduler is already running")
            return
        
        logger.info(f"Starting CVE scheduler - daily updates at {self.update_time}")
        
        # Schedule daily update
        schedule.every().day.at(self.update_time).do(self.daily_update_job)
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("CVE scheduler started successfully")
    
    def stop_scheduler(self):
        """Stop the CVE update scheduler."""
        if not self.running:
            return
            
        logger.info("Stopping CVE scheduler...")
        self.running = False
        schedule.clear()
        
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=5)
        
        logger.info("CVE scheduler stopped")
    
    def _run_scheduler(self):
        """Run the scheduler in a separate thread."""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in CVE scheduler: {e}")
                time.sleep(300)  # Wait 5 minutes on error
    
    def run_update_now(self):
        """Run CVE update immediately."""
        logger.info("Running immediate CVE update...")
        self.daily_update_job()
    
    def get_next_update_time(self) -> Optional[str]:
        """Get the next scheduled update time.
        
        Returns:
            Next update time as string or None if not scheduled
        """
        if not self.enabled or not self.running:
            return None
            
        jobs = schedule.jobs
        if jobs:
            next_run = jobs[0].next_run
            if next_run:
                return next_run.strftime("%Y-%m-%d %H:%M:%S")
        
        return None


# Global scheduler instance
_cve_scheduler: Optional[CVEScheduler] = None


def get_cve_scheduler() -> CVEScheduler:
    """Get the global CVE scheduler instance."""
    global _cve_scheduler
    if _cve_scheduler is None:
        _cve_scheduler = CVEScheduler()
    return _cve_scheduler


def start_cve_scheduler(update_time: str = "02:00", enabled: bool = True):
    """Start the global CVE scheduler.
    
    Args:
        update_time: Time to run daily updates (HH:MM format)
        enabled: Whether scheduling is enabled
    """
    scheduler = get_cve_scheduler()
    scheduler.update_time = update_time
    scheduler.enabled = enabled
    scheduler.start_scheduler()


def stop_cve_scheduler():
    """Stop the global CVE scheduler."""
    scheduler = get_cve_scheduler()
    scheduler.stop_scheduler()


if __name__ == "__main__":
    # Test the scheduler
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE Scheduler Test")
    parser.add_argument("--start", action="store_true", help="Start scheduler")
    parser.add_argument("--update-now", action="store_true", help="Run update now")
    parser.add_argument("--time", default="02:00", help="Update time (HH:MM)")
    
    args = parser.parse_args()
    
    if args.update_now:
        scheduler = CVEScheduler()
        scheduler.run_update_now()
    elif args.start:
        print(f"Starting CVE scheduler with daily updates at {args.time}")
        start_cve_scheduler(args.time)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping scheduler...")
            stop_cve_scheduler()
    else:
        parser.print_help()
